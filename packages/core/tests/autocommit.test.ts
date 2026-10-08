import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { PasswordlessService } from '../src/account/application/passwordless-service.ts';
import type { ChallengeRepository } from '../src/account/domain/challenge.ts';
import { MembershipAdminService } from '../src/admin/application/membership-admin.ts';
import { UserAdminService } from '../src/admin/application/user-admin.ts';
import { TokenService } from '../src/authorization/application/token-service.ts';
import type {
  Authorization,
  AuthorizationRepository,
  OAuthError,
  RegisteredClient,
  RegisteredClientRepository,
} from '../src/authorization/domain/models.ts';
import { IdentityModule } from '../src/composition.ts';
import type { DirectoryRepository } from '../src/directory/domain/directory-repository.ts';
import { LinkService } from '../src/linking/application/link-service.ts';
import type { LinkRepository } from '../src/linking/domain/identity-link.ts';
import { SecurityNotificationService } from '../src/notifications/application/security-notifications.ts';
import { manualClock } from '../src/shared/domain/clock.ts';
import {
  AUTHORIZATIONS,
  CHALLENGES,
  DIRECTORY,
  LINKS,
  REGISTERED_CLIENTS,
} from '../src/shared/domain/tokens.ts';
import { Hashing } from '../src/shared/infrastructure/crypto/hashing.ts';
import { loadIdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import { registerClient } from './support/clients.ts';
import { useIsolatedDatabase } from './support/database.ts';
import { type RecordingMailSender, useRecordingMail } from './support/mail.ts';

/**
 * The guest's database: `wasmcloud:postgres` runs every statement on whichever pooled
 * connection is free, so `transaction(fn)` is just `fn`, nothing is rolled back, and a row
 * lock lasts for one statement. Statements issued outside `SQL.begin` on the Bun pool behave
 * the same way, which makes the pool a faithful stand-in. Every invariant below must therefore
 * hold through the single statements the repositories issue, not through the transaction.
 */
function autocommit(database: SqlDatabase): SqlDatabase {
  const view: SqlDatabase = {
    run: (sql, params) => database.run(sql, params),
    query: (sql, params) => database.query(sql, params),
    first: (sql, params) => database.first(sql, params),
    exec: (sql) => database.exec(sql),
    transaction: (fn) => fn(view),
  };
  return view;
}

let isolated: Awaited<ReturnType<typeof useIsolatedDatabase>>;
let database: SqlDatabase;
let mail: RecordingMailSender;
let admin = '';
const directory = () => useContainer().resolve<DirectoryRepository>(DIRECTORY);
const authorizations = () => useContainer().resolve<AuthorizationRepository>(AUTHORIZATIONS);
const clients = () => useContainer().resolve<RegisteredClientRepository>(REGISTERED_CLIENTS);
const links = () => useContainer().resolve<LinkRepository>(LINKS);

async function person(
  options: { role?: string; password?: boolean; verified?: boolean } = {},
): Promise<{ id: string; email: string }> {
  const id = crypto.randomUUID();
  const email = `auto-${id.slice(0, 8)}@example.com`;
  await directory().insertAccount({
    id,
    login: `auto-${id.slice(0, 8)}`,
    email,
    displayName: 'Autocommit',
    passwordHash: options.password ? 'not-a-real-hash' : null,
    emailVerified: options.verified ?? true,
    systemRole: options.role ?? 'user',
    status: 'active',
  });
  return { id, email };
}

async function organization(slug: string): Promise<string> {
  const id = crypto.randomUUID();
  await directory().insertOrganization({ id, slug, name: slug });
  return id;
}

async function browserClient(): Promise<RegisteredClient> {
  const registered = await registerClient({
    grantTypes: ['authorization_code', 'refresh_token'],
    scopes: ['profile', 'email'],
    redirectUris: ['https://app.example/callback'],
  });
  return (await clients().find(registered.clientId)) as RegisteredClient;
}

function stored(
  client: RegisteredClient,
  principal: string,
  overrides: Partial<Authorization>,
): Authorization {
  return {
    id: crypto.randomUUID(),
    registeredClientId: client.id,
    principalName: principal,
    grantType: 'authorization_code',
    authorizedScopes: ['profile'],
    attributes: {
      redirect_uri: 'https://app.example/callback',
      requested_redirect_uri: null,
      code_challenge: null,
      nonce: null,
      auth_time: Date.now(),
    },
    state: null,
    code: null,
    access: null,
    refresh: null,
    idToken: null,
    ...overrides,
  };
}

/** Both outcomes of two racing grants: the responses that succeeded and the errors returned. */
async function race(client: RegisteredClient, form: Record<string, string>) {
  const tokens = useContainer().resolve(TokenService);
  const results = await Promise.allSettled([
    tokens.exchange(client, new URLSearchParams(form)),
    tokens.exchange(client, new URLSearchParams(form)),
  ]);
  return {
    issued: results.filter((result) => result.status === 'fulfilled'),
    refused: results
      .filter((result) => result.status === 'rejected')
      .map((result) => (result.reason as OAuthError).code),
  };
}

beforeAll(async () => {
  isolated = await useIsolatedDatabase('identity_autocommit_test');
  database = isolated.database;
  IdentityModule.connect(autocommit(database));
  mail = useRecordingMail();
  admin = (await person({ role: 'platform_admin' })).id;
});

afterAll(async () => {
  await isolated.release();
});

describe('grants without a transaction', () => {
  test('an authorization code is exchanged once, and the loser revokes the authorization', async () => {
    const client = await browserClient();
    const user = await person();
    const code = Hashing.token();
    const authorization = stored(client, user.id, {
      code: {
        hash: Hashing.sha256Hex(code),
        issuedAt: Date.now(),
        expiresAt: Date.now() + 60_000,
        invalidated: false,
      },
    });
    await authorizations().save(authorization);
    const { issued, refused } = await race(client, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://app.example/callback',
    });
    expect(issued).toHaveLength(1);
    expect(refused).toEqual(['invalid_grant']);
    // A code presented twice is a replay: the tokens it issued are gone as well.
    expect(await authorizations().findById(authorization.id)).toBeUndefined();
  });

  test('a refresh token rotates once, and the loser revokes the token family', async () => {
    const client = await browserClient();
    const user = await person();
    const refresh = Hashing.token();
    const authorization = stored(client, user.id, {
      refresh: {
        hash: Hashing.sha256Hex(refresh),
        issuedAt: Date.now(),
        expiresAt: Date.now() + 3_600_000,
        invalidated: false,
      },
    });
    await authorizations().save(authorization);
    const { issued, refused } = await race(client, {
      grant_type: 'refresh_token',
      refresh_token: refresh,
    });
    expect(issued).toHaveLength(1);
    expect(refused).toEqual(['invalid_grant']);
    expect(await authorizations().findById(authorization.id)).toBeUndefined();
    expect(
      await database.query(
        `SELECT 1 FROM auth_audit_records WHERE action = 'oauth.refresh_reuse_detected' AND target = ?`,
        [authorization.id],
      ),
    ).toHaveLength(1);
    expect(
      await authorizations().claimReplayedRefresh(Hashing.sha256Hex(refresh), Date.now()),
    ).toBeUndefined();
  });
});

describe('admin invariants without a transaction', () => {
  test('concurrent demotions and removals never leave an organization ownerless', async () => {
    const memberships = useContainer().resolve(MembershipAdminService);
    const gammaId = await organization('gamma');
    const first = (await person()).id;
    const second = (await person()).id;
    const owners = async () => {
      await directory().upsertMembership(gammaId, first, 'owner');
      await directory().upsertMembership(gammaId, second, 'owner');
    };
    await owners();
    const demoted = await Promise.all([
      memberships.changeRole(admin, { orgSlug: 'gamma', userId: first, newRole: 'member' }),
      memberships.changeRole(admin, { orgSlug: 'gamma', userId: second, newRole: 'member' }),
    ]);
    expect(demoted.filter((r) => 'location' in r && r.location.includes('changed=1'))).toHaveLength(
      1,
    );
    expect(await directory().countOwners('gamma')).toBe(1);
    await owners();
    const removed = await Promise.all([
      memberships.remove(admin, { orgSlug: 'gamma', userId: first }),
      memberships.remove(admin, { orgSlug: 'gamma', userId: second }),
    ]);
    expect(removed.filter((r) => 'location' in r && r.location.includes('removed=1'))).toHaveLength(
      1,
    );
    expect(await directory().countOwners('gamma')).toBe(1);
    // Promotion and a plain member removal are unconditional.
    const member = (await person()).id;
    await directory().upsertMembership(gammaId, member, 'member');
    expect(
      await memberships.changeRole(admin, { orgSlug: 'gamma', userId: member, newRole: 'owner' }),
    ).toMatchObject({ location: expect.stringContaining('changed=1') });
    expect(await memberships.remove(admin, { orgSlug: 'gamma', userId: member })).toMatchObject({
      location: expect.stringContaining('removed=1'),
    });
  });

  test('concurrent archives never leave the platform without an active administrator', async () => {
    const users = useContainer().resolve(UserAdminService);
    const deputy = (await person({ role: 'platform_admin' })).id;
    const archived = await Promise.all([users.archive(admin, admin), users.archive(admin, deputy)]);
    expect(
      archived.filter((result) => 'location' in result && result.location.includes('archived=1')),
    ).toHaveLength(1);
    expect(await directory().countActivePlatformAdmins()).toBe(1);
    await directory().updateAccount(admin, { status: 'active' });
    await directory().updateAccount(deputy, { status: 'archived' });

    // The sole owner of an active organization is refused by the statement as well.
    const soleOwner = (await person()).id;
    await directory().upsertMembership(await organization('delta'), soleOwner, 'owner');
    expect(await directory().archiveUnlessLast(soleOwner)).toBe(false);

    // A statement that loses its race reports the rule it hit, or a general refusal.
    const losing = useContainer().construct(UserAdminService, {
      1: Object.create(directory(), { archiveUnlessLast: { value: async () => false } }),
    });
    const plain = (await person()).id;
    expect(await losing.archive(admin, plain)).toMatchObject({
      location: `/admin/users/${plain}?error=Cannot+archive+user`,
    });
  });
});

describe('account flows without a transaction', () => {
  const settings = loadIdentitySettings({
    ISSUER_URL: 'https://auth.example',
    AUTH_PUBLIC_ORIGIN: 'https://public.example/',
  });

  test('a sign-in link is issued once per minute and consumed once', async () => {
    const clock = manualClock(Date.now());
    const passwordless = useContainer().construct(PasswordlessService, { 4: settings, 5: clock });
    const user = await person();
    await passwordless.requestSignIn(user.email);
    await passwordless.requestSignIn(user.email);
    expect(mail.to(user.email)).toHaveLength(1);
    const token = mail.lastToken(user.email) ?? '';
    const consumed = await Promise.all([
      passwordless.consume(token),
      passwordless.consume(token),
      passwordless.consume(token),
    ]);
    expect(consumed.filter(Boolean)).toHaveLength(1);

    // Losing the claim after the reads passed refuses the token too.
    const claimed = Object.create(useContainer().resolve<ChallengeRepository>(CHALLENGES), {
      claim: { value: async () => false },
    });
    const loser = useContainer().construct(PasswordlessService, {
      1: claimed,
      4: settings,
      5: clock,
    });
    clock.advance(61_000);
    await passwordless.requestSignIn(user.email);
    expect(await loser.consume(mail.lastToken(user.email) ?? '')).toBeUndefined();
  });

  test('concurrent unlinks keep one way to sign in', async () => {
    const unlinks = useContainer().resolve(LinkService);
    const user = await person({ verified: false });
    const link = async (subject: string) =>
      links().insert({
        id: crypto.randomUUID(),
        userId: user.id,
        issuer: 'https://idp.example',
        subject,
        providerName: 'Example',
        providerEmail: null,
      });
    const first = await link('first');
    const second = await link('second');
    const caller = { userId: user.id, sessionId: 'session-1', lastAuthenticatedAt: Date.now() };
    const prepare = async (subject: string) =>
      (
        (await unlinks.prepare(caller, { issuer: first.issuer, subject })).body as {
          confirmation_token: string;
        }
      ).confirmation_token;
    const [one, two] = await Promise.all([prepare(first.subject), prepare(second.subject)]);
    const results = await Promise.all([
      unlinks.unlink(caller, {
        issuer: first.issuer,
        subject: first.subject,
        confirmationToken: one,
      }),
      unlinks.unlink(caller, {
        issuer: second.issuer,
        subject: second.subject,
        confirmationToken: two,
      }),
    ]);
    expect(results.map((result) => result.status).sort()).toEqual([200, 409]);
    expect(await links().list(user.id)).toHaveLength(1);
    // A confirmation token is taken by the statement that reads it, so it cannot be replayed.
    expect(
      (
        await unlinks.unlink(caller, {
          issuer: first.issuer,
          subject: first.subject,
          confirmationToken: one,
        })
      ).status,
    ).toBe(400);
  });

  test('concurrent workers deliver a security notification once', async () => {
    const clock = manualClock(Date.now());
    const notifications = useContainer().construct(SecurityNotificationService, { 4: clock });
    const user = await person();
    const link = await links().insert({
      id: crypto.randomUUID(),
      userId: user.id,
      issuer: 'https://n.example',
      subject: 'subject',
      providerName: 'Example',
      providerEmail: null,
    });
    await notifications.enqueue('linked', user.id, link, null);
    const [row] = await database.query<{ id: string }>(
      `SELECT id::text AS id FROM identity_security_notifications WHERE user_id = ?`,
      [user.id],
    );
    clock.advance(1);
    await Promise.all([
      notifications.deliver(row?.id ?? ''),
      notifications.deliver(row?.id ?? ''),
      notifications.deliver(row?.id ?? ''),
    ]);
    expect(mail.to(user.email)).toHaveLength(1);
  });
});
