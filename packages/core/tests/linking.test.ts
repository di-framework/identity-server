import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import type { AuthorizationRepository } from '../src/authorization/domain/models.ts';
import type { DirectoryRepository } from '../src/directory/domain/directory-repository.ts';
import { IdentityProviders } from '../src/linking/application/identity-providers.ts';
import {
  CALLBACK_FAILED,
  CALLBACK_INCOMPLETE,
  LINK_TTL_MS,
  LinkFlowService,
} from '../src/linking/application/link-flow-service.ts';
import {
  type AccountCaller,
  LinkService,
  RECENT_AUTHENTICATION_MS,
  UNLINK_TTL_MS,
} from '../src/linking/application/link-service.ts';
import type { LinkFlow, LinkRepository } from '../src/linking/domain/identity-link.ts';
import {
  HttpIdentityProviderClient,
  type IdentityProviderClient,
} from '../src/linking/infrastructure/http-identity-provider-client.ts';
import {
  NotificationWorker,
  retryDelayMs,
  SecurityNotificationService,
} from '../src/notifications/application/security-notifications.ts';
import { manualClock } from '../src/shared/domain/clock.ts';
import { IssuerCanonicalizer } from '../src/shared/domain/issuer.ts';
import { ServiceResult } from '../src/shared/domain/service-result.ts';
import { AUTHORIZATIONS, DIRECTORY, LINKS } from '../src/shared/domain/tokens.ts';
import { Hashing } from '../src/shared/infrastructure/crypto/hashing.ts';
import { PasswordHasher } from '../src/shared/infrastructure/crypto/passwords.ts';
import {
  type IdentitySettings,
  loadIdentitySettings,
} from '../src/shared/infrastructure/identity-settings.ts';
import { useTestDatabase } from './support/database.ts';
import { FakeIdp } from './support/fake-idp.ts';
import { type RecordingMailSender, useRecordingMail } from './support/mail.ts';

let database: SqlDatabase;
let mail: RecordingMailSender;
let idp: FakeIdp;
const clock = manualClock(Date.now());
const directory = () => useContainer().resolve<DirectoryRepository>(DIRECTORY);
const links = () => useContainer().resolve<LinkRepository>(LINKS);

function settings(providers: IdentitySettings['identityLink']['providers'] = {}): IdentitySettings {
  const base = loadIdentitySettings({ AUTH_PUBLIC_ORIGIN: 'https://identity.example' });
  return { ...base, identityLink: { clientId: 'fallback-client', providers } };
}

function services(client?: IdentityProviderClient) {
  const config = settings({ acme: idp.settings() });
  const providers = new IdentityProviders(config, new IssuerCanonicalizer());
  const notifications = useContainer().construct(SecurityNotificationService, { 4: clock });
  const http = new HttpIdentityProviderClient(clock);
  const flows = useContainer().construct(LinkFlowService, {
    2: providers,
    3: client ?? http,
    4: notifications,
    6: config,
    7: clock,
  });
  const unlinks = useContainer().construct(LinkService, { 4: notifications, 6: clock });
  return { flows, unlinks, notifications, providers };
}

async function person(options: { password?: boolean; verified?: boolean; status?: string } = {}) {
  const id = crypto.randomUUID();
  await directory().insertAccount({
    id,
    login: `link-${id.slice(0, 8)}`,
    email: `link-${id.slice(0, 8)}@example.com`,
    displayName: 'Linker',
    passwordHash: options.password ? await new PasswordHasher().hash('a-long-password') : null,
    emailVerified: options.verified ?? true,
    systemRole: 'user',
    status: options.status ?? 'active',
  });
  return id;
}

beforeAll(async () => {
  database = await useTestDatabase();
  mail = useRecordingMail();
  idp = new FakeIdp('identity-test-client', () => clock.now());
});

afterAll(() => idp.stop());

async function linkedViaFlow(userId: string, sessionId = 'session-1') {
  const { flows } = services();
  idp.subject = `subject-${crypto.randomUUID()}`;
  const location = await flows.start({ userId, sessionId, provider: 'acme' });
  const state = idp.rememberAuthorization(location);
  const result = await flows.callback({ userId, sessionId, state, code: 'code-1' });
  expect(result.kind).toBe('pending');
  return { flows, token: (result as { token: string }).token, subject: idp.subject };
}

describe('issuers and providers', () => {
  test('canonicalizes issuers as the auth server does', () => {
    const issuers = new IssuerCanonicalizer();
    expect(issuers.canonicalize(' HTTPS://Example.COM:443/Team/ ')).toBe(
      'https://example.com/Team',
    );
    expect(issuers.canonicalize('http://example.com:80')).toBe('http://example.com');
    expect(issuers.canonicalize('https://example.com:80/')).toBe('https://example.com');
    expect(issuers.canonicalize('http://example.com:8080/')).toBe('http://example.com:8080');
    for (const [raw, message] of [
      [' ', 'Issuer cannot be blank'],
      ['not a url', 'Invalid issuer URI format'],
      ['ftp://example.com', 'scheme must be http or https'],
      ['https://example.com/?', 'must not contain a query or fragment'],
      ['https://example.com/#', 'must not contain a query or fragment'],
      ['https://example.com/?a=1', 'must not contain a query or fragment'],
    ] as const) {
      expect(() => issuers.canonicalize(raw)).toThrow(message);
    }
  });

  test('resolves configured and built-in providers and validates endpoints', () => {
    const resolve = (
      providers: IdentitySettings['identityLink']['providers'],
      name: string,
      issuer?: string,
    ) =>
      new IdentityProviders(settings(providers), new IssuerCanonicalizer()).resolve(name, issuer);
    const google = resolve({}, ' Google ');
    expect(google).toMatchObject({
      name: 'Google',
      issuer: 'https://accounts.google.com',
      clientId: 'fallback-client',
      scopes: ['openid', 'profile', 'email'],
      freshAuthenticationParameter: 'prompt=login&max_age=0',
    });
    expect(resolve({}, 'github').jwksUri).toBe('');
    expect(resolve({}, 'gitlab').freshAuthenticationParameter).toBe('prompt=login');
    expect(resolve({}, 'okta', 'https://okta.com/').issuer).toBe('https://okta.com');
    const configured = resolve(
      { acme: { ...idp.settings(), clientId: undefined, scopes: ['openid'], clientSecret: 's' } },
      'ACME',
    );
    expect(configured).toMatchObject({
      clientId: 'fallback-client',
      scopes: ['openid'],
      clientSecret: 's',
    });
    const cases: Array<
      [IdentitySettings['identityLink']['providers'], string, string | undefined, string]
    > = [
      [{}, ' ', undefined, 'Identity provider is required'],
      [{}, 'unknown', undefined, 'Identity provider is not configured'],
      [{ acme: { issuer: 'https://a.example' } }, 'acme', undefined, 'incomplete'],
      [{}, 'google', 'https://other.example', 'issuer does not match'],
      [
        { acme: { issuer: 'https://a.example', authorizationEndpoint: 'http://a.example/auth' } },
        'acme',
        undefined,
        'must use HTTPS',
      ],
      [
        {
          acme: {
            issuer: 'https://a.example',
            authorizationEndpoint: 'https://u:p@a.example/auth',
          },
        },
        'acme',
        undefined,
        'user information or fragments',
      ],
      [
        {
          acme: { issuer: 'https://a.example', authorizationEndpoint: 'https://a.example/auth#x' },
        },
        'acme',
        undefined,
        'user information or fragments',
      ],
      [
        { acme: { issuer: 'https://a.example', authorizationEndpoint: 'not a url' } },
        'acme',
        undefined,
        'must contain a host',
      ],
    ];
    for (const [providers, name, issuer, message] of cases) {
      expect(() => resolve(providers, name, issuer)).toThrow(message);
    }
    const loopback = resolve(
      { acme: { issuer: 'http://localhost:1', authorizationEndpoint: 'http://localhost:1/a' } },
      'acme',
    );
    expect(loopback.tokenEndpoint).toBe('');
  });
});

describe('link flow', () => {
  test('start persists a hashed, session-bound transaction and builds the authorize URL', async () => {
    const { flows } = services();
    const userId = await person();
    await expect(
      flows.start({ userId: crypto.randomUUID(), sessionId: 's', provider: 'acme' }),
    ).rejects.toThrow('User not found');
    const location = await flows.start({
      userId,
      sessionId: 'session-x',
      provider: ' acme ',
      returnUrl: '//evil',
    });
    const url = new URL(location);
    expect(url.origin + url.pathname).toBe(`${idp.issuer}/authorize`);
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      client_id: 'identity-test-client',
      redirect_uri: 'https://identity.example/account/identity-links/callback',
      response_type: 'code',
      scope: 'openid profile email',
      code_challenge_method: 'S256',
      prompt: 'login',
    });
    expect(location).toContain('scope=openid+profile+email');
    const state = url.searchParams.get('state') ?? '';
    const flow = await database.first<{
      session_hash: string;
      return_url: string;
      provider_name: string;
    }>(
      `SELECT session_hash, return_url, provider_name FROM identity_link_flows WHERE token_hash = ?`,
      [Hashing.sha256Hex(state)],
    );
    expect(flow).toEqual({
      session_hash: Hashing.sha256Hex('session-x'),
      return_url: '/account/identity-links',
      provider_name: 'acme',
    });
    const audit = await database.first<{ correlation_id: string; target: string }>(
      `SELECT correlation_id, target FROM auth_audit_records WHERE action = 'identity_link.initiated' AND actor_client_id = ?`,
      [userId],
    );
    expect(audit).toEqual({ correlation_id: Hashing.sha256Hex('session-x'), target: idp.issuer });
    const kept = await flows.start({
      userId,
      sessionId: 's',
      provider: 'acme',
      returnUrl: '/account/x',
    });
    const keptState = new URL(kept).searchParams.get('state') ?? '';
    expect(
      (
        await database.first<{ return_url: string }>(
          `SELECT return_url FROM identity_link_flows WHERE token_hash = ?`,
          [Hashing.sha256Hex(keptState)],
        )
      )?.return_url,
    ).toBe('/account/x');
    expect(flows.redirectUri).toBe('https://identity.example/account/identity-links/callback');
  });

  test('callback verifies the provider and stages a pending link once', async () => {
    const { flows } = services();
    const userId = await person();
    expect(
      await flows.callback({
        userId,
        sessionId: 's',
        error: 'access_denied',
        state: 'x',
        code: 'y',
      }),
    ).toEqual({
      kind: 'error',
      message: CALLBACK_INCOMPLETE,
    });
    expect(await flows.callback({ userId, sessionId: 's', state: 'x' })).toMatchObject({
      message: CALLBACK_INCOMPLETE,
    });
    expect(await flows.callback({ userId, sessionId: 's', state: 'unknown', code: 'c' })).toEqual({
      kind: 'error',
      message: CALLBACK_FAILED,
    });
    const location = await flows.start({ userId, sessionId: 's1', provider: 'acme' });
    const state = idp.rememberAuthorization(location);
    expect(
      await flows.callback({ userId, sessionId: 'other-session', state, code: 'c' }),
    ).toMatchObject({ kind: 'error' });
    expect(await flows.callback({ userId, sessionId: 's1', state, code: 'c' })).toMatchObject({
      kind: 'error',
    });

    const again = idp.rememberAuthorization(
      await flows.start({ userId, sessionId: 's1', provider: 'acme' }),
    );
    expect(
      await flows.callback({ userId: await person(), sessionId: 's1', state: again, code: 'c' }),
    ).toMatchObject({ kind: 'error' });

    const expired = idp.rememberAuthorization(
      await flows.start({ userId, sessionId: 's1', provider: 'acme' }),
    );
    clock.advance(LINK_TTL_MS + 1);
    expect(
      await flows.callback({ userId, sessionId: 's1', state: expired, code: 'c' }),
    ).toMatchObject({ kind: 'error' });

    const ok = idp.rememberAuthorization(
      await flows.start({ userId, sessionId: 's1', provider: 'acme' }),
    );
    const result = await flows.callback({ userId, sessionId: 's1', state: ok, code: 'the-code' });
    expect(result.kind).toBe('pending');
    const form = idp.requests.at(-1);
    expect(form?.get('code')).toBe('the-code');
    expect(form?.get('redirect_uri')).toBe(
      'https://identity.example/account/identity-links/callback',
    );
    expect(form?.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(form?.has('client_secret')).toBe(false);
    const pending = flows.pendingFor((result as { token: string }).token, userId);
    expect(pending).toMatchObject({
      userId,
      issuer: idp.issuer,
      subject: idp.subject,
      providerEmail: 'linked@provider.example',
    });
    expect(await flows.callback({ userId, sessionId: 's1', state: ok, code: 'c' })).toMatchObject({
      kind: 'error',
    });
    const audit = await database.first<{ target: string }>(
      `SELECT target FROM auth_audit_records WHERE action = 'identity_link.callback_validated' AND actor_client_id = ?`,
      [userId],
    );
    expect(audit?.target).toBe(`${idp.issuer}#${Hashing.sha256Hex(idp.subject)}`);
    expect(audit?.target).not.toContain(idp.subject);
  });

  test('confirm writes the link, notifies, and audits; cancel and expiry discard it', async () => {
    const userId = await person();
    const { flows, token, subject } = await linkedViaFlow(userId);
    expect(flows.pendingFor(token, crypto.randomUUID())).toBeUndefined();
    expect(flows.pendingFor(undefined, userId)).toBeUndefined();
    expect(flows.pendingFor('missing', userId)).toBeUndefined();
    expect(await flows.confirm(undefined, userId)).toBeUndefined();
    const link = await flows.confirm(token, userId);
    expect(link).toMatchObject({ userId, issuer: idp.issuer, subject, providerName: 'acme' });
    expect(await flows.confirm(token, userId)).toBeUndefined();
    const notice = await database.first<{
      status: string;
      recipient_email: string;
      action: string;
    }>(
      `SELECT status, recipient_email, action FROM identity_security_notifications WHERE user_id = ?`,
      [userId],
    );
    expect(notice).toMatchObject({ status: 'pending', action: 'linked' });
    const created = await database.first<{ after_metadata: Record<string, string> }>(
      `SELECT after_metadata FROM auth_audit_records WHERE action = 'identity_link.created' AND actor_client_id = ?`,
      [userId],
    );
    expect(created?.after_metadata.subject_hint).toBe(Hashing.sha256Hex(subject).slice(0, 16));

    idp.subject = subject;
    const sameUser = idp.rememberAuthorization(
      await flows.start({ userId, sessionId: 's', provider: 'acme' }),
    );
    const restaged = await flows.callback({ userId, sessionId: 's', state: sameUser, code: 'c' });
    expect((await flows.confirm((restaged as { token: string }).token, userId))?.id).toBe(link?.id);

    const thief = await person();
    const stolen = idp.rememberAuthorization(
      await flows.start({ userId: thief, sessionId: 's', provider: 'acme' }),
    );
    expect(
      await flows.callback({ userId: thief, sessionId: 's', state: stolen, code: 'c' }),
    ).toMatchObject({ kind: 'error' });

    const other = await linkedViaFlow(await person());
    other.flows.cancel(other.token, crypto.randomUUID());
    expect(
      other.flows.pendingFor(
        other.token,
        (other.flows.pendingFor(other.token, '') ?? { userId: '' }).userId,
      ),
    ).toBeUndefined();
    const owner = await person();
    const staged = await linkedViaFlow(owner);
    staged.flows.cancel(undefined, owner);
    staged.flows.cancel(staged.token, owner);
    expect(staged.flows.pendingFor(staged.token, owner)).toBeUndefined();

    const late = await linkedViaFlow(owner);
    clock.advance(LINK_TTL_MS + 1);
    expect(late.flows.pendingFor(late.token, owner)).toBeUndefined();
    const lateConfirm = await linkedViaFlow(owner);
    clock.advance(LINK_TTL_MS + 1);
    expect(await lateConfirm.flows.confirm(lateConfirm.token, owner)).toBeUndefined();

    const raced = await linkedViaFlow(owner);
    await links().insert({
      id: crypto.randomUUID(),
      userId: thief,
      issuer: idp.issuer,
      subject: raced.subject,
      providerName: 'acme',
      providerEmail: null,
    });
    expect(await raced.flows.confirm(raced.token, owner)).toBeUndefined();
  });

  test('a provider issuer that differs from the transaction is rejected', async () => {
    const stub: IdentityProviderClient = {
      exchange: async () => ({ issuer: 'https://elsewhere.example', subject: 's', email: null }),
    };
    const { flows } = services(stub);
    const userId = await person();
    const state = idp.rememberAuthorization(
      await flows.start({ userId, sessionId: 's', provider: 'acme' }),
    );
    expect(await flows.callback({ userId, sessionId: 's', state, code: 'c' })).toMatchObject({
      kind: 'error',
    });
  });
});

describe('provider client', () => {
  function flow(overrides: Partial<LinkFlow> = {}): LinkFlow {
    const codeVerifier = Hashing.token();
    return {
      tokenHash: 'h',
      userId: 'u',
      sessionHash: 's',
      providerName: 'acme',
      issuer: idp.issuer,
      nonce: 'nonce-1',
      codeVerifier,
      codeChallenge: Hashing.pkceChallenge(codeVerifier),
      returnUrl: '/',
      createdAt: clock.now(),
      expiresAt: clock.now() + 1000,
      ...overrides,
    };
  }

  test('rejects every invalid exchange or token', async () => {
    const client = new HttpIdentityProviderClient(clock);
    const provider = new IdentityProviders(
      settings({ acme: idp.settings({ clientSecret: 'shh' }) }),
      new IssuerCanonicalizer(),
    ).resolve('acme');
    idp.lastNonce = 'nonce-1';
    const run = (f = flow()) => client.exchange(provider, f, 'code', 'https://identity.example/cb');

    const identity = await run();
    expect(identity).toEqual({
      issuer: idp.issuer,
      subject: idp.subject,
      email: 'linked@provider.example',
    });
    expect(idp.requests.at(-1)?.get('client_secret')).toBe('shh');
    idp.email = undefined;
    expect((await run()).email).toBeNull();
    idp.email = 'linked@provider.example';

    await expect(client.exchange({ ...provider, jwksUri: '' }, flow(), 'c', 'r')).rejects.toThrow(
      'not configured',
    );
    await expect(run(flow({ codeChallenge: 'wrong' }))).rejects.toThrow('PKCE');
    const cases: Array<[Partial<FakeIdp['behaviour']>, string]> = [
      [{ status: 400 }, 'could not be completed'],
      [{ body: 'not json' }, 'invalid token response'],
      [{ body: '[1]' }, 'invalid token response'],
      [{ noIdToken: true }, 'signed identity token'],
      [{ foreignKey: true }, 'Invalid token signature'],
      [{ claims: { iss: 'https://evil.example' } }, 'issuer is invalid'],
      [{ claims: { exp: Math.floor(clock.now() / 1000) - 120 } }, 'expired'],
      [{ claims: { exp: 'soon' } }, 'expired'],
      [{ claims: { nbf: Math.floor(clock.now() / 1000) + 600 } }, 'not yet valid'],
      [{ claims: { sub: ' ' } }, 'subject'],
      [{ claims: { aud: ['someone-else'] } }, 'audience'],
      [{ claims: { nonce: 'other' } }, 'nonce'],
      [{ claims: { auth_time: Math.floor(clock.now() / 1000) - 3600 } }, 'not fresh'],
      [{ claims: { auth_time: undefined } }, 'not fresh'],
    ];
    for (const [behaviour, message] of cases) {
      idp.behaviour = behaviour;
      await expect(run()).rejects.toThrow(message);
    }
    idp.behaviour = {
      claims: { aud: ['x', 'identity-test-client'], nbf: Math.floor(clock.now() / 1000) },
    };
    expect((await run()).subject).toBe(idp.subject);
    idp.behaviour = {};
  });
});

describe('unlinking', () => {
  async function linkFor(userId: string, subject = `sub-${crypto.randomUUID()}`) {
    return links().insert({
      id: crypto.randomUUID(),
      userId,
      issuer: 'https://idp.example',
      subject,
      providerName: 'Example',
      providerEmail: null,
    });
  }

  function caller(userId: string, sessionId = 'session-1'): AccountCaller {
    return { userId, sessionId, lastAuthenticatedAt: clock.now() };
  }

  test('lists, prepares, and unlinks with step-up, binding, and the final-method rule', async () => {
    const { unlinks } = services();
    const userId = await person({ password: true });
    const link = await linkFor(userId);
    const status = async (result: Promise<ServiceResult>) => (await result).status;
    expect(await status(unlinks.list(undefined))).toBe(403);
    expect(await status(unlinks.list({ userId: 'not-a-uuid' }))).toBe(403);
    expect(await status(unlinks.list({ userId: crypto.randomUUID() }))).toBe(404);
    expect((await unlinks.list({ userId })).body).toEqual([
      expect.objectContaining({
        id: link.id,
        subjectHint: Hashing.sha256Hex(link.subject).slice(0, 16),
      }),
    ]);

    const input = { issuer: 'https://IDP.example/', subject: link.subject };
    expect(await status(unlinks.prepare(undefined, input))).toBe(403);
    expect(await status(unlinks.prepare({ userId }, input))).toBe(403);
    expect(
      await status(
        unlinks.prepare(
          { ...caller(userId), lastAuthenticatedAt: clock.now() - RECENT_AUTHENTICATION_MS - 1 },
          input,
        ),
      ),
    ).toBe(403);
    expect(await status(unlinks.prepare(caller(userId), { issuer: 'bad', subject: 'x' }))).toBe(
      400,
    );
    expect(
      await status(unlinks.prepare(caller(userId), { issuer: input.issuer, subject: ' ' })),
    ).toBe(400);
    expect(await status(unlinks.prepare(caller(crypto.randomUUID()), input))).toBe(404);
    expect(await status(unlinks.prepare(caller(userId), { ...input, subject: 'missing' }))).toBe(
      404,
    );
    const prepared = await unlinks.prepare(caller(userId), input);
    expect(prepared.body).toMatchObject({
      expires_in: UNLINK_TTL_MS / 1000,
      identity: { id: link.id },
    });
    const token = (prepared.body as { confirmation_token: string }).confirmation_token;

    expect(await status(unlinks.unlink(undefined, input))).toBe(403);
    expect(await status(unlinks.unlink({ userId }, { ...input, confirmationToken: token }))).toBe(
      400,
    );
    expect(await status(unlinks.unlink(caller(userId), input))).toBe(400);
    expect(
      await status(
        unlinks.unlink(caller(userId), { issuer: 'bad', subject: 'x', confirmationToken: token }),
      ),
    ).toBe(400);
    expect(
      await status(
        unlinks.unlink(caller(userId), {
          issuer: input.issuer,
          subject: '',
          confirmationToken: token,
        }),
      ),
    ).toBe(400);
    expect(
      await status(unlinks.unlink(caller(userId), { ...input, confirmationToken: 'short' })),
    ).toBe(400);
    expect(
      await status(
        unlinks.unlink(caller(userId), { ...input, confirmationToken: Hashing.token() }),
      ),
    ).toBe(400);
    expect(
      await status(
        unlinks.unlink(caller(userId, 'other-session'), { ...input, confirmationToken: token }),
      ),
    ).toBe(400);
    expect(
      await status(unlinks.unlink(caller(userId), { ...input, confirmationToken: token })),
    ).toBe(400);

    const authorization = useContainer().resolve<AuthorizationRepository>(AUTHORIZATIONS);
    await authorization.save({
      id: crypto.randomUUID(),
      registeredClientId: 'c',
      principalName: userId,
      grantType: 'authorization_code',
      authorizedScopes: [],
      attributes: {},
      state: null,
      code: null,
      access: null,
      refresh: null,
      idToken: null,
    });
    const fresh = (await unlinks.prepare(caller(userId), input)).body as {
      confirmation_token: string;
    };
    expect(
      await status(
        unlinks.unlink(caller(userId), {
          ...input,
          subject: 'other',
          confirmationToken: fresh.confirmation_token,
        }),
      ),
    ).toBe(400);
    const again = (await unlinks.prepare(caller(userId), input)).body as {
      confirmation_token: string;
    };
    const removed = await unlinks.unlink(caller(userId), {
      ...input,
      confirmationToken: again.confirmation_token,
    });
    expect(removed.body).toEqual({
      unlinked: true,
      issuer: 'https://idp.example',
      subject_hint: Hashing.sha256Hex(link.subject).slice(0, 16),
    });
    expect(
      await database.first(`SELECT 1 FROM oauth2_authorization WHERE principal_name = ?`, [userId]),
    ).toBeNull();
    expect(
      await database.first<{ action: string; correlation_id: string }>(
        `SELECT action, correlation_id FROM identity_security_notifications WHERE user_id = ?`,
        [userId],
      ),
    ).toEqual({ action: 'unlinked', correlation_id: 'session-1' });
    const audit = await database.first<{
      correlation_id: string;
      before_metadata: Record<string, string>;
    }>(
      `SELECT correlation_id, before_metadata FROM auth_audit_records WHERE action = 'identity_link.removed' AND actor_client_id = ?`,
      [userId],
    );
    expect(audit?.correlation_id).toBe(Hashing.sha256Hex('session-1'));
    expect(audit?.before_metadata).toEqual({
      providerName: 'Example',
      subject_hint: Hashing.sha256Hex(link.subject).slice(0, 16),
    });

    const expiring = await linkFor(userId);
    const late = (
      await unlinks.prepare(caller(userId), { issuer: expiring.issuer, subject: expiring.subject })
    ).body as { confirmation_token: string };
    clock.advance(UNLINK_TTL_MS);
    expect(
      await status(
        unlinks.unlink(
          { ...caller(userId) },
          {
            issuer: expiring.issuer,
            subject: expiring.subject,
            confirmationToken: late.confirmation_token,
          },
        ),
      ),
    ).toBe(400);
  });

  test('refuses the final sign-in method and inactive accounts', async () => {
    const { unlinks } = services();
    const only = await person({ verified: false });
    const link = await linkFor(only);
    const input = { issuer: link.issuer, subject: link.subject };
    const token = (
      (await unlinks.prepare(caller(only), input)).body as { confirmation_token: string }
    ).confirmation_token;
    expect(
      (await unlinks.unlink(caller(only), { ...input, confirmationToken: token })).status,
    ).toBe(409);

    const twoLinks = await person({ verified: false });
    const first = await linkFor(twoLinks);
    await linkFor(twoLinks);
    const ok = (
      (await unlinks.prepare(caller(twoLinks), { issuer: first.issuer, subject: first.subject }))
        .body as { confirmation_token: string }
    ).confirmation_token;
    expect(
      (
        await unlinks.unlink(caller(twoLinks), {
          issuer: first.issuer,
          subject: first.subject,
          confirmationToken: ok,
        })
      ).status,
    ).toBe(200);

    const pending = await person({ status: 'pending' });
    const pendingLink = await linkFor(pending);
    expect(
      (
        await unlinks.prepare(caller(pending), {
          issuer: pendingLink.issuer,
          subject: pendingLink.subject,
        })
      ).status,
    ).toBe(409);

    const archivedLater = await person({ password: true });
    const archivedLink = await linkFor(archivedLater);
    const archivedToken = (
      (
        await unlinks.prepare(caller(archivedLater), {
          issuer: archivedLink.issuer,
          subject: archivedLink.subject,
        })
      ).body as { confirmation_token: string }
    ).confirmation_token;
    await directory().updateAccount(archivedLater, { status: 'archived' });
    expect(
      (
        await unlinks.unlink(caller(archivedLater), {
          issuer: archivedLink.issuer,
          subject: archivedLink.subject,
          confirmationToken: archivedToken,
        })
      ).status,
    ).toBe(409);

    const vanished = await person({ password: true });
    const vanishedLink = await linkFor(vanished);
    const vanishedToken = (
      (
        await unlinks.prepare(caller(vanished), {
          issuer: vanishedLink.issuer,
          subject: vanishedLink.subject,
        })
      ).body as { confirmation_token: string }
    ).confirmation_token;
    await links().delete(vanishedLink.id);
    expect(
      (
        await unlinks.unlink(caller(vanished), {
          issuer: vanishedLink.issuer,
          subject: vanishedLink.subject,
          confirmationToken: vanishedToken,
        })
      ).status,
    ).toBe(404);
  });

  test('the account page unlink start, pending view, and confirm', async () => {
    const { unlinks } = services();
    const userId = await person({ password: true });
    const link = await linkFor(userId);
    expect(await unlinks.startUnlink({ userId, sessionId: 's' }, link.id)).toBeInstanceOf(
      ServiceResult,
    );
    expect(await unlinks.startUnlink(caller(userId), 'not-a-uuid')).toMatchObject({ status: 403 });
    expect(await unlinks.startUnlink(caller(await person()), link.id)).toMatchObject({
      status: 403,
    });
    expect(await unlinks.pendingUnlink({ userId })).toBeUndefined();
    expect(await unlinks.pendingUnlink(caller(userId))).toBeUndefined();
    const token = await unlinks.startUnlink(caller(userId), link.id);
    expect(typeof token).toBe('string');
    expect(await unlinks.pendingUnlink(caller(userId))).toMatchObject({ id: link.id });
    expect(await unlinks.confirmUnlink(caller(userId), null)).toBe(false);
    expect(await unlinks.confirmUnlink({ userId }, token as string)).toBe(false);
    expect(await unlinks.confirmUnlink(caller(userId), token as string)).toBe(true);
    expect(await unlinks.pendingUnlink(caller(userId))).toBeUndefined();

    const second = await linkFor(userId);
    const stale = await unlinks.startUnlink(caller(userId), second.id);
    clock.advance(UNLINK_TTL_MS);
    expect(await unlinks.pendingUnlink(caller(userId))).toBeUndefined();
    expect(await unlinks.confirmUnlink(caller(userId), stale as string)).toBe(false);
    const inactive = await person({ status: 'pending' });
    const inactiveLink = await linkFor(inactive);
    expect(await unlinks.startUnlink(caller(inactive), inactiveLink.id)).toMatchObject({
      status: 409,
    });
    expect(await unlinks.startUnlink(caller(crypto.randomUUID()), inactiveLink.id)).toMatchObject({
      status: 403,
    });
  });
});

describe('security notifications', () => {
  test('deduplicates, skips unverified contacts, delivers, and retries with backoff', async () => {
    const { notifications } = services();
    const worker = useContainer().construct(NotificationWorker, { 1: notifications, 2: clock });
    const verified = await person();
    const link = await links().insert({
      id: crypto.randomUUID(),
      userId: verified,
      issuer: 'https://n.example',
      subject: 'secret-subject',
      providerName: 'Prov\r\nider',
      providerEmail: null,
    });
    await notifications.enqueue('linked', verified, link, null);
    await notifications.enqueue('linked', verified, link, null);
    await notifications.enqueue('linked', crypto.randomUUID(), link, null);
    const rows = await database.query<{ id: string; provider_name: string; status: string }>(
      `SELECT id::text AS id, provider_name, status FROM identity_security_notifications WHERE user_id = ?`,
      [verified],
    );
    expect(rows).toEqual([
      { id: expect.any(String), provider_name: 'Prov  ider', status: 'pending' },
    ]);

    const unverified = await person({ verified: false });
    await notifications.enqueue('unlinked', unverified, link, 'corr');
    expect(
      (
        await database.first<{ status: string }>(
          `SELECT status FROM identity_security_notifications WHERE user_id = ?`,
          [unverified],
        )
      )?.status,
    ).toBe('skipped_no_verified_contact');

    clock.advance(1);
    mail.failNext = 1;
    await notifications.deliver(rows[0]?.id ?? '');
    const failed = await database.first<{
      status: string;
      attempts: number;
      last_error: string;
      next_attempt_at: Date;
    }>(
      `SELECT status, attempts, last_error, next_attempt_at FROM identity_security_notifications WHERE id = ?`,
      [rows[0]?.id],
    );
    expect(failed).toMatchObject({ status: 'failed', attempts: 1, last_error: 'delivery_failed' });
    expect(new Date(failed?.next_attempt_at as Date).getTime()).toBe(clock.now() + 30_000);
    await notifications.deliver(rows[0]?.id ?? '');
    expect(
      (
        await database.first<{ attempts: number }>(
          `SELECT attempts FROM identity_security_notifications WHERE id = ?`,
          [rows[0]?.id],
        )
      )?.attempts,
    ).toBe(1);
    clock.advance(30_001);
    await notifications.deliver(rows[0]?.id ?? '');
    const sent = mail.to(`link-${verified.slice(0, 8)}@example.com`).at(-1);
    expect(sent?.subject).toBe('GSIO account security notification');
    expect(sent?.text).toContain('An external identity was linked on your GSIO account.');
    expect(sent?.text).toContain(
      `Identity hint: ${Hashing.sha256Hex('secret-subject').slice(0, 16)}`,
    );
    expect(sent?.text).not.toContain('secret-subject');
    await notifications.deliver(rows[0]?.id ?? '');
    await notifications.deliver(crypto.randomUUID());
    const actions = (
      await database.query<{ action: string }>(
        `SELECT action FROM auth_audit_records WHERE target = (SELECT event_key FROM identity_security_notifications WHERE id = ?) ORDER BY created_at`,
        [rows[0]?.id],
      )
    ).map((row) => row.action);
    expect(actions).toEqual([
      'identity_security_notification.queued',
      'identity_security_notification.failed',
      'identity_security_notification.sent',
    ]);

    const orphan = crypto.randomUUID();
    await database.run(
      `INSERT INTO identity_security_notifications (id, event_key, user_id, action, provider_name, issuer, identity_hint, status, next_attempt_at, created_at)
       VALUES (?, ?, ?, 'linked', 'p', 'i', 'h', 'pending', ?, ?)`,
      [
        orphan,
        Hashing.sha256Hex(orphan),
        verified,
        new Date(clock.now() - 1),
        new Date(clock.now()),
      ],
    );
    expect(await worker.runOnce()).toBeGreaterThanOrEqual(1);
    expect(
      (
        await database.first<{ status: string }>(
          `SELECT status FROM identity_security_notifications WHERE id = ?`,
          [orphan],
        )
      )?.status,
    ).toBe('skipped_no_verified_contact');
    expect([1, 2, 8, 9, 20].map(retryDelayMs)).toEqual([
      30_000, 60_000, 3_600_000, 3_600_000, 3_600_000,
    ]);
    expect(retryDelayMs(0)).toBe(30_000);
  });

  test('the worker loop runs on a fixed delay until stopped and reports errors', async () => {
    const errors: unknown[] = [];
    let calls = 0;
    const worker = new NotificationWorker(
      {
        due: async () => {
          calls += 1;
          if (calls === 2) throw new Error('boom');
          return [];
        },
      } as never,
      {} as SecurityNotificationService,
      clock,
    );
    worker.start(5, (error) => errors.push(error));
    worker.start(5);
    await Bun.sleep(40);
    worker.stop();
    const seen = calls;
    await Bun.sleep(20);
    expect(calls).toBe(seen);
    expect(calls).toBeGreaterThanOrEqual(3);
    expect(errors).toHaveLength(1);
    const quiet = new NotificationWorker(
      {
        due: async () => {
          throw new Error('x');
        },
      } as never,
      {} as SecurityNotificationService,
      clock,
    );
    quiet.start(1);
    await Bun.sleep(10);
    quiet.stop();
  });
});
