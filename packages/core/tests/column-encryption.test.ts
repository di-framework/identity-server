import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHmac, randomBytes } from 'node:crypto';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import type { ChallengeRepository } from '../src/account/domain/challenge.ts';
import type { AuditRepository } from '../src/audit/domain/audit-entry.ts';
import type { Authorization, AuthorizationRepository } from '../src/authorization/domain/models.ts';
import { IdentityModule } from '../src/composition.ts';
import type { DirectoryRepository } from '../src/directory/domain/directory-repository.ts';
import type { LinkRepository } from '../src/linking/domain/identity-link.ts';
import type { NotificationRepository } from '../src/notifications/domain/notification.ts';
import type { SessionRepository } from '../src/sessions/domain/session.ts';
import type { IdentityError } from '../src/shared/domain/identity-error.ts';
import {
  AUDIT,
  AUTHORIZATIONS,
  CHALLENGES,
  DIRECTORY,
  LINKS,
  NOTIFICATIONS,
  SESSIONS,
} from '../src/shared/domain/tokens.ts';
import {
  ColumnCipher,
  ColumnEncryption,
  ColumnEncryptionUnavailable,
  keyCheck,
} from '../src/shared/infrastructure/column-encryption.ts';
import {
  type IdentitySettings,
  loadIdentitySettings,
} from '../src/shared/infrastructure/identity-settings.ts';
import {
  PLAINTEXT_REJECTED,
  PostgresGateway,
} from '../src/shared/infrastructure/postgres-gateway.ts';
import { Sql, sql } from '../src/shared/infrastructure/sql.ts';
import { useIsolatedDatabase } from './support/database.ts';

const COLUMN_KEY = randomBytes(32).toString('base64');
const BIDX_KEY = randomBytes(32).toString('base64');
const ISSUER = 'https://idp.example';

let isolated: Awaited<ReturnType<typeof useIsolatedDatabase>>;
let original: IdentitySettings;
/** Every statement text and its bindings, as the database received them. */
const statements: Array<{ text: string; params: unknown[] }> = [];

const resolve = <T>(token: string) => useContainer().resolve<T>(token);
const directory = () => resolve<DirectoryRepository>(DIRECTORY);
const links = () => resolve<LinkRepository>(LINKS);
const sessions = () => resolve<SessionRepository>(SESSIONS);
const audits = () => resolve<AuditRepository>(AUDIT);
const challenges = () => resolve<ChallengeRepository>(CHALLENGES);
const notifications = () => resolve<NotificationRepository>(NOTIFICATIONS);
const authorizations = () => resolve<AuthorizationRepository>(AUTHORIZATIONS);
const encryption = () => useContainer().resolve(ColumnEncryption);
const raw = () => isolated.database;

function recording(db: SqlDatabase): SqlDatabase {
  const note = <T>(text: string, params: unknown[] | undefined, result: T): T => {
    statements.push({ text, params: params ?? [] });
    return result;
  };
  return {
    ...db,
    query: (text, params) => note(text, params, db.query(text, params)),
    first: (text, params) => note(text, params, db.first(text, params)),
    run: (text, params) => note(text, params, db.run(text, params)),
    exec: (text) => note(text, [], db.exec(text)),
    transaction: (fn) => db.transaction((tx) => fn(recording(tx))),
  } as SqlDatabase;
}

function configure(encryptionSettings: Partial<IdentitySettings['encryption']>): void {
  IdentityModule.configure({
    ...original,
    encryption: { columns: false, columnKey: '', bidxKey: '', ...encryptionSettings },
  });
}

const enabledSettings = { columns: true, columnKey: COLUMN_KEY, bidxKey: BIDX_KEY };

function bidx(value: string): string {
  return createHmac('sha256', BIDX_KEY).update(value).digest('hex');
}

function authorization(id: string, claims: Record<string, unknown>): Authorization {
  const now = Date.now();
  const token = (hash: string) => ({
    hash,
    issuedAt: now,
    expiresAt: now + 60_000,
    invalidated: false,
  });
  return {
    id,
    registeredClientId: 'client',
    principalName: 'principal',
    grantType: 'authorization_code',
    authorizedScopes: ['openid'],
    attributes: {},
    state: null,
    code: token(`code-${id}`),
    access: null,
    refresh: null,
    idToken: { ...token(`id-${id}`), claims },
  };
}

/** One row through every repository that writes a protected column. */
async function seed(tag: string) {
  const userId = crypto.randomUUID();
  const email = `${tag}@Example.com`;
  await directory().insertAccount({
    id: userId,
    login: `${tag}-login`,
    email,
    displayName: `${tag} name`,
    passwordHash: null,
    emailVerified: true,
    systemRole: 'user',
    status: 'active',
  });
  const linkId = crypto.randomUUID();
  const subject = `${tag}-subject`;
  await links().insert({
    id: linkId,
    userId,
    issuer: ISSUER,
    subject,
    providerName: 'acme',
    providerEmail: `${tag}@provider.example`,
  });
  const flowHash = `${tag}-flow`.padEnd(64, 'f');
  const now = Date.now();
  await links().insertFlow({
    tokenHash: flowHash,
    userId,
    sessionHash: 's'.repeat(64),
    providerName: 'acme',
    issuer: ISSUER,
    nonce: `${tag}-nonce`,
    codeVerifier: `${tag}-verifier`,
    codeChallenge: 'challenge',
    returnUrl: '/account',
    createdAt: now,
    expiresAt: now + 60_000,
  });
  const confirmationHash = `${tag}-confirm`.padEnd(64, 'c');
  await links().insertConfirmation({
    tokenHash: confirmationHash,
    userId,
    sessionHash: `${tag}-session`.padEnd(64, 's'),
    issuer: ISSUER,
    subject,
    expiresAt: new Date(now + 60_000),
  });
  const sessionId = `${tag}-sid`.padEnd(64, '0');
  await sessions().insert(
    {
      id: sessionId,
      userId,
      csrf: 'csrf',
      lastAuthenticatedAt: null,
      attributes: { SPRING_SECURITY_SAVED_REQUEST: `/${tag}` },
      expiresAt: now + 60_000,
    },
    now,
  );
  await audits().append({
    action: `test.${tag}`,
    actor: userId,
    target: null,
    correlationId: tag,
    before: { tag },
    after: { email },
  });
  const challengeId = crypto.randomUUID();
  expect(
    await challenges().insertUnlessRecent(
      {
        id: challengeId,
        userId,
        email,
        tokenHash: `${tag}-challenge`.padEnd(64, 'h'),
        purpose: 'sign_in',
        expiresAt: now + 60_000,
        consumedAt: null,
      },
      now,
      now - 60_000,
    ),
  ).toBe(true);
  const notificationId = crypto.randomUUID();
  await notifications().insertIfAbsent({
    id: notificationId,
    eventKey: `${tag}-event`.padEnd(64, 'e'),
    userId,
    action: 'linked',
    recipientEmail: email,
    providerName: 'acme',
    issuer: ISSUER,
    identityHint: 'hint',
    correlationId: null,
    status: 'pending',
    attempts: 0,
    nextAttemptAt: now - 1,
    createdAt: now,
    sentAt: null,
    lastError: null,
  });
  const authorizationId = `${tag}-authorization`;
  await authorizations().save(authorization(authorizationId, { email, sub: userId }));
  return {
    tag,
    userId,
    email,
    linkId,
    subject,
    flowHash,
    confirmationHash,
    sessionId,
    challengeId,
    notificationId,
    authorizationId,
    now,
  };
}

type Seeded = Awaited<ReturnType<typeof seed>>;

/** Reads every protected value back through the repositories. */
async function expectReadable(row: Seeded): Promise<void> {
  const user = await directory().findUser(row.userId);
  expect(user).toMatchObject({ email: row.email, displayName: `${row.tag} name` });
  expect(await directory().findUserByEmail(row.email.toUpperCase())).toMatchObject({
    id: row.userId,
  });
  expect(await directory().findUserByEmailOrLogin(` ${row.email} `, 'nobody')).toMatchObject({
    id: row.userId,
  });
  expect(await directory().findActiveByLoginOrEmail(row.email.toLowerCase())).toMatchObject({
    id: row.userId,
  });
  expect(await directory().findActiveByLoginOrEmail(`${row.tag}-login`)).toMatchObject({
    id: row.userId,
  });
  expect(await links().find(row.userId, ISSUER, row.subject)).toMatchObject({
    id: row.linkId,
    subject: row.subject,
    providerEmail: `${row.tag}@provider.example`,
  });
  expect(await links().lockByIdentity(ISSUER, row.subject)).toMatchObject({ id: row.linkId });
  expect(await links().lockForUser(row.userId, ISSUER, row.subject)).toMatchObject({
    id: row.linkId,
  });
  expect(await links().lockByIdentity(ISSUER, `${row.subject}-other`)).toBeUndefined();
  expect((await links().list(row.userId)).map((link) => link.subject)).toEqual([row.subject]);
  expect(
    (await directory().membershipsForUser(row.userId)).map((membership) => membership.userEmail),
  ).toEqual([]);
  expect(
    await links().latestConfirmation(row.userId, `${row.tag}-session`.padEnd(64, 's')),
  ).toMatchObject({ subject: row.subject });
  expect((await sessions().find(row.sessionId))?.attributes).toEqual({
    SPRING_SECURITY_SAVED_REQUEST: `/${row.tag}`,
  });
  const entries = await audits().list();
  const entry = entries.find((candidate) => candidate.correlationId === row.tag);
  expect(entry).toBeDefined();
  expect(JSON.parse((await audits().find(entry?.id ?? ''))?.afterMetadata ?? '{}')).toEqual({
    email: row.email,
  });
  expect((await challenges().lockByHash(`${row.tag}-challenge`.padEnd(64, 'h')))?.email).toBe(
    row.email,
  );
  expect((await authorizations().findById(row.authorizationId))?.idToken?.claims).toEqual({
    email: row.email,
    sub: row.userId,
  });
  expect((await authorizations().findByToken('code', `code-${row.authorizationId}`))?.id).toBe(
    row.authorizationId,
  );
}

beforeAll(async () => {
  isolated = await useIsolatedDatabase('identity_column_encryption_test');
  original = IdentityModule.settings();
  IdentityModule.connect(recording(isolated.database));
  configure({});
});

afterAll(async () => {
  IdentityModule.configure(original);
  await isolated.release();
});

describe('opt-in column encryption', () => {
  let legacy: Seeded;
  let fresh: Seeded;

  test('V18 leaves encryption disabled: rows are plaintext and statements use no pgcrypto', async () => {
    legacy = await seed('legacy');
    expect(
      await raw().first<Record<string, unknown>>('SELECT enabled FROM identity_column_encryption'),
    ).toEqual({
      enabled: false,
    });
    expect(
      await raw().first<Record<string, unknown>>(
        `SELECT email, normalized_email, display_name, email_enc, normalized_email_bidx
         FROM users WHERE id = ?`,
        [legacy.userId],
      ),
    ).toEqual({
      email: legacy.email,
      normalized_email: legacy.email.toLowerCase(),
      display_name: 'legacy name',
      email_enc: null,
      normalized_email_bidx: null,
    });
    expect(statements.some((statement) => /pgp_sym|hmac\(/.test(statement.text))).toBe(false);
    await expectReadable(legacy);
  });

  test('keys without the opt-in switch change nothing', async () => {
    configure({ columnKey: COLUMN_KEY, bidxKey: BIDX_KEY });
    expect((await encryption().cipher()).enabled).toBe(false);
  });

  test('opting in latches the state with key checks, not keys', async () => {
    configure(enabledSettings);
    expect((await encryption().cipher()).enabled).toBe(true);
    const state = await raw().first<Record<string, unknown>>(
      'SELECT * FROM identity_column_encryption',
    );
    expect(state).toMatchObject({
      enabled: true,
      column_key_check: keyCheck(COLUMN_KEY),
      bidx_key_check: keyCheck(BIDX_KEY),
    });
    expect(JSON.stringify(state)).not.toContain(COLUMN_KEY);
    expect(JSON.stringify(state)).not.toContain(BIDX_KEY);
  });

  test('new rows hold ciphertext and blind indexes; plaintext columns are NULL', async () => {
    fresh = await seed('fresh');
    const user = await raw().first<Record<string, unknown>>(
      `SELECT email, normalized_email, display_name, avatar_url, email_enc IS NOT NULL AS enc,
              display_name_enc IS NOT NULL AS name_enc, normalized_email_bidx
       FROM users WHERE id = ?`,
      [fresh.userId],
    );
    expect(user).toMatchObject({
      email: null,
      normalized_email: null,
      display_name: null,
      avatar_url: null,
      enc: true,
      name_enc: true,
    });
    expect(Buffer.from(user?.normalized_email_bidx as Uint8Array).toString('hex')).toEqual(
      bidx(fresh.email.toLowerCase()),
    );
    const plaintextColumns: Array<[string, string, string, unknown]> = [
      ['identity_links', 'subject, provider_email', 'id', fresh.linkId],
      ['identity_link_flows', 'nonce, code_verifier', 'token_hash', fresh.flowHash],
      ['identity_unlink_confirmations', 'subject', 'token_hash', fresh.confirmationHash],
      ['browser_sessions', 'attributes', 'id', fresh.sessionId],
      ['email_challenges', 'email', 'id', fresh.challengeId],
      ['identity_security_notifications', 'recipient_email', 'id', fresh.notificationId],
      ['oauth2_authorization', 'oidc_id_token_claims', 'id', fresh.authorizationId],
      ['auth_audit_records', 'before_metadata, after_metadata', 'correlation_id', 'fresh'],
    ];
    for (const [table, columns, key, value] of plaintextColumns) {
      const row = await raw().first<Record<string, unknown>>(
        `SELECT ${columns} FROM ${table} WHERE ${key} = ?`,
        [value],
      );
      expect([table, Object.values(row ?? { missing: 1 }).every((v) => v === null)]).toEqual([
        table,
        true,
      ]);
    }
    const link = await raw().first<{ subject_bidx: Uint8Array }>(
      'SELECT subject_bidx FROM identity_links WHERE id = ?',
      [fresh.linkId],
    );
    expect(Buffer.from(link?.subject_bidx as Uint8Array).toString('hex')).toEqual(
      bidx(fresh.subject),
    );
    const challenge = await raw().first<{ email_bidx: Uint8Array }>(
      'SELECT email_bidx FROM email_challenges WHERE id = ?',
      [fresh.challengeId],
    );
    expect(Buffer.from(challenge?.email_bidx as Uint8Array).toString('hex')).toEqual(
      bidx(fresh.email.toLowerCase()),
    );
    // Without the key the ciphertext is opaque: it is not the value in any encoding.
    const dump = JSON.stringify(
      await raw().query("SELECT encode(email_enc, 'escape') AS e FROM users WHERE id = ?", [
        fresh.userId,
      ]),
    );
    expect(dump).not.toContain('fresh@');
  });

  test('reads and lookups cover legacy plaintext and new ciphertext rows', async () => {
    await expectReadable(legacy);
    await expectReadable(fresh);
    const organizationId = crypto.randomUUID();
    await directory().insertOrganization({ id: organizationId, slug: 'colenc', name: 'Colenc' });
    await directory().upsertMembership(organizationId, legacy.userId, 'owner');
    await directory().upsertMembership(organizationId, fresh.userId, 'member');
    const listed = await directory().listMembers('colenc', undefined, 10);
    expect(new Set(listed.map((member) => `${member.email}|${member.displayName}`))).toEqual(
      new Set([`${legacy.email}|legacy name`, `${fresh.email}|fresh name`]),
    );
    expect(await directory().listMembers('colenc', listed[1]?.id, 10)).toEqual([]);
    expect(
      new Set(
        (await directory().membershipsForOrganization('colenc')).map(
          (membership) => membership.userEmail,
        ),
      ),
    ).toEqual(new Set([legacy.email, fresh.email]));
    expect((await directory().allMemberships()).map((m) => m.userDisplayName).sort()).toEqual([
      'fresh name',
      'legacy name',
    ]);
    const members = await directory().listUsers();
    expect(members.find((user) => user.id === fresh.userId)?.email).toBe(fresh.email);
    expect(members.find((user) => user.id === legacy.userId)?.email).toBe(legacy.email);
    const claimed = await notifications().claim(fresh.notificationId, Date.now(), Date.now() + 1);
    expect(claimed?.recipientEmail).toBe(fresh.email);
    expect(
      (await notifications().claim(legacy.notificationId, Date.now(), Date.now() + 1))
        ?.recipientEmail,
    ).toBe(legacy.email);
    expect(await links().takeFlow(fresh.flowHash)).toMatchObject({
      nonce: 'fresh-nonce',
      codeVerifier: 'fresh-verifier',
    });
    expect(await links().takeFlow(legacy.flowHash)).toMatchObject({ nonce: 'legacy-nonce' });
    expect(await links().takeConfirmation(fresh.confirmationHash)).toMatchObject({
      subject: fresh.subject,
    });
    expect(await links().takeConfirmation(legacy.confirmationHash)).toMatchObject({
      subject: legacy.subject,
    });
  });

  test('uniqueness spans legacy plaintext and blind indexes', async () => {
    const account = (email: string | null) =>
      directory().insertAccount({
        id: crypto.randomUUID(),
        login: `dup-${crypto.randomUUID().slice(0, 8)}`,
        email,
        displayName: 'dup',
        passwordHash: null,
        emailVerified: false,
        systemRole: 'user',
        status: 'pending',
      });
    for (const email of [legacy.email.toLowerCase(), fresh.email.toUpperCase()]) {
      await expect(account(email)).rejects.toMatchObject({ status: 409 });
    }
    // Without an email nothing conflicts.
    await account(null);
    const link = (subject: string) =>
      links().insert({
        id: crypto.randomUUID(),
        userId: legacy.userId,
        issuer: ISSUER,
        subject,
        providerName: 'acme',
        providerEmail: null,
      });
    await expect(link(legacy.subject)).rejects.toMatchObject({ status: 409 });
    await expect(link(fresh.subject)).rejects.toMatchObject({ status: 409 });
    expect((await link('another-subject')).subject).toBe('another-subject');
  });

  test('the challenge rate limit sees legacy and new challenges', async () => {
    const now = Date.now();
    const attempt = (email: string) =>
      challenges().insertUnlessRecent(
        {
          id: crypto.randomUUID(),
          userId: null,
          email,
          tokenHash: crypto.randomUUID().replaceAll('-', '').padEnd(64, 'r'),
          purpose: 'sign_in',
          expiresAt: now + 60_000,
          consumedAt: null,
        },
        now,
        now - 3_600_000,
      );
    expect(await attempt(legacy.email)).toBe(false);
    expect(await attempt(fresh.email.toUpperCase())).toBe(false);
    expect(await attempt('new-address@example.com')).toBe(true);
  });

  test('updates to legacy rows encrypt what they write and keep the rest', async () => {
    await directory().updateDisplayName(legacy.userId, 'renamed');
    await directory().updateAccount(legacy.userId, { status: 'active' });
    const row = await raw().first<Record<string, unknown>>(
      'SELECT email, display_name, display_name_enc IS NOT NULL AS enc FROM users WHERE id = ?',
      [legacy.userId],
    );
    expect(row).toEqual({ email: legacy.email, display_name: null, enc: true });
    expect((await directory().findUser(legacy.userId))?.displayName).toBe('renamed');
    const session = await sessions().find(legacy.sessionId);
    await sessions().update(
      { ...(session as NonNullable<typeof session>), attributes: { moved: 'yes' } },
      Date.now(),
    );
    expect((await sessions().find(legacy.sessionId))?.attributes).toEqual({ moved: 'yes' });
    const authorizationRow = authorization(legacy.authorizationId, { rotated: true });
    expect(
      await authorizations().commitGrant(authorizationRow, {
        code: `code-${legacy.authorizationId}`,
      }),
    ).toBe(true);
    expect((await authorizations().findById(legacy.authorizationId))?.idToken?.claims).toEqual({
      rotated: true,
    });
    expect(
      await raw().first<Record<string, unknown>>(
        'SELECT oidc_id_token_claims FROM oauth2_authorization WHERE id = ?',
        [legacy.authorizationId],
      ),
    ).toEqual({ oidc_id_token_claims: null });
  });

  test('the database refuses plaintext writes while enabled', async () => {
    const gateway = useContainer().resolve(PostgresGateway);
    const insert = () =>
      sql`INSERT INTO auth_audit_records (id, action, before_metadata, after_metadata)
          VALUES (${crypto.randomUUID()}, 'plaintext', '{"leak":1}', NULL) RETURNING id`;
    for (const call of [
      () => gateway.write(insert()),
      () => gateway.run(insert()),
      () => gateway.query(insert()),
      () => gateway.one(insert()),
    ]) {
      await expect(call()).rejects.toMatchObject({ status: 503 });
    }
    const error = await raw()
      .run(`UPDATE users SET email = 'x@example.com' WHERE id = ?`, [fresh.userId])
      .catch((caught: unknown) => caught);
    expect(String((error as Error).message)).toContain('users.email');
    expect(PLAINTEXT_REJECTED).toBe('IDC01');
  });

  test('no key ever appears in statement text; keys travel as bindings', () => {
    expect(statements.length).toBeGreaterThan(50);
    for (const statement of statements) {
      expect(statement.text).not.toContain(COLUMN_KEY);
      expect(statement.text).not.toContain(BIDX_KEY);
    }
    const bound = statements.flatMap((statement) => statement.params);
    expect(bound).toContain(COLUMN_KEY);
    expect(bound).toContain(BIDX_KEY);
  });

  test('once enabled, missing or different keys fail closed with 503', async () => {
    for (const [settings, message] of [
      [
        { columns: false, columnKey: '', bidxKey: '' },
        'IDENTITY_COLUMN_KEY and IDENTITY_BIDX_KEY are',
      ],
      [{ columns: true, columnKey: COLUMN_KEY, bidxKey: '' }, 'IDENTITY_BIDX_KEY is not set'],
      [
        { columns: true, columnKey: BIDX_KEY, bidxKey: COLUMN_KEY },
        'differs from the keys column encryption was enabled with',
      ],
    ] as const) {
      configure(settings);
      const failure = await encryption()
        .cipher()
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ColumnEncryptionUnavailable);
      expect((failure as IdentityError).status).toBe(503);
      expect((failure as Error).message).toContain(message);
      expect((failure as Error).message).not.toContain(COLUMN_KEY);
      await expect(directory().findUser(fresh.userId)).rejects.toMatchObject({ status: 503 });
      await expect(sessions().find(fresh.sessionId)).rejects.toMatchObject({ status: 503 });
    }
    // The switch only opts in; the latch keeps encryption on with the keys alone.
    configure({ columns: false, columnKey: COLUMN_KEY, bidxKey: BIDX_KEY });
    expect((await encryption().cipher()).enabled).toBe(true);
    expect((await directory().findUser(fresh.userId))?.email).toBe(fresh.email);
  });

  test('a missing state row fails closed', async () => {
    await raw().run('DELETE FROM identity_column_encryption');
    encryption().reset();
    await expect(encryption().cipher()).rejects.toThrow('has no state row');
    await raw().run(
      `INSERT INTO identity_column_encryption (enabled, enabled_at, column_key_check, bidx_key_check)
       VALUES (true, now(), ?, ?)`,
      [keyCheck(COLUMN_KEY), keyCheck(BIDX_KEY)],
    );
    encryption().reset();
    expect((await encryption().cipher()).enabled).toBe(true);
  });
});

describe('column cipher statements', () => {
  test('plaintext statements bind values and call no pgcrypto function', () => {
    const plain = ColumnCipher.plaintext;
    expect(plain.read('email', 'email')).toEqual(Sql.raw('email AS email'));
    expect(plain.plain('a', { json: true })).toEqual(new Sql('?::text::jsonb', ['a']));
    expect(plain.plain(null).text).toBe('NULL');
    expect(plain.encrypt('a').text).toBe('NULL');
    expect(plain.blindIndex('a').text).toBe('NULL');
    expect(plain.matches('email', 'email_bidx', 'a')).toEqual(new Sql('email = ?', ['a']));
  });

  test('enabled statements bind the keys', () => {
    const cipher = new ColumnCipher({ column: 'ck', bidx: 'bk' });
    expect(cipher.plain('a').text).toBe('NULL');
    expect(cipher.encrypt(null).text).toBe('NULL');
    expect(cipher.blindIndex(null).text).toBe('NULL');
    expect(cipher.encrypt('a').params).toEqual(['a', 'ck']);
    expect(cipher.blindIndex('a').params).toEqual(['a', 'bk']);
    expect(cipher.matches('email', 'email_bidx', 'a', 'A').params).toEqual(['a', 'bk', 'A']);
    expect(cipher.read('u.email', 'email', { enc: 'u.email_enc' }).text).toBe(
      'coalesce(pgp_sym_decrypt(u.email_enc, ?::text), u.email) AS email',
    );
  });

  test('enabling fails closed on an engine without pgcrypto', async () => {
    const settings = loadIdentitySettings({});
    const gateway = {
      one: async () => ({ enabled: false, column_key_check: null, bidx_key_check: null }),
      run: async () => {
        throw new Error('could not open extension control file');
      },
    } as unknown as PostgresGateway;
    const previous = IdentityModule.settings();
    IdentityModule.configure({ ...settings, encryption: enabledSettings });
    try {
      await expect(new ColumnEncryption(gateway).cipher()).rejects.toThrow(
        'needs the pgcrypto extension',
      );
    } finally {
      IdentityModule.configure(previous);
    }
  });
});
