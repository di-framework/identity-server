import { beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { AccountService } from '../src/account/application/account-service.ts';
import {
  CHALLENGE_TTL_MS,
  PasswordlessService,
} from '../src/account/application/passwordless-service.ts';
import type { DirectoryRepository } from '../src/directory/domain/directory-repository.ts';
import { SESSION_IDLE_MS, SessionService } from '../src/sessions/application/session-service.ts';
import { manualClock } from '../src/shared/domain/clock.ts';
import { DIRECTORY } from '../src/shared/domain/tokens.ts';
import { Hashing } from '../src/shared/infrastructure/crypto/hashing.ts';
import { PasswordHasher } from '../src/shared/infrastructure/crypto/passwords.ts';
import { loadIdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import { useTestDatabase } from './support/database.ts';
import { type RecordingMailSender, useRecordingMail } from './support/mail.ts';

let database: SqlDatabase;
let mail: RecordingMailSender;
const passwords = new PasswordHasher();
const directory = () => useContainer().resolve<DirectoryRepository>(DIRECTORY);

beforeAll(async () => {
  database = await useTestDatabase();
  mail = useRecordingMail();
});

async function person(
  status: string,
  options: { password?: string | null; email?: string | null; verified?: boolean } = {},
) {
  const tag = Hashing.token(6)
    .toLowerCase()
    .replaceAll(/[^a-z0-9]/g, 'x');
  const id = crypto.randomUUID();
  const email = options.email === undefined ? `${tag}@example.com` : options.email;
  await directory().insertAccount({
    id,
    login: `User-${tag}`,
    email,
    displayName: `User ${tag}`,
    passwordHash:
      options.password === undefined
        ? await passwords.hash('correct-horse-1')
        : options.password && (await passwords.hash(options.password)),
    emailVerified: options.verified ?? false,
    systemRole: 'user',
    status,
  });
  return { id, login: `User-${tag}`, email: email ?? '' };
}

async function audits(action: string, target: string) {
  return database.query<{ actor_client_id: string | null }>(
    `SELECT actor_client_id FROM auth_audit_records WHERE action = ? AND target = ?`,
    [action, target],
  );
}

describe('sessions', () => {
  test('start, resolve, idle expiry, sign-in rotation, attributes, and logout', async () => {
    const clock = manualClock(Date.UTC(2026, 0, 1));
    const sessions = useContainer().construct(SessionService, { 1: clock });
    const started = await sessions.start();
    expect(started.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(started.session).toMatchObject({
      userId: null,
      lastAuthenticatedAt: null,
      attributes: {},
    });
    expect(started.session.id).toBe(Hashing.sha256Hex(started.token));
    const stored = await database.first<{ id: string }>(
      `SELECT id FROM browser_sessions WHERE id = ?`,
      [started.session.id],
    );
    expect(stored?.id).not.toBe(started.token);

    expect(await sessions.resolve(undefined)).toBeUndefined();
    expect(await sessions.resolve('unknown')).toBeUndefined();
    clock.advance(SESSION_IDLE_MS - 1);
    const touched = await sessions.resolve(started.token);
    expect(touched?.session.expiresAt).toBe(clock.now() + SESSION_IDLE_MS);

    const user = await person('active');
    const kept = await sessions.signIn(started, user.id, false);
    expect(kept.token).toBe(started.token);
    expect(kept.session).toMatchObject({ userId: user.id, lastAuthenticatedAt: clock.now() });
    const rotated = await sessions.signIn(kept, user.id, true);
    expect(rotated.token).not.toBe(kept.token);
    expect(rotated.session.csrf).not.toBe(kept.session.csrf);
    expect(await sessions.resolve(kept.token)).toBeUndefined();

    const withAttribute = await sessions.setAttribute(rotated, 'k', 'v');
    expect((await sessions.resolve(withAttribute.token))?.session.attributes).toEqual({ k: 'v' });
    const cleared = await sessions.setAttribute(withAttribute, 'k', null);
    expect((await sessions.resolve(cleared.token))?.session.attributes).toEqual({});

    expect(sessions.csrfMatches(cleared, cleared.session.csrf)).toBe(true);
    expect(sessions.csrfMatches(cleared, 'wrong')).toBe(false);
    expect(sessions.csrfMatches(cleared, null)).toBe(false);

    await sessions.destroy(cleared);
    expect(await sessions.resolve(cleared.token)).toBeUndefined();

    const idle = await sessions.start();
    clock.advance(SESSION_IDLE_MS);
    expect(await sessions.resolve(idle.token)).toBeUndefined();
    const stale = await sessions.start();
    clock.advance(SESSION_IDLE_MS + 1);
    expect(await sessions.purgeExpired()).toBeGreaterThanOrEqual(1);
    expect(await sessions.resolve(stale.token)).toBeUndefined();
  });
});

describe('form login and password', () => {
  test('signs in active users by login or email with an Argon2 hash', async () => {
    const accounts = useContainer().resolve(AccountService);
    const active = await person('active');
    expect((await accounts.signIn(active.login.toUpperCase(), 'correct-horse-1'))?.id).toBe(
      active.id,
    );
    expect((await accounts.signIn(` ${active.email} `, 'correct-horse-1'))?.id).toBe(active.id);
    expect(await accounts.signIn(active.login, 'wrong-password')).toBeUndefined();
    const pending = await person('pending');
    expect(await accounts.signIn(pending.login, 'correct-horse-1')).toBeUndefined();
    const noPassword = await person('active', { password: null });
    expect(await accounts.signIn(noPassword.login, 'anything')).toBeUndefined();
    expect(await accounts.signIn('nobody', 'anything')).toBeUndefined();
  });

  test('password changes need 12 characters, store only for active users, and always audit', async () => {
    const accounts = useContainer().resolve(AccountService);
    const active = await person('active');
    expect(await accounts.setPassword(active.id, 'short-pass1')).toBe('short');
    expect(await audits('account.password_rotated', active.id)).toEqual([]);
    expect(await accounts.setPassword(active.id, 'a-new-password!')).toBe('saved');
    expect((await accounts.signIn(active.login, 'a-new-password!'))?.id).toBe(active.id);
    expect(await audits('account.password_rotated', active.id)).toEqual([
      { actor_client_id: null },
    ]);

    const archived = await person('archived');
    expect(await accounts.setPassword(archived.id, 'a-new-password!')).toBe('saved');
    expect(
      await passwords.verify(
        'correct-horse-1',
        (await directory().findUser(archived.id))?.passwordHash,
      ),
    ).toBe(true);
    expect(await audits('account.password_rotated', archived.id)).toHaveLength(1);

    expect((await accounts.activeUser(active.id))?.id).toBe(active.id);
    expect(await accounts.activeUser(archived.id)).toBeUndefined();
    expect(await accounts.activeUser(null)).toBeUndefined();
    const lookup = await directory().findActiveByLoginOrEmail(active.email);
    expect(lookup?.id).toBe(active.id);
    expect((await directory().findUserByEmail(archived.email.toUpperCase()))?.id).toBe(archived.id);
  });
});

describe('passwordless', () => {
  function service(clock = manualClock(Date.now())) {
    const settings = loadIdentitySettings({
      ISSUER_URL: 'https://auth.example',
      AUTH_PUBLIC_ORIGIN: 'https://public.example/',
    });
    return {
      clock,
      passwordless: useContainer().construct(PasswordlessService, { 4: settings, 5: clock }),
    };
  }

  test('mails pending accounts an activation link and active accounts a sign-in link', async () => {
    const { passwordless } = service();
    const pending = await person('pending');
    const active = await person('active');
    await passwordless.requestSignIn(pending.email.toUpperCase());
    await passwordless.requestSignIn(active.email);
    const [activation] = mail.to(pending.email);
    expect(activation).toEqual({
      to: pending.email,
      subject: 'Your GSIO sign-in link',
      text: expect.stringMatching(
        /^Open this link to continue to GSIO:\nhttps:\/\/public\.example\/passwordless\/confirm\?token=[A-Za-z0-9_-]{43}\n\nThis link expires in 15 minutes\.$/,
      ),
    });
    const purposes = await database.query<{ purpose: string; email: string }>(
      `SELECT purpose, email FROM email_challenges WHERE email IN (?, ?) ORDER BY purpose`,
      [pending.email, active.email],
    );
    expect(purposes).toEqual([
      { purpose: 'activation', email: pending.email },
      { purpose: 'sign_in', email: active.email },
    ]);
    const token = mail.lastToken(active.email) ?? '';
    const stored = await database.first<{ token_hash: string }>(
      `SELECT token_hash FROM email_challenges WHERE email = ?`,
      [active.email],
    );
    expect(stored?.token_hash).toBe(Hashing.sha256Hex(token));
  });

  test('unknown and archived addresses get nothing, and one challenge per minute is sent', async () => {
    const { passwordless, clock } = service();
    const archived = await person('archived');
    await passwordless.requestSignIn(archived.email);
    await passwordless.requestSignIn('nobody@example.com');
    expect(mail.to(archived.email)).toEqual([]);

    const active = await person('active');
    await passwordless.requestSignIn(active.email);
    await passwordless.requestSignIn(active.email);
    expect(mail.to(active.email)).toHaveLength(1);
    await (await passwordless.invite((await directory().findUser(active.id)) as never))();
    expect(mail.to(active.email)).toHaveLength(2);
    clock.advance(61_000);
    await passwordless.requestSignIn(active.email);
    expect(mail.to(active.email)).toHaveLength(3);

    const noEmail = await person('pending', { email: null });
    await (await passwordless.invite((await directory().findUser(noEmail.id)) as never))();
    expect(
      await database.query(`SELECT 1 FROM email_challenges WHERE user_id = ?`, [noEmail.id]),
    ).toEqual([]);
  });

  test('concurrent requests for one email and purpose issue a single challenge', async () => {
    const { passwordless } = service();
    const active = await person('active');
    await Promise.all(Array.from({ length: 8 }, () => passwordless.requestSignIn(active.email)));
    expect(mail.to(active.email)).toHaveLength(1);
    expect(
      await database.query(`SELECT 1 FROM email_challenges WHERE email = ?`, [active.email]),
    ).toHaveLength(1);
  });

  test('a delivery failure consumes the challenge and audits passwordless.delivery_failed', async () => {
    const { passwordless } = service();
    const active = await person('active');
    mail.failNext = 1;
    await passwordless.requestSignIn(active.email);
    const row = await database.first<{ consumed_at: unknown }>(
      `SELECT consumed_at FROM email_challenges WHERE email = ?`,
      [active.email],
    );
    expect(row?.consumed_at).not.toBeNull();
    expect(await audits('passwordless.delivery_failed', active.id)).toEqual([
      { actor_client_id: null },
    ]);
  });

  test('consumption is single-use, time-boxed, and activates and verifies the account', async () => {
    const { passwordless, clock } = service();
    const pending = await person('pending');
    await passwordless.requestSignIn(pending.email);
    const token = mail.lastToken(pending.email) ?? '';

    expect(await passwordless.consume('short')).toBeUndefined();
    expect(await passwordless.consume(Hashing.token())).toBeUndefined();
    const [first, second] = await Promise.all([
      passwordless.consume(token),
      passwordless.consume(token),
    ]);
    const consumed = first ?? second;
    expect([first, second].filter(Boolean)).toHaveLength(1);
    expect(consumed?.purpose).toBe('activation');
    expect(consumed?.user).toMatchObject({ id: pending.id, status: 'active', emailVerified: true });
    expect(await audits('passwordless.consumed', pending.id)).toEqual([{ actor_client_id: null }]);

    const late = await person('active');
    await passwordless.requestSignIn(late.email);
    clock.advance(CHALLENGE_TTL_MS);
    expect(await passwordless.consume(mail.lastToken(late.email) ?? '')).toBeUndefined();

    const archived = await person('active');
    await passwordless.requestSignIn(archived.email);
    await directory().updateAccount(archived.id, { status: 'archived' });
    expect(await passwordless.consume(mail.lastToken(archived.email) ?? '')).toBeUndefined();

    const orphan = Hashing.token();
    await database.run(
      `INSERT INTO email_challenges (id, user_id, email, token_hash, purpose, expires_at)
       VALUES (?, NULL, 'orphan@example.com', ?, 'sign_in', ?)`,
      [crypto.randomUUID(), Hashing.sha256Hex(orphan), new Date(clock.now() + 60_000)],
    );
    expect(await passwordless.consume(orphan)).toBeUndefined();
  });
});
