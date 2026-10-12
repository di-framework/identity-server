import { expect, test } from 'bun:test';
import { cpSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  applyMigrations,
  loadMigrations,
  migrationsDirectory,
} from '@di-framework/identity-migrations';
import { Id, Model } from '@di-framework/repo';
import { PostgresAdapter, toPostgresParams } from '../src/shared/infrastructure/postgres.ts';
import { withThrowawayDatabase } from './support/database.ts';

/**
 * An `organizations` row for exercising `PostgresAdapter`. Production code has no entity mapping
 * of `users`: its PII columns are encrypted once column encryption is enabled, so every user
 * read and write goes through `PostgresDirectoryRepository`.
 */
@Model()
class OrganizationRow {
  @Id()
  id!: string;

  slug!: string;
  name!: string;
}

test('rewrites repo placeholders to postgres bindings', () => {
  expect(toPostgresParams('SELECT * FROM t WHERE id = ? AND binding = ?', ['a', 'b'])).toEqual({
    text: 'SELECT * FROM t WHERE id = $1 AND binding = $2',
    params: ['a', 'b'],
  });
  expect(toPostgresParams('CREATE TABLE t (note text);', [])).toEqual({
    text: 'CREATE TABLE t (note text);',
    params: [],
  });
});

test('discovers the reused Flyway migrations in version order', async () => {
  const migrations = await loadMigrations();
  expect(migrations.map((migration) => [migration.version, migration.description])).toEqual([
    ['1', 'directory'],
    ['2', 'spring authorization server'],
    ['3', 'admin lifecycle'],
    ['4', 'refresh token history'],
    ['5', 'admin idempotency lookup'],
    ['6', 'system roles and archival'],
    ['7', 'identity links'],
    ['8', 'identity link flows'],
    ['9', 'identity unlink confirmations'],
    ['10', 'identity security notifications'],
    ['11', 'browser sessions'],
    ['12', 'normalize jsonb metadata'],
    ['13', 'runtime secrets'],
    ['14', 'varchar hashes'],
    ['15', 'concurrency indexes'],
    ['16', 'runtime secrets to secret'],
    ['17', 'clear session secrets'],
    ['18', 'column encryption'],
  ]);
});

test('applies the reused migrations and reads a row through PostgresAdapter', async () => {
  await withThrowawayDatabase('identity_migrate_test', async (db) => {
    const applied = await applyMigrations(db);
    expect(applied.pending).toEqual([]);
    expect(applied.applied.map((record) => record.version)).toEqual([
      '1',
      '2',
      '3',
      '4',
      '5',
      '6',
      '7',
      '8',
      '9',
      '10',
      '11',
      '12',
      '13',
      '14',
      '15',
      '16',
      '17',
      '18',
    ]);

    const again = await applyMigrations(db);
    expect(again.applied).toEqual([]);
    expect(again.pending).toEqual([]);

    const id = crypto.randomUUID();
    const adapter = new PostgresAdapter<OrganizationRow, string>(db, { table: 'organizations' });
    const organization = new OrganizationRow();
    organization.id = id;
    organization.slug = 'ada';
    organization.name = 'Ada';
    await adapter.save(organization);
    expect((await adapter.findById(id))?.name).toBe('Ada');
    await adapter.transaction(async (tx) => {
      expect((await tx.findById(id))?.slug).toBe('ada');
    });
    expect((await adapter.findAll()).some((row) => row.id === id)).toBe(true);
  });
}, 30_000);

test('V12 unwraps metadata and session attributes stored as JSON string scalars', async () => {
  const earlier = mkdtempSync(join(tmpdir(), 'identity-v11-'));
  const root = join(earlier, 'migrations');
  cpSync(migrationsDirectory, root, { recursive: true });
  for (const name of readdirSync(root)) {
    const version = /^V(\d+)__/.exec(name);
    if (version && Number(version[1]) >= 12) rmSync(join(root, name));
  }
  try {
    await withThrowawayDatabase('identity_v12_test', async (db) => {
      await applyMigrations(db, root);
      const audit = crypto.randomUUID();
      await db.run(
        `INSERT INTO auth_audit_records (id, action, before_metadata, after_metadata)
         VALUES (?, 'test.legacy', to_jsonb(?::text), to_jsonb(?::text))`,
        [audit, '{"role":"owner"}', 'plain text'],
      );
      await db.run(
        `INSERT INTO browser_sessions (id, csrf_token, attributes, expires_at)
         VALUES (?, 'csrf', to_jsonb(?::text), now())`,
        ['a'.repeat(64), '{"saved":"/admin"}'],
      );
      expect((await applyMigrations(db)).applied.map((record) => record.version)).toEqual([
        '12',
        '13',
        '14',
        '15',
        '16',
        '17',
        '18',
      ]);
      expect(
        await db.first<Record<string, unknown>>(
          `SELECT jsonb_typeof(before_metadata) AS before, before_metadata->>'role' AS role,
                  after_metadata #>> '{}' AS after
           FROM auth_audit_records WHERE id = ?`,
          [audit],
        ),
      ).toEqual({ before: 'object', role: 'owner', after: 'plain text' });
      expect(
        await db.first<Record<string, unknown>>(
          `SELECT attributes->>'saved' AS saved FROM browser_sessions`,
        ),
      ).toEqual({
        saved: '/admin',
      });
    });
  } finally {
    rmSync(earlier, { recursive: true, force: true });
  }
}, 30_000);

test('V16 removes runtime secrets from identity_runtime_secret and keeps bootstrap state', async () => {
  const earlier = mkdtempSync(join(tmpdir(), 'identity-v15-'));
  const root = join(earlier, 'migrations');
  cpSync(migrationsDirectory, root, { recursive: true });
  for (const name of readdirSync(root)) {
    const version = /^V(\d+)__/.exec(name);
    if (version && Number(version[1]) >= 16) rmSync(join(root, name));
  }
  try {
    await withThrowawayDatabase('identity_v16_test', async (db) => {
      await applyMigrations(db, root);
      const names = [
        'AUTH_ACTIVE_PRIVATE_JWK',
        'SMTP_PASSWORD',
        // Written by hand under a name no writer in this repository ever used.
        'LEGACY_HAND_SEEDED_KEY',
        'bootstrap_fingerprint',
        'bootstrap_client_fingerprints',
        'bootstrap_lease',
      ];
      for (const name of names) {
        await db.run('INSERT INTO identity_runtime_secret (name, value) VALUES (?, ?)', [
          name,
          'stored',
        ]);
      }
      expect((await applyMigrations(db)).applied.map((record) => record.version)).toEqual([
        '16',
        '17',
        '18',
      ]);
      expect(await db.query('SELECT name FROM identity_runtime_secret ORDER BY name')).toEqual([
        { name: 'bootstrap_client_fingerprints' },
        { name: 'bootstrap_fingerprint' },
        { name: 'bootstrap_lease' },
      ]);
    });
  } finally {
    rmSync(earlier, { recursive: true, force: true });
  }
}, 30_000);

test('V17 removes raw secrets from existing browser session attributes', async () => {
  const earlier = mkdtempSync(join(tmpdir(), 'identity-v16-'));
  const root = join(earlier, 'migrations');
  cpSync(migrationsDirectory, root, { recursive: true });
  for (const name of readdirSync(root)) {
    const version = /^V(\d+)__/.exec(name);
    if (version && Number(version[1]) >= 17) rmSync(join(root, name));
  }
  try {
    await withThrowawayDatabase('identity_v17_test', async (db) => {
      await applyMigrations(db, root);
      const insert = (id: string, attributes: Record<string, string>) =>
        db.run(
          `INSERT INTO browser_sessions (id, csrf_token, attributes, expires_at)
           VALUES (?, 'csrf', ?::text::jsonb, now())`,
          [id, JSON.stringify(attributes)],
        );
      await insert('a'.repeat(64), {
        IDENTITY_CLIENT_SECRET_REVEAL: '{"clientId":"cli_1","secret":"s"}',
        GSIO_IDENTITY_LINK_PENDING_TOKEN: 'raw-link',
        GSIO_IDENTITY_UNLINK_CONFIRMATION_TOKEN: 'raw-unlink',
        SPRING_SECURITY_SAVED_REQUEST: '/admin',
      });
      await insert('b'.repeat(64), { SPRING_SECURITY_SAVED_REQUEST: '/account' });
      // Not objects: left as they are instead of failing the migration.
      await db.run(
        `INSERT INTO browser_sessions (id, csrf_token, attributes, expires_at)
         VALUES (?, 'csrf', '"GSIO_IDENTITY_LINK_PENDING_TOKEN"'::jsonb, now()),
                (?, 'csrf', '["IDENTITY_CLIENT_SECRET_REVEAL"]'::jsonb, now())`,
        ['c'.repeat(64), 'd'.repeat(64)],
      );
      expect((await applyMigrations(db)).applied.map((record) => record.version)).toEqual([
        '17',
        '18',
      ]);
      expect(await db.query('SELECT id, attributes FROM browser_sessions ORDER BY id')).toEqual([
        { id: 'a'.repeat(64), attributes: { SPRING_SECURITY_SAVED_REQUEST: '/admin' } },
        { id: 'b'.repeat(64), attributes: { SPRING_SECURITY_SAVED_REQUEST: '/account' } },
        { id: 'c'.repeat(64), attributes: 'GSIO_IDENTITY_LINK_PENDING_TOKEN' },
        { id: 'd'.repeat(64), attributes: ['IDENTITY_CLIENT_SECRET_REVEAL'] },
      ]);
    });
  } finally {
    rmSync(earlier, { recursive: true, force: true });
  }
}, 30_000);

test('V18 prepares column encryption on a populated database without changing a row', async () => {
  const earlier = mkdtempSync(join(tmpdir(), 'identity-v17-'));
  const root = join(earlier, 'migrations');
  cpSync(migrationsDirectory, root, { recursive: true });
  for (const name of readdirSync(root)) {
    const version = /^V(\d+)__/.exec(name);
    if (version && Number(version[1]) >= 18) rmSync(join(root, name));
  }
  try {
    await withThrowawayDatabase('identity_v18_test', async (db) => {
      await applyMigrations(db, root);
      const user = crypto.randomUUID();
      const seed = [
        [
          `INSERT INTO users (id, login, normalized_login, email, normalized_email, display_name, avatar_url)
           VALUES (?, 'pat', 'pat', 'Pat@Example.com', 'pat@example.com', 'Pat', 'https://a.example/p.png')`,
          [user],
        ],
        [
          `INSERT INTO identity_links (id, user_id, issuer, subject, provider_name, provider_email)
           VALUES (?, ?, 'https://idp.example', 'sub-1', 'acme', 'pat@idp.example')`,
          [crypto.randomUUID(), user],
        ],
        [
          `INSERT INTO email_challenges (id, user_id, email, token_hash, purpose, expires_at)
           VALUES (?, ?, 'Pat@Example.com', ?, 'sign_in', now())`,
          [crypto.randomUUID(), user, 'c'.repeat(64)],
        ],
        [
          `INSERT INTO browser_sessions (id, csrf_token, attributes, expires_at)
           VALUES (?, 'csrf', '{"saved":"/x"}', now())`,
          ['d'.repeat(64)],
        ],
        [
          `INSERT INTO auth_audit_records (id, action, before_metadata, after_metadata)
           VALUES (?, 'seed', '{"a":1}', '{"b":2}')`,
          [crypto.randomUUID()],
        ],
      ] as const;
      for (const [text, params] of seed) await db.run(text, [...params]);
      const snapshot = async () => ({
        users: await db.query(
          'SELECT id::text, email, normalized_email, display_name, avatar_url FROM users',
        ),
        links: await db.query('SELECT subject, provider_email FROM identity_links'),
        challenges: await db.query('SELECT email FROM email_challenges'),
        sessions: await db.query('SELECT attributes FROM browser_sessions'),
        audit: await db.query('SELECT before_metadata, after_metadata FROM auth_audit_records'),
      });
      const before = await snapshot();
      expect((await applyMigrations(db)).applied.map((record) => record.version)).toEqual(['18']);
      expect(await snapshot()).toEqual(before);
      expect(
        await db.first<Record<string, unknown>>(
          `SELECT enabled, (SELECT count(*)::int FROM users WHERE email_enc IS NOT NULL
             OR normalized_email_bidx IS NOT NULL) AS encrypted
           FROM identity_column_encryption`,
        ),
      ).toEqual({ enabled: false, encrypted: 0 });
      expect(
        await db.first<Record<string, unknown>>(
          `SELECT count(*)::int AS n FROM pg_extension WHERE extname = 'pgcrypto'`,
        ),
      ).toEqual({ n: 1 });
      // Disabled, plaintext is written as before, and users_email_key still refuses a duplicate
      // raw address even from a writer that leaves normalized_email unset.
      const insert = (login: string, email: string, normalized: string | null) =>
        db.run(
          `INSERT INTO users (id, login, normalized_login, email, normalized_email, display_name)
           VALUES (?, ?, ?, ?, ?, 'Pat 2')`,
          [crypto.randomUUID(), login, login, email, normalized],
        );
      const duplicate = await insert('pat2', 'Pat@Example.com', null).catch(
        (error: unknown) => error,
      );
      expect(String((duplicate as Error).message)).toContain('users_email_key');
      const normalized = await insert('pat3', 'PAT@example.com', 'pat@example.com').catch(
        (error: unknown) => error,
      );
      expect(String((normalized as Error).message)).toContain('users_normalized_email_key');
      await insert('pat4', 'other@example.com', 'other@example.com');
    });
  } finally {
    rmSync(earlier, { recursive: true, force: true });
  }
}, 30_000);
