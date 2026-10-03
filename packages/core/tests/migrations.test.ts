import { expect, test } from 'bun:test';
import { cpSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  applyMigrations,
  loadMigrations,
  migrationsDirectory,
} from '@di-framework/identity-migrations';
import { User, UserRepository } from '../src/directory/infrastructure/user-repository.ts';
import { PostgresAdapter, toPostgresParams } from '../src/shared/infrastructure/postgres.ts';
import { withThrowawayDatabase } from './support/database.ts';

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
  ]);
});

test('applies the reused migrations and reads a user through UserRepository', async () => {
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
    ]);

    const again = await applyMigrations(db);
    expect(again.applied).toEqual([]);
    expect(again.pending).toEqual([]);

    const users = new UserRepository(db);
    const id = crypto.randomUUID();
    const user = new User();
    user.id = id;
    user.login = 'ada';
    user.normalized_login = 'ada';
    user.email = 'ada@example.com';
    user.normalized_email = 'ada@example.com';
    user.password_hash = null;
    user.display_name = 'Ada';
    user.avatar_url = null;
    user.email_verified = true;
    user.status = 'active';
    await users.save(user);
    const found = await users.findById(id);
    expect(found?.login).toBe('ada');
    expect(found?.display_name).toBe('Ada');
    expect(found?.email_verified).toBe(true);
    expect(found?.status).toBe('active');

    const adapter = new PostgresAdapter<User, string>(db, { table: 'users' });
    await adapter.transaction(async (tx) => {
      expect((await tx.findById(id))?.login).toBe('ada');
    });
    expect((await adapter.findAll()).some((user) => user.id === id)).toBe(true);
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
