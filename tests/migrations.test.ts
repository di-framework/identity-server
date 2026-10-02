import { expect, test } from 'bun:test';
import { User, UserRepository } from '../src/identity/directory/infrastructure/user-repository.ts';
import {
  applyMigrations,
  loadMigrations,
} from '../src/identity/shared/infrastructure/migrations.ts';
import {
  localPostgresUrl,
  openPostgresDatabase,
  PostgresAdapter,
  toPostgresParams,
} from '../src/identity/shared/infrastructure/postgres.ts';

const migrateTestDatabase = 'identity_migrate_test';

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
  ]);
});

test('applies the reused migrations and reads a user through UserRepository', async () => {
  const admin = await openPostgresDatabase(localPostgresUrl);
  await admin.exec(`DROP DATABASE IF EXISTS ${migrateTestDatabase} WITH (FORCE)`);
  await admin.exec(`CREATE DATABASE ${migrateTestDatabase}`);
  await admin.close?.();

  const db = await openPostgresDatabase(
    localPostgresUrl.replace(/\/identity$/, `/${migrateTestDatabase}`),
  );
  try {
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
  } finally {
    await db.close?.();
    const cleanup = await openPostgresDatabase(localPostgresUrl);
    await cleanup.exec(`DROP DATABASE IF EXISTS ${migrateTestDatabase} WITH (FORCE)`);
    await cleanup.close?.();
  }
}, 30_000);
