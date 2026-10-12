import { afterAll, beforeEach, expect, test } from 'bun:test';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getBindingMetadata } from '@di-framework/bindings';
import type { WasmPgliteConnection } from '@di-framework/pglite-component';
import type { SqlDatabase } from '@di-framework/repo';
import { routeRequest } from '../../server/src/serve.ts';
import { pgliteFixture } from '../tests/support/pglite.ts';
import { IdentityConfig } from './bindings.ts';
import {
  DATABASE_ROOT_ENV,
  DEFAULT_DATABASE_ROOT,
  databaseRoot,
  pgliteDatabase,
} from './database.ts';
import { readFlywayMigrations } from './flyway.ts';
import {
  applySchema,
  embeddedMigrations,
  ensureSchema,
  migrationStatement,
  resetSchema,
} from './migrations.ts';
import { handle, resetGuest } from './runtime.ts';
import {
  loadGuestSettings,
  MissingRuntimeSecretsError,
  REQUIRED_RUNTIME_SECRETS,
  RUNTIME_SECRET_SETTINGS,
} from './settings.ts';

const fixture = pgliteFixture();
let counter = 0;
/** A fresh in-process pglite database behind the guest's real adapter. */
const freshDatabase = () =>
  pgliteDatabase(fixture.module, () => ({
    [DATABASE_ROOT_ENV]: `/data/guest-${++counter}`,
  }))();

/** A `SqlDatabase` whose statements fail, for the error paths. */
function failing(error: unknown, calls: string[] = []): SqlDatabase {
  const fail = async (sql: string) => {
    calls.push(sql);
    throw error;
  };
  return {
    run: fail,
    query: fail,
    first: fail,
    exec: fail,
    transaction: async () => fail('transaction'),
  } as unknown as SqlDatabase;
}

beforeEach(() => {
  resetSchema();
});

afterAll(async () => {
  await fixture.shutdown();
});

test('embedded migrations are the shipped Flyway files in version order', () => {
  const directory = join(import.meta.dir, '../../../packages/migrations/migrations');
  const files = readdirSync(directory)
    .filter((name) => name.endsWith('.sql'))
    .sort((left, right) => Number(/^V(\d+)/.exec(left)?.[1]) - Number(/^V(\d+)/.exec(right)?.[1]));
  expect(embeddedMigrations.map((migration) => migration.version)).toEqual(
    files.map((file) => String(Number(/^V(\d+)/.exec(file)?.[1]))),
  );
  for (const file of files) {
    const match = /^V(\d+)__(.+)\.sql$/.exec(file);
    if (!match || match[1] === undefined || match[2] === undefined) throw new Error(file);
    const found = embeddedMigrations.find(
      (migration) => migration.version === String(Number(match[1])),
    );
    expect(found?.description).toBe(match[2]);
    expect(found?.sql).toBe(readFileSync(join(directory, file), 'utf8'));
  }
  const broken = join(tmpdir(), `identity-flyway-${Date.now()}`);
  mkdirSync(broken, { recursive: true });
  try {
    writeFileSync(join(broken, 'notes.sql'), 'select 1;\n');
    expect(() => readFlywayMigrations(broken)).toThrow('unexpected migration filename notes.sql');
  } finally {
    rmSync(broken, { recursive: true, force: true });
  }
});

test('every shipped migration applies on PGlite (PostgreSQL 17) once, in version order', async () => {
  const database = await freshDatabase();
  const first = await ensureSchema(database);
  expect(first).toEqual(embeddedMigrations.map((migration) => migration.version));
  expect(await ensureSchema(database)).toEqual(first);
  const recorded = await database.query<{ version: string; description: string }>(
    'SELECT version, description FROM identity_schema_migrations ORDER BY version::int',
  );
  expect(recorded.map((row) => [row.version, row.description])).toEqual(
    embeddedMigrations.map((migration) => [migration.version, migration.description]),
  );
  // A second instance on the same files skips everything already recorded.
  resetSchema();
  expect(await applySchema(database)).toEqual([]);
  expect(
    await database.first<{ comment: string }>(
      `SELECT obj_description('identity_runtime_secret'::regclass, 'pg_class') AS comment`,
    ),
  ).toEqual({ comment: expect.stringContaining('Not for secrets') });

  expect(() =>
    migrationStatement({ version: '0', description: 'directory', sql: 'SELECT 1;' }),
  ).toThrow('invalid migration version');
  expect(() => migrationStatement({ version: '1', description: 'Bad', sql: 'SELECT 1;' })).toThrow(
    'invalid migration description',
  );
  expect(
    migrationStatement({ version: '3', description: 'admin_lifecycle', sql: 'SELECT 1;;;\n' }),
  ).toBe(
    "SELECT 1;\nINSERT INTO identity_schema_migrations (version, description) VALUES ('3', 'admin_lifecycle');",
  );
});

test('a failed migration rolls back with its version row and can be retried', async () => {
  const database = await freshDatabase();
  const [head, ...rest] = embeddedMigrations;
  if (!head) throw new Error('no migrations');
  const broken = { ...head, sql: `${head.sql}\nSELECT * FROM missing_table;` };
  embeddedMigrations.splice(0, 1, broken);
  try {
    await expect(ensureSchema(database)).rejects.toMatchObject({ code: '42P01' });
  } finally {
    embeddedMigrations.splice(0, 1, head);
  }
  expect(await database.query('SELECT version FROM identity_schema_migrations')).toEqual([]);
  expect(
    await database.first<Record<string, unknown>>(`SELECT to_regclass('public.users') AS users`),
  ).toEqual({
    users: null,
  });
  expect(await ensureSchema(database)).toEqual([head, ...rest].map((m) => m.version));
});

test('the database root comes from DI_PGLITE_DATA_DIR, and a failed open is retried', async () => {
  expect(databaseRoot({})).toBe(DEFAULT_DATABASE_ROOT);
  expect(databaseRoot({ [DATABASE_ROOT_ENV]: '  ' })).toBe(DEFAULT_DATABASE_ROOT);
  expect(databaseRoot({ [DATABASE_ROOT_ENV]: '/data/identity' })).toBe('/data/identity');

  let attempts = 0;
  const local = pgliteFixture();
  const open = pgliteDatabase(
    {
      open: (path, options) => {
        attempts += 1;
        if (attempts === 1) return { tag: 'err', val: { tag: 'io', val: 'storage not mounted' } };
        return local.module.open(path, options);
      },
    },
    () => ({ [DATABASE_ROOT_ENV]: '/data/retry' }),
  );
  await expect(open()).rejects.toThrow('storage not mounted');
  const database = await open();
  expect(await open()).toBe(database);
  expect(attempts).toBe(2);
  expect(local.opened).toEqual(['/data/retry']);
  await local.shutdown();
});

test('runtime secrets come from the environment and override wasi config', async () => {
  const secrets = {
    ISSUER_URL: 'http://from-secret',
    AUTH_PUBLIC_ORIGIN: 'http://from-secret',
    AUTH_ACTIVE_PRIVATE_JWK: '{"kty":"RSA"}',
    SMTP_HOST: 'smtp.internal',
    DATABASE_URL: 'postgres://not-a-runtime-setting',
  };
  const settings = await loadGuestSettings(
    {
      getAll: () => [
        ['ISSUER_URL', 'http://from-config'],
        ['SMTP_FROM', 'a@b.c'],
      ],
    },
    secrets,
  );
  expect(settings.issuer).toBe('http://from-secret');
  expect(settings.smtp.from).toBe('a@b.c');
  expect(settings.smtp.host).toBe('smtp.internal');
  // Only the listed names are read from the environment.
  expect(settings.database.url).not.toBe(secrets.DATABASE_URL);
  expect(RUNTIME_SECRET_SETTINGS).toContain('AUTH_DIRECTORY_CLIENT_SECRET');
  expect(getBindingMetadata(IdentityConfig)?.options.config?.SMTP_HOST).toBeUndefined();
  expect(getBindingMetadata(IdentityConfig)?.options.secretFrom).toBeUndefined();
});

test('a control Secret without the runtime settings fails closed and names only the keys', async () => {
  const error = await loadGuestSettings(
    { getAll: async () => [['AUTH_PUBLIC_ORIGIN', ' ']] },
    { AUTH_ACTIVE_PRIVATE_JWK: 'private-key-material', DI_CONTROL_TOKEN: 'control-token' },
  ).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(MissingRuntimeSecretsError);
  expect((error as MissingRuntimeSecretsError).missing).toEqual([
    'ISSUER_URL',
    'AUTH_PUBLIC_ORIGIN',
  ]);
  expect(String(error)).not.toContain('private-key-material');
  expect(String(error)).not.toContain('control-token');
  expect(REQUIRED_RUNTIME_SECRETS.every((key) => RUNTIME_SECRET_SETTINGS.includes(key))).toBe(true);
});

test('embedded assets keep their media types', async () => {
  const assets = new Map<string, Uint8Array>([
    ['main.css', new Uint8Array([1])],
    ['main.js', new Uint8Array([2])],
    ['mark.svg', new Uint8Array([3])],
    ['file.bin', new Uint8Array([4])],
  ]);
  const css = await routeRequest(new Request('https://identity.test/assets/main.css'), assets);
  expect(css.headers.get('content-type')).toContain('text/css');
  expect(
    (await routeRequest(new Request('https://identity.test/assets/main.js'), assets)).headers.get(
      'content-type',
    ),
  ).toContain('javascript');
  expect(
    (await routeRequest(new Request('https://identity.test/assets/mark.svg'), assets)).headers.get(
      'content-type',
    ),
  ).toContain('svg');
  expect(
    (await routeRequest(new Request('https://identity.test/assets/file.bin'), assets)).headers.get(
      'content-type',
    ),
  ).toContain('octet-stream');
  expect(
    (await routeRequest(new Request('https://identity.test/assets/missing.css'), assets)).status,
  ).toBe(404);
});

test('a failed database or schema surfaces as not ready', async () => {
  const runtime = (database: () => Promise<SqlDatabase>, env = {}) => ({
    database,
    config: { getAll: () => [] },
    env: () => env,
    assets: new Map(),
    shell: '<div id="root"></div>',
  });
  resetGuest();
  const closed = await handle(
    new Request('https://identity.test/ready'),
    runtime(async () => failing(new Error('PostgreSQL closed'))),
  );
  expect(closed.status).toBe(503);
  expect(await closed.json()).toEqual({ ok: false, error: 'PostgreSQL closed' });
  const opaque = await handle(
    new Request('https://identity.test/ready'),
    runtime(async () => {
      throw 'nope';
    }),
  );
  expect(opaque.status).toBe(503);
  expect(await opaque.json()).toEqual({ ok: false, error: 'failed' });

  const database = await freshDatabase();
  const unconfigured = await handle(
    new Request('https://identity.test/ready'),
    runtime(async () => database, { DI_CONTROL_TOKEN: 'only-the-cli-keys' }),
  );
  expect(unconfigured.status).toBe(503);
  expect(await unconfigured.json()).toEqual({
    ok: false,
    error:
      'runtime settings missing from the identity-control Secret: ISSUER_URL, AUTH_PUBLIC_ORIGIN, AUTH_ACTIVE_PRIVATE_JWK',
  });
  resetGuest();
});

test('the test provider refuses what the real provider refuses', async () => {
  const local = pgliteFixture(undefined, { integers: 'number' });
  try {
    // A successful open returns the connection resource itself, as the binding does.
    const connection = (await local.module.open('/data/strict', undefined)) as WasmPgliteConnection;
    expect(await local.module.open('/data/strict', undefined)).toMatchObject({
      tag: 'err',
      val: { tag: 'open-failed' },
    });
    expect(await connection.commit()).toMatchObject({
      tag: 'err',
      val: { tag: 'invalid-transaction-state' },
    });
    expect(await connection.savepoint('s1')).toMatchObject({
      tag: 'err',
      val: { tag: 'invalid-transaction-state' },
    });
    expect(await connection.begin()).toEqual({ tag: 'ok', val: undefined });
    expect(await connection.begin()).toMatchObject({
      tag: 'err',
      val: { tag: 'invalid-transaction-state' },
    });
    expect(await connection.rollback()).toEqual({ tag: 'ok', val: undefined });
    expect(
      await connection.query('SELECT $1::float8 AS f', [{ tag: 'real', val: Number.NaN }]),
    ).toMatchObject({
      tag: 'err',
      val: { tag: 'invalid-params' },
    });
    expect(await connection.first('SELECT 7::int8 AS n', [])).toEqual({
      tag: 'ok',
      val: [['n', { tag: 'integer', val: 7 }]],
    });
    expect(await connection.close()).toEqual({ tag: 'ok', val: undefined });
    expect(await connection.exec('SELECT 1')).toMatchObject({ tag: 'err', val: { tag: 'closed' } });
  } finally {
    await local.shutdown();
  }
});
