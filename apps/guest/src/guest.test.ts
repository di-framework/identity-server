import { beforeEach, expect, test } from 'bun:test';
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getBindingMetadata } from '@di-framework/bindings';
import { text } from '@di-framework/repo/postgres';
import { routeRequest } from '../../server/src/serve.ts';
import { IdentityConfig, IdentityDatabase } from './bindings.ts';
import { openGuestDatabase, sharesTransaction } from './database.ts';
import { readFlywayMigrations } from './flyway.ts';
import {
  applySchema,
  embeddedMigrations,
  ensureSchema,
  migrationStatement,
  resetSchema,
} from './migrations.ts';
import { bindParams } from './pg.ts';
import { handle, resetGuest } from './runtime.ts';
import { loadGuestSettings } from './settings.ts';

const cell = (val: string) => ({ tag: 'text' as const, val });

function stream(rows: readonly unknown[]): AsyncIterable<unknown> {
  return {
    async *[Symbol.asyncIterator]() {
      for (const row of rows) yield row;
    },
  };
}

function table(columns: unknown, rows: readonly unknown[], done: unknown = null): unknown {
  return [columns, stream(rows), done];
}

function guest(options: {
  queryBatch?: (sql: string) => Promise<unknown>;
  query?: (sql: string, params: readonly unknown[]) => Promise<unknown>;
}): IdentityDatabase {
  return new IdentityDatabase({
    queryBatch: options.queryBatch ?? (async () => undefined),
    query: options.query ?? (async () => table(['version'], [])),
  });
}

beforeEach(() => {
  resetSchema();
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

test('batch and rows surface guest failures', async () => {
  const ok = guest({
    queryBatch: async () => ({ tag: 'ok' }),
    query: async () => table(['version'], [[cell('1')]]),
  });
  await expect(ok.batch('SELECT 1')).resolves.toBeUndefined();
  await expect(ok.rows('SELECT version FROM identity_schema_migrations')).resolves.toEqual([
    { version: '1' },
  ]);

  const rejected = guest({
    queryBatch: async () => ({ tag: 'err', val: { code: '42601', message: 'syntax' } }),
    query: async () => {
      throw { message: 'down' };
    },
  });
  await expect(rejected.batch('nope')).rejects.toThrow('PostgreSQL 42601 syntax');
  await expect(rejected.rows('SELECT 1')).rejects.toThrow('PostgreSQL down');
});

test('schema batches run once and skip versions already recorded', async () => {
  const batches: string[] = [];
  const pending = guest({
    queryBatch: async (sql) => {
      batches.push(sql);
    },
  });
  const first = await ensureSchema(pending);
  expect(first).toEqual(embeddedMigrations.map((migration) => migration.version));
  expect(batches[0]).toContain('CREATE TABLE IF NOT EXISTS identity_schema_migrations');
  expect(batches.some((sql) => sql.includes('CREATE TABLE users'))).toBe(true);
  expect(batches.some((sql) => sql.includes("VALUES ('12', 'normalize_jsonb_metadata')"))).toBe(
    true,
  );
  const afterFirst = batches.length;
  expect(await ensureSchema(pending)).toEqual(first);
  expect(batches).toHaveLength(afterFirst);

  resetSchema();
  const applied = guest({
    query: async () =>
      table(
        ['version'],
        embeddedMigrations.map((migration) => [cell(migration.version)]),
      ),
    queryBatch: async (sql) => {
      batches.push(sql);
    },
  });
  batches.length = 0;
  expect(await applySchema(applied)).toEqual([]);
  expect(batches).toHaveLength(1);

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

test('a failed schema apply can be retried', async () => {
  let failed = false;
  const database = guest({
    queryBatch: async () => {
      if (!failed) {
        failed = true;
        throw { message: 'unavailable' };
      }
    },
  });
  await expect(ensureSchema(database)).rejects.toThrow('PostgreSQL unavailable');
  await expect(ensureSchema(database)).resolves.toEqual(
    embeddedMigrations.map((migration) => migration.version),
  );
});

test('uuid and integer parameters go inline so Postgres types them from context', () => {
  const id = '11111111-1111-4111-8111-111111111111';
  expect(bindParams('SELECT ?', [])).toEqual({ text: 'SELECT ?', params: [] });
  expect(bindParams('INSERT INTO t VALUES (?, ?, ?, ?)', ['acme', id, true, 1.5])).toEqual({
    text: `INSERT INTO t VALUES ($1, '${id}', $2, $3)`,
    params: [text('acme'), { tag: 'bool', val: true }, { tag: 'numeric', val: '1.5' }],
  });
  expect(bindParams('SELECT x - ? LIMIT ? OFFSET ?', [-5, 25, 7n])).toEqual({
    text: 'SELECT x - (-5) LIMIT 25 OFFSET 7',
    params: [],
  });
  expect(() => bindParams('SELECT ?', [2 ** 53])).toThrow('not an exact integer');
  expect(() => bindParams('SELECT ?', ['a', 'b'])).toThrow('placeholder count 1 does not match 2');
});

test('the sql adapter binds parameters and rolls a transaction back', async () => {
  const calls: string[] = [];
  const database = guest({
    queryBatch: async (sql) => {
      calls.push(sql);
      if (sql === 'ROLLBACK') throw new Error('rollback failed');
    },
    query: async (sql, params) => {
      calls.push(`${sql} ${JSON.stringify(params)}`);
      if (sql.includes('txid_current'))
        return table(['tx'], [[cell(calls.length < 4 ? '9' : '8')]]);
      if (sql.includes('AS tx')) return table(['tx'], [[cell('9')]]);
      if (sql.includes('RETURNING')) return table(['one'], [[cell('1')]]);
      if (sql.includes('ALREADY')) throw new Error('PostgreSQL already failed');
      throw { code: '23505', message: 'duplicate key value' };
    },
  });
  const sql = openGuestDatabase(database);
  expect(await sql.query<{ tx: string }>('SELECT ? AS tx', ['acme'])).toEqual([{ tx: '9' }]);
  expect((await sql.run('DELETE FROM t WHERE id = ? RETURNING 1', ['a'])).changes).toBe(1);
  await expect(sql.run('INSERT INTO t VALUES (?)', ['a'])).rejects.toMatchObject({ code: '23505' });
  await expect(sql.query('SELECT ALREADY')).rejects.toThrow('PostgreSQL already failed');
  await expect(
    sql.transaction(async (tx) => {
      await tx.query('SELECT txid_current()::text AS tx');
      throw new Error('nope');
    }),
  ).rejects.toThrow('nope');
  expect(calls).toContain('BEGIN');
  expect(calls).toContain('ROLLBACK');
  const same = {
    async transaction(fn: (db: { first: () => Promise<{ tx: string }> }) => Promise<unknown>) {
      return fn({ first: async () => ({ tx: '4' }) });
    },
  };
  const different = {
    async transaction(fn: (db: { first: () => Promise<{ tx: string }> }) => Promise<unknown>) {
      let n = 0;
      return fn({
        first: async () => ({ tx: String(++n) }),
      });
    },
  };
  expect(await sharesTransaction(same as never)).toBe(true);
  expect(await sharesTransaction(different as never)).toBe(false);
  expect(
    await sharesTransaction({
      transaction: async (fn: (db: { first: () => Promise<{ tx: null }> }) => Promise<unknown>) =>
        fn({ first: async () => ({ tx: null }) }),
    } as never),
  ).toBe(false);
});

test('runtime secrets override wasi config', async () => {
  const settings = await loadGuestSettings(
    {
      getAll: () => [
        ['ISSUER_URL', 'http://from-config'],
        ['SMTP_FROM', 'a@b.c'],
      ],
    },
    {
      query: async () => [
        { name: 'ISSUER_URL', value: 'http://from-table' },
        { name: 'SMTP_HOST', value: 'smtp.internal' },
      ],
    } as never,
  );
  expect(settings.issuer).toBe('http://from-table');
  expect(settings.smtp.from).toBe('a@b.c');
  expect(settings.smtp.host).toBe('smtp.internal');
  expect(getBindingMetadata(IdentityConfig)?.options.config?.SMTP_HOST).toBeUndefined();
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

test('a failed schema apply surfaces as not ready', async () => {
  resetGuest();
  const database = guest({
    queryBatch: async () => {
      throw { message: 'closed' };
    },
  });
  const response = await handle(new Request('https://identity.test/ready'), {
    database,
    config: { getAll: () => [] },
    assets: new Map(),
    shell: '<div id="root"></div>',
  });
  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ ok: false, error: 'PostgreSQL closed' });
  const opaque = await handle(new Request('https://identity.test/ready'), {
    database: {
      batch: async () => {
        throw 'nope';
      },
      rows: async () => [],
    } as unknown as IdentityDatabase,
    config: { getAll: () => [] },
    assets: new Map(),
    shell: '<div id="root"></div>',
  });
  expect(opaque.status).toBe(503);
  expect(await opaque.json()).toEqual({ ok: false, error: 'failed' });
});
