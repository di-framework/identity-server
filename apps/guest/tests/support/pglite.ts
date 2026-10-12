import type {
  WasmPgliteConnection,
  WasmPgliteModule,
  WasmPgRow,
  WasmPgValue,
} from '@di-framework/pglite-component';
import { createWasmPgliteDatabase } from '@di-framework/pglite-component';
import type { SqlDatabase } from '@di-framework/repo';
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';

/**
 * A stand-in for the `di-framework:pglite/database@0.2.0` import, backed by `@electric-sql/pglite`
 * (PostgreSQL 17.5, the engine version the provider component bundles) running in this process.
 *
 * It speaks the provider's WIT shapes, so the guest's real `SqlDatabase` adapter
 * (`createWasmPgliteDatabase` from `@di-framework/pglite-component`) runs unchanged on top of it:
 * the adapter's placeholder rewrite, parameter variants, result mapping, mutex, transactions and
 * savepoints are all exercised. Like the provider it allows one open connection per database
 * root, pins `TimeZone=UTC` and `DateStyle=ISO`, and sends text, JSON and timestamp parameters
 * untyped (OID 0) so PostgreSQL infers their types from context. pgcrypto is loaded, as the provider
 * ships it for column encryption (`pgcrypto: false` models a provider build without it); `bytea`
 * travels as the WIT `blob` variant in both directions.
 */

const RAW: Record<number, (value: string) => string> = {};
for (let oid = 1; oid < 10_000; oid++) RAW[oid] = (value) => value;

const INTEGER = new Set([20, 21, 23, 26]);
const REAL = new Set([700, 701]);
const JSON_TYPES = new Set([114, 3802]);

/** Engines by database root. Pass a filesystem `dataDir` to keep one across `reopen`. */
export interface PgliteFixture {
  module: WasmPgliteModule;
  /** Roots passed to `open`, in order. */
  opened: string[];
  /** Drops the in-process engines (the files under `dataDir` stay). */
  shutdown(): Promise<void>;
}

/**
 * `integers`: how the binding lifts WIT `s64` results. componentize-qjs 0.4.4-di.5 lifts them as
 * `bigint` (the default); earlier toolchains lift them as JavaScript numbers, which the adapter
 * also accepts. Tests run both.
 */
export interface PgliteFixtureOptions {
  integers?: 'bigint' | 'number';
  /** Load the pgcrypto extension (default true). */
  pgcrypto?: boolean;
}

export function pgliteFixture(
  dataDir?: (root: string) => string,
  options: PgliteFixtureOptions = {},
): PgliteFixture {
  const integers = options.integers ?? 'bigint';
  const extensions = options.pgcrypto === false ? {} : { pgcrypto };
  const engines = new Map<string, PGlite>();
  const open = new Set<string>();
  const opened: string[] = [];
  const module: WasmPgliteModule = {
    async open(path) {
      const root = path || '/data/pglite';
      opened.push(root);
      if (open.has(root)) {
        // The provider's `open-failed`: another connection already owns this instance.
        return { tag: 'err', val: { tag: 'open-failed', val: `${root} is already open` } };
      }
      let engine = engines.get(root);
      if (!engine) {
        engine = new PGlite({
          ...(dataDir ? { dataDir: dataDir(root) } : {}),
          extensions,
          parsers: RAW,
          serializers: RAW,
        } as never);
        engines.set(root, engine);
      }
      await engine.exec("SET TimeZone = 'UTC'; SET DateStyle = 'ISO'");
      open.add(root);
      return connection(engine, integers, () => open.delete(root));
    },
  };
  return {
    module,
    opened,
    async shutdown() {
      for (const engine of engines.values()) await engine.close();
      engines.clear();
      open.clear();
    },
  };
}

/** A provider error raised inside `guard`, passed through as its WIT variant. */
class ProviderError {
  constructor(
    readonly tag: string,
    readonly val: string,
  ) {}
}

function connection(
  engine: PGlite,
  integers: 'bigint' | 'number',
  release: () => void,
): WasmPgliteConnection {
  let closed = false;
  // The provider tracks the transaction itself and refuses calls the state does not permit
  // (`invalid-transaction-state`) instead of passing them to PostgreSQL, which would only warn.
  let inTransaction = false;
  const requireTransaction = (open: boolean, call: string) => {
    if (inTransaction !== open) {
      throw new ProviderError(
        'invalid-transaction-state',
        `${call} ${open ? 'needs an open transaction' : 'inside an open transaction'}`,
      );
    }
  };
  const integer = (value: bigint) => (integers === 'number' ? Number(value) : value);
  const guard = async <T>(fn: () => Promise<T>) => {
    if (closed) return { tag: 'err' as const, val: { tag: 'closed', val: 'connection closed' } };
    try {
      return { tag: 'ok' as const, val: await fn() };
    } catch (error) {
      if (error instanceof ProviderError) {
        return { tag: 'err' as const, val: { tag: error.tag, val: error.val } };
      }
      const record = error as { code?: string; message?: string };
      return {
        tag: 'err' as const,
        val: {
          tag: 'execution-failed',
          val: { code: record.code ?? 'XX000', message: record.message ?? String(error) },
        },
      };
    }
  };
  const statement = async (sql: string, params: WasmPgValue[]) => {
    for (const param of params) {
      if (param.tag === 'real' && !Number.isFinite(param.val)) {
        throw new ProviderError('invalid-params', 'non-finite floats cannot be sent as parameters');
      }
    }
    const bound = params.map(toParam);
    return engine.query<Record<string, unknown>>(
      sql,
      bound.map((param) => param.value),
      { paramTypes: bound.map((param) => param.oid) },
    );
  };
  const rows = (result: Awaited<ReturnType<typeof statement>>): WasmPgRow[] =>
    result.rows.map((row) =>
      result.fields.map(
        (field) =>
          [field.name, toValue(row[field.name], field.dataTypeID, integer)] as [
            string,
            WasmPgValue,
          ],
      ),
    );
  return {
    exec: (sql) => guard(async () => void (await engine.exec(sql))),
    run: (sql, params) =>
      guard(async () => integer(BigInt((await statement(sql, params)).affectedRows ?? 0))),
    query: (sql, params) => guard(async () => rows(await statement(sql, params))),
    first: (sql, params) => guard(async () => rows(await statement(sql, params))[0]),
    begin: () =>
      guard(async () => {
        requireTransaction(false, 'begin');
        await engine.exec('BEGIN');
        inTransaction = true;
      }),
    commit: () =>
      guard(async () => {
        requireTransaction(true, 'commit');
        inTransaction = false;
        await engine.exec('COMMIT');
      }),
    rollback: () =>
      guard(async () => {
        requireTransaction(true, 'rollback');
        inTransaction = false;
        await engine.exec('ROLLBACK');
      }),
    savepoint: (name) =>
      guard(async () => {
        requireTransaction(true, 'savepoint');
        await engine.exec(`SAVEPOINT ${name}`);
      }),
    releaseSavepoint: (name) =>
      guard(async () => {
        requireTransaction(true, 'release savepoint');
        await engine.exec(`RELEASE SAVEPOINT ${name}`);
      }),
    rollbackToSavepoint: (name) =>
      guard(async () => {
        requireTransaction(true, 'rollback to savepoint');
        await engine.exec(`ROLLBACK TO SAVEPOINT ${name}`);
      }),
    close: () =>
      guard(async () => {
        // The provider rolls back uncommitted work and resets the session on close.
        if (inTransaction) await engine.exec('ROLLBACK');
        inTransaction = false;
        closed = true;
        release();
      }),
  };
}

function toParam(value: WasmPgValue): { value: string | null; oid: number } {
  switch (value.tag) {
    case 'null':
      return { value: null, oid: 0 };
    case 'integer':
      return { value: String(value.val), oid: 20 };
    case 'real':
      return { value: String(value.val), oid: 701 };
    case 'boolean':
      return { value: value.val ? 't' : 'f', oid: 16 };
    case 'blob':
      return { value: `\\x${Buffer.from(Uint8Array.from(value.val)).toString('hex')}`, oid: 17 };
    default:
      return { value: value.val, oid: 0 };
  }
}

function toValue(
  raw: unknown,
  oid: number,
  integer: (value: bigint) => bigint | number,
): WasmPgValue {
  if (raw === null || raw === undefined) return { tag: 'null' };
  if (Array.isArray(raw)) return { tag: 'text', val: arrayLiteral(raw) };
  const text = String(raw);
  if (oid === 16) return { tag: 'boolean', val: text === 't' };
  if (INTEGER.has(oid)) return { tag: 'integer', val: integer(BigInt(text)) };
  if (REAL.has(oid)) return { tag: 'real', val: Number(text) };
  if (oid === 17) return { tag: 'blob', val: Uint8Array.from(Buffer.from(text.slice(2), 'hex')) };
  if (JSON_TYPES.has(oid)) return { tag: 'json', val: text };
  if (oid === 1184) {
    if (text === 'infinity' || text === '-infinity' || text.endsWith(' BC')) {
      return { tag: 'timestamp', val: text };
    }
    return { tag: 'timestamp', val: `${text.replace(' ', 'T').replace(/\+00$/, '')}Z` };
  }
  return { tag: 'text', val: text };
}

function arrayLiteral(values: unknown[]): string {
  const items = values.map((item) => {
    if (item === null) return 'NULL';
    if (Array.isArray(item)) return arrayLiteral(item);
    const text = String(item);
    return /^[^",{}\\\s]+$/.test(text) && text.toUpperCase() !== 'NULL'
      ? text
      : `"${text.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
  });
  return `{${items.join(',')}}`;
}

export const OPEN_TEST_PGLITE = Symbol.for('identity.test.pglite');

/** One in-memory PGlite database behind the real adapter, for suites written against `SqlDatabase`. */
export async function openTestPglite(): Promise<SqlDatabase> {
  const fixture = pgliteFixture();
  // An engine left open at exit ends the process with status 99; pglite-preload.ts closes it.
  (globalThis as Record<symbol, unknown>)[OPEN_TEST_PGLITE] = () => fixture.shutdown();
  return createWasmPgliteDatabase('/data/test', { module: fixture.module });
}
