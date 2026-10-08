import type { SqlDatabase } from '@di-framework/repo';
import { postgresError, readRows } from '@di-framework/repo/postgres';
import type { IdentityDatabase } from './bindings.ts';
import { bindParams } from './pg.ts';

/**
 * `SqlDatabase` over the wasmCloud Postgres binding, in autocommit.
 *
 * `wasmcloud:postgres@0.2.0` has no connection or transaction handle: each `query` and
 * `query-batch` call may run on any pooled connection of the host, so a `BEGIN` sent in one call
 * does not cover the next. The guest therefore never opens a transaction. Every statement
 * commits on its own, `transaction(fn)` runs `fn` on this same handle, and `FOR UPDATE` and
 * advisory locks last only for their statement. The repositories keep their invariants with
 * single statements (conditional `UPDATE … RETURNING`, data-modifying CTEs), which the Bun
 * server also runs, inside its real transactions. A multi-statement `exec` script still runs as
 * one `query-batch`, which Postgres executes as one implicit transaction on one connection.
 */
export function openGuestDatabase(database: IdentityDatabase): SqlDatabase {
  const handle: SqlDatabase = {
    async run(sql, params = []) {
      const rows = await statements(database, sql, params);
      return { changes: rows.length };
    },
    async query<T>(sql: string, params: unknown[] = []) {
      return (await statements(database, sql, params)) as T[];
    },
    async first<T>(sql: string, params: unknown[] = []) {
      return ((await statements(database, sql, params))[0] ?? null) as T | null;
    },
    async exec(sql) {
      await database.batch(sql);
    },
    transaction: (fn) => fn(handle),
  };
  return handle;
}

async function statements(
  database: IdentityDatabase,
  sql: string,
  params: unknown[] = [],
): Promise<Record<string, unknown>[]> {
  const bound = bindParams(sql, params);
  try {
    return await readRows(await database.query(bound.text, bound.params));
  } catch (error) {
    throw coded(error);
  }
}

function coded(error: unknown): Error {
  const wrapped =
    error instanceof Error && error.message.startsWith('PostgreSQL') ? error : postgresError(error);
  const code = /PostgreSQL (\d{5})/.exec(wrapped.message)?.[1];
  if (code) (wrapped as { code?: string }).code = code;
  return wrapped;
}
