import { createSqlDatabase, type SqlDatabase } from '@di-framework/repo';
import { toPostgresParams } from '../../../packages/core/src/shared/infrastructure/postgres.ts';
import type { IdentityDatabase } from './bindings.ts';
import { pgValue, postgresError, readRows } from './pg.ts';

/**
 * `SqlDatabase` over the wasmCloud Postgres binding. `createSqlDatabase` serializes statements
 * and brackets `transaction` with `BEGIN` / `COMMIT`. That is one transaction only when the
 * provider runs those calls on one connection.
 */
export function openGuestDatabase(database: IdentityDatabase): SqlDatabase {
  return createSqlDatabase(
    {
      async run(sql, params) {
        const rows = await statements(database, sql, params);
        return { changes: rows.length };
      },
      query(sql, params) {
        return statements(database, sql, params);
      },
      async exec(sql) {
        await database.batch(sql);
      },
    },
    { beginStatement: 'BEGIN' },
  );
}

/** True when two reads inside one transaction observe the same `txid_current()`. */
export async function sharesTransaction(database: SqlDatabase): Promise<boolean> {
  let first = '';
  let second = '';
  await database.transaction(async (tx) => {
    first = await txid(tx);
    second = await txid(tx);
  });
  return first !== '' && first === second;
}

async function txid(database: SqlDatabase): Promise<string> {
  const row = await database.first<{ tx: unknown }>('SELECT txid_current()::text AS tx');
  return row?.tx == null ? '' : String(row.tx);
}

async function statements(
  database: IdentityDatabase,
  sql: string,
  params: unknown[] = [],
): Promise<Record<string, unknown>[]> {
  const bound = toPostgresParams(sql, params);
  try {
    return await readRows(await database.query(bound.text, bound.params.map(pgValue)));
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
