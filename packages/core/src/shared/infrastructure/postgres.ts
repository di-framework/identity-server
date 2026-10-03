import { AsyncLocalStorage } from 'node:async_hooks';
import {
  SQL_DATABASE_BRAND,
  type SqlAdapterOptions,
  type SqlDatabase,
  SqlStorageAdapter,
  type StorageAdapter,
} from '@di-framework/repo';
import { SQL } from 'bun';
import { loadDatabaseConfig, localPostgresUrl } from './database-config.ts';

export { localPostgresUrl };

/**
 * Rewrites `@di-framework/repo` `?` placeholders to Postgres `$1` bindings.
 * `exec` sends migration scripts through unchanged.
 */
export function toPostgresParams(
  sql: string,
  params: readonly unknown[] = [],
): { text: string; params: readonly unknown[] } {
  if (params.length === 0) return { text: sql, params };
  let index = 0;
  const text = sql.replaceAll('?', () => `$${++index}`);
  if (index !== params.length) {
    throw new Error(`SQL placeholder count ${index} does not match ${params.length} parameters`);
  }
  return { text, params };
}

/** Maps a Bun Postgres result onto the change count `@di-framework/repo` stores. */
export class PostgresChanges {
  static from(result: unknown): { changes?: number } {
    if (result === null || result === undefined || typeof result !== 'object') return {};
    const record = result as { changes?: unknown; count?: unknown; rowCount?: unknown };
    for (const value of [record.changes, record.count, record.rowCount]) {
      if (typeof value === 'number') return { changes: value };
      if (typeof value === 'bigint') return { changes: Number(value) };
    }
    return {};
  }
}

type Handle = Pick<SQL, 'unsafe'>;

/**
 * Opens a pooled Postgres database as a `SqlDatabase`.
 *
 * Statements outside a transaction take any pooled connection. `transaction(fn)` reserves one
 * connection for `fn` through `SQL.begin`, and every statement issued in that async context,
 * including nested `transaction` calls, runs on it. Row locks (`SELECT … FOR UPDATE`) therefore
 * serialize concurrent requests, the notification worker, and bootstrap. `MigrationRunner`
 * receives the transaction view it is handed, so migrations run on one connection as well.
 */
export async function openPostgresDatabase(
  url: string = loadDatabaseConfig().url,
  options: { max?: number } = {},
): Promise<SqlDatabase> {
  const pool = new SQL({ url, adapter: 'postgres', max: options.max ?? 8 });
  await pool.unsafe('SELECT 1');
  const active = new AsyncLocalStorage<Handle>();
  const view = (fixed?: Handle): SqlDatabase => {
    const handle = (): Handle => fixed ?? active.getStore() ?? pool;
    const database: SqlDatabase & { [SQL_DATABASE_BRAND]: true } = {
      [SQL_DATABASE_BRAND]: true,
      async run(sql, params = []) {
        const bound = toPostgresParams(sql, params);
        return PostgresChanges.from(await handle().unsafe(bound.text, [...bound.params]));
      },
      async query<T>(sql: string, params: unknown[] = []) {
        const bound = toPostgresParams(sql, params);
        return [...(await handle().unsafe(bound.text, [...bound.params]))] as T[];
      },
      async first<T>(sql: string, params: unknown[] = []) {
        return ((await database.query<T>(sql, params))[0] ?? null) as T | null;
      },
      async exec(sql) {
        await handle().unsafe(sql).simple();
      },
      async transaction<T>(fn: (db: SqlDatabase) => Promise<T>): Promise<T> {
        const current = fixed ?? active.getStore();
        if (current) return fn(view(current));
        return (await pool.begin((tx) => active.run(tx, () => fn(view(tx))))) as T;
      },
      close: () => pool.close(),
    };
    return database;
  };
  return view();
}

/**
 * Custom SQL adapter for Postgres. Repositories receive it through `EntityRepository`.
 * Placeholders stay `?`; `openPostgresDatabase` rewrites them.
 */
export class PostgresAdapter<E extends Record<string, any>, ID extends string | number = string>
  extends SqlStorageAdapter<E, ID>
  implements StorageAdapter<E, ID>
{
  constructor(
    private readonly database: SqlDatabase,
    options: SqlAdapterOptions<E>,
  ) {
    super(options);
  }

  protected override allRows(sql: string, args: unknown[] = []) {
    return this.database.query(sql, args);
  }

  protected override firstRow(sql: string, args: unknown[] = []) {
    return this.database.first<Record<string, unknown>>(sql, args);
  }

  protected override run(sql: string, args: unknown[] = []) {
    return this.database.run(sql, args);
  }

  override transaction<T>(fn: (adapter: this) => Promise<T>): Promise<T> {
    return this.database.transaction(async () => fn(this));
  }
}
