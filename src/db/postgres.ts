import {
  createSqlDatabase,
  type SqlAdapterOptions,
  type SqlDatabase,
  type SqlDriver,
  SqlStorageAdapter,
  type StorageAdapter,
} from '@di-framework/repo';
import { type ReservedSQL, SQL } from 'bun';

/** Local `podman compose` database. Matches `compose.yml`. */
export const localPostgresUrl = 'postgres://identity:identity@127.0.0.1:5432/identity';

export function resolvePostgresUrl(env: NodeJS.ProcessEnv = process.env): string {
  return env.DATABASE_URL ?? localPostgresUrl;
}

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

function affected(result: unknown): { changes?: number } {
  if (result === null || result === undefined || typeof result !== 'object') return {};
  const record = result as { changes?: unknown; count?: unknown; rowCount?: unknown };
  for (const value of [record.changes, record.count, record.rowCount]) {
    if (typeof value === 'number') return { changes: value };
    if (typeof value === 'bigint') return { changes: Number(value) };
  }
  return {};
}

/**
 * Opens one reserved Postgres session as a `SqlDatabase`.
 * `MigrationRunner` brackets each migration in BEGIN/COMMIT on that session.
 */
export async function openPostgresDatabase(
  url: string = resolvePostgresUrl(),
): Promise<SqlDatabase> {
  const pool = new SQL({ url, adapter: 'postgres', max: 1 });
  const reserved: ReservedSQL = await pool.reserve();
  const driver: SqlDriver = {
    async run(sql, params) {
      const bound = toPostgresParams(sql, params);
      return affected(await reserved.unsafe(bound.text, [...bound.params]));
    },
    async query(sql, params) {
      const bound = toPostgresParams(sql, params);
      const rows = await reserved.unsafe(bound.text, [...bound.params]);
      return [...rows] as Record<string, unknown>[];
    },
    async exec(sql) {
      await reserved.unsafe(sql).simple();
    },
    close() {
      reserved.release();
      return pool.close();
    },
  };
  return createSqlDatabase(driver, { beginStatement: 'BEGIN' });
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
