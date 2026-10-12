import type { SqlDatabase } from '@di-framework/repo';
import type { EmbeddedMigration } from './flyway.ts';
import embeddedMigrations from './migrations.json';

const HISTORY = `CREATE TABLE IF NOT EXISTS identity_schema_migrations (
  version text PRIMARY KEY,
  description text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
)`;

let schema: Promise<string[]> | undefined;

/**
 * Apply each shipped Flyway file once, in its own transaction together with the row that records
 * its version, so a failed migration leaves neither behind.
 */
export function ensureSchema(database: SqlDatabase): Promise<string[]> {
  schema ??= applySchema(database).catch((error: unknown) => {
    schema = undefined;
    throw error;
  });
  return schema;
}

export { embeddedMigrations };

export function resetSchema(): void {
  schema = undefined;
}

/**
 * `migrations` defaults to every shipped file; the cutover importer passes the files up to the
 * source database's version (deploy/cutover/import-core.ts), so the history reads as if the
 * guest had applied them.
 */
export async function applySchema(
  database: SqlDatabase,
  migrations: readonly EmbeddedMigration[] = embeddedMigrations,
): Promise<string[]> {
  await database.exec(HISTORY);
  const existing = await database.query<{ version: unknown }>(
    'SELECT version FROM identity_schema_migrations',
  );
  const applied = new Set(existing.map((row) => String(row.version)));
  const ran: string[] = [];
  for (const migration of migrations) {
    if (applied.has(migration.version)) continue;
    await database.transaction((tx) => tx.exec(migrationStatement(migration)));
    ran.push(migration.version);
  }
  return ran;
}

export function migrationStatement(migration: EmbeddedMigration): string {
  if (!/^[1-9][0-9]*$/.test(migration.version)) throw new Error('invalid migration version');
  if (!/^[a-z0-9_]+$/.test(migration.description)) {
    throw new Error('invalid migration description');
  }
  const script = migration.sql.trim().replace(/;+\s*$/, '');
  return `${script};\nINSERT INTO identity_schema_migrations (version, description) VALUES ('${migration.version}', '${migration.description}');`;
}
