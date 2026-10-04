import type { IdentityDatabase } from './bindings.ts';
import type { EmbeddedMigration } from './flyway.ts';
import embeddedMigrations from './migrations.json';

const HISTORY = `CREATE TABLE IF NOT EXISTS identity_schema_migrations (
  version text PRIMARY KEY,
  description text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
)`;

let schema: Promise<string[]> | undefined;

/** Apply each shipped Flyway file once, as one batch, recording the version in the same batch. */
export function ensureSchema(database: IdentityDatabase): Promise<string[]> {
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

export async function applySchema(database: IdentityDatabase): Promise<string[]> {
  await database.batch(HISTORY);
  const existing = await database.rows('SELECT version FROM identity_schema_migrations');
  const applied = new Set(existing.map((row) => String(row.version)));
  const ran: string[] = [];
  for (const migration of embeddedMigrations) {
    if (applied.has(migration.version)) continue;
    await database.batch(migrationStatement(migration));
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
