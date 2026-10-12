import { dirname, resolve } from 'node:path';
import {
  discoverManifestMigrations,
  type MigrationDefinition,
  type MigrationExecutionResult,
  MigrationRunner,
  type SqlDatabase,
} from '@di-framework/repo';

/**
 * Flyway SQL reused from the auth server.
 * Discovery matches the repo CLI: `discoverManifestMigrations` over `./migrations`.
 */
export const migrationsDirectory = resolve(import.meta.dir, '../migrations');

export function loadMigrations(directory = migrationsDirectory): Promise<MigrationDefinition[]> {
  return discoverManifestMigrations({
    directory,
    cwd: dirname(directory),
    binding: 'default',
  });
}

export async function applyMigrations(
  db: SqlDatabase,
  directory = migrationsDirectory,
): Promise<MigrationExecutionResult> {
  const migrations = await loadMigrations(directory);
  const runner = new MigrationRunner({ db, migrations });
  return runner.execute();
}

/** Tables the migration runner keeps for itself; the service role may only read them. */
const RUNNER_TABLES = ['_migrations', '_migrations_lock'];

/**
 * Role separation for a Postgres deployment: `owner` (the migration role, which owns every table,
 * trigger and function) grants the service role on `service` exactly what the service needs:
 * USAGE on the schema, SELECT/INSERT/UPDATE/DELETE on the tables (read-only on the runner's own
 * tables), USAGE/SELECT on sequences and EXECUTE on functions. No TRUNCATE, REFERENCES or
 * TRIGGER, and no ownership, so the service role cannot disable, drop or replace the column
 * encryption triggers. Refuses a service role that is the owner, a superuser, or owns any table.
 * Returns the service role name.
 */
export async function grantServiceRole(
  owner: SqlDatabase,
  service: SqlDatabase,
  schema = 'public',
): Promise<string> {
  const ownerRole = await owner.first<{ role: string }>('SELECT current_user AS role');
  const role = await service.first<{
    role: string;
    quoted: string;
    superuser: boolean;
    owned: number;
  }>(
    `SELECT current_user AS role, quote_ident(current_user) AS quoted,
            (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser,
            (SELECT count(*)::int FROM pg_tables WHERE schemaname = ? AND tableowner = current_user)
              AS owned`,
    [schema],
  );
  if (!ownerRole || !role) throw new Error('cannot read the database roles');
  if (role.role === ownerRole.role) {
    throw new Error('MIGRATION_DATABASE_URL and DATABASE_URL must use different roles');
  }
  if (role.superuser) {
    throw new Error(
      'the DATABASE_URL role must not be a superuser when MIGRATION_DATABASE_URL is set',
    );
  }
  if (role.owned > 0) {
    throw new Error(
      'the DATABASE_URL role owns identity tables; transfer them to the MIGRATION_DATABASE_URL role',
    );
  }
  const target = role.quoted;
  const quotedSchema = (await owner.first<{ q: string }>('SELECT quote_ident(?) AS q', [schema]))
    ?.q;
  const runnerTables = RUNNER_TABLES.map((table) => `${quotedSchema}.${table}`).join(', ');
  await owner.exec(
    [
      `GRANT USAGE ON SCHEMA ${quotedSchema} TO ${target}`,
      `REVOKE ALL ON ALL TABLES IN SCHEMA ${quotedSchema} FROM ${target}`,
      `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${quotedSchema} TO ${target}`,
      `REVOKE INSERT, UPDATE, DELETE ON ${runnerTables} FROM ${target}`,
      `GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${quotedSchema} TO ${target}`,
      `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ${quotedSchema} TO ${target}`,
    ].join(';\n'),
  );
  return role.role;
}
