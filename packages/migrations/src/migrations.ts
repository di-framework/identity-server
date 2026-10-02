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
