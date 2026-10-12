import { applyMigrations } from '@di-framework/identity-migrations';
import type { SqlDatabase } from '@di-framework/repo';
import { IdentityModule } from '../../src/composition.ts';
import {
  localPostgresUrl,
  openPostgresDatabase,
} from '../../src/shared/infrastructure/postgres.ts';

/** Shared, migrated database for every Postgres-backed test file in one `bun test` run. */
export const testDatabaseName = 'identity_test';

let shared: Promise<SqlDatabase> | undefined;

export function databaseUrl(name: string): string {
  return localPostgresUrl.replace(/\/identity$/, `/${name}`);
}

/**
 * Creates `identity_test` once per process, applies migrations, and connects the container.
 * Every call reconnects it, so a file that used an isolated database hands the container back.
 */
export async function useTestDatabase(): Promise<SqlDatabase> {
  shared ??=
    process.env.IDENTITY_TEST_DATABASE === 'pglite'
      ? pgliteTestDatabase()
      : (async () => {
          await recreate(testDatabaseName);
          const database = await openPostgresDatabase(databaseUrl(testDatabaseName));
          await applyMigrations(database);
          return database;
        })();
  const database = await shared;
  IdentityModule.connect(database);
  return database;
}

/**
 * Fresh migrated database connected to the container for one test file that needs an empty
 * directory. `release` drops it and reconnects the shared database.
 */
export async function useIsolatedDatabase(
  name: string,
): Promise<{ database: SqlDatabase; release(): Promise<void> }> {
  await recreate(name);
  const database = await openPostgresDatabase(databaseUrl(name));
  await applyMigrations(database);
  IdentityModule.connect(database);
  return {
    database,
    async release() {
      await database.close?.();
      await drop(name);
      await useTestDatabase();
    },
  };
}

/** Runs `fn` against a fresh, unmigrated database that is dropped afterwards. */
export async function withThrowawayDatabase<T>(
  name: string,
  fn: (database: SqlDatabase) => Promise<T>,
): Promise<T> {
  await recreate(name);
  const database = await openPostgresDatabase(databaseUrl(name));
  try {
    return await fn(database);
  } finally {
    await database.close?.();
    await drop(name);
  }
}

async function recreate(name: string): Promise<void> {
  const admin = await openPostgresDatabase(localPostgresUrl, { max: 1 });
  await admin.exec(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.exec(`CREATE DATABASE ${name}`);
  await admin.close?.();
}

async function drop(name: string): Promise<void> {
  const admin = await openPostgresDatabase(localPostgresUrl, { max: 1 });
  await admin.exec(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.close?.();
}

/**
 * `IDENTITY_TEST_DATABASE=pglite`: the shared test database is an in-process PGlite (PostgreSQL
 * 17.5) behind the guest's pglite adapter, with one connection, instead of the Postgres pool.
 * Suites that only use `useTestDatabase` (for example apps/server/tests/authorization-code.test.ts)
 * then run on the engine and adapter the wasmCloud guest uses.
 */
async function pgliteTestDatabase(): Promise<SqlDatabase> {
  const { openTestPglite } = await import('../../../../apps/guest/tests/support/pglite.ts');
  const database = await openTestPglite();
  await applyMigrations(database);
  return database;
}
