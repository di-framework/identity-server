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

/** Creates `identity_test` once per process, applies migrations, and connects the container. */
export function useTestDatabase(): Promise<SqlDatabase> {
  shared ??= (async () => {
    await recreate(testDatabaseName);
    const database = await openPostgresDatabase(databaseUrl(testDatabaseName));
    await applyMigrations(database);
    IdentityModule.connect(database);
    return database;
  })();
  return shared;
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
