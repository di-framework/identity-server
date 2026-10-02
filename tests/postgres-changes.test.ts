import { expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import {
  configuredDatabaseUrl,
  DatabaseSettings,
  loadDatabaseConfig,
  localPostgresUrl,
} from '../src/identity/shared/infrastructure/database-config.ts';
import {
  PostgresChanges,
  toPostgresParams,
} from '../src/identity/shared/infrastructure/postgres.ts';

test('maps postgres results and rewrites placeholders', () => {
  expect(PostgresChanges.from(null)).toEqual({});
  expect(PostgresChanges.from(undefined)).toEqual({});
  expect(PostgresChanges.from('x')).toEqual({});
  expect(PostgresChanges.from({ changes: 2 })).toEqual({ changes: 2 });
  expect(PostgresChanges.from({ count: 3n })).toEqual({ changes: 3 });
  expect(PostgresChanges.from({ rowCount: 4 })).toEqual({ changes: 4 });
  expect(PostgresChanges.from({ changes: 1n })).toEqual({ changes: 1 });
  expect(PostgresChanges.from({})).toEqual({});
  expect(toPostgresParams('select 1')).toEqual({ text: 'select 1', params: [] });
  expect(() => toPostgresParams('select ? and ?', ['only'])).toThrow('placeholder count');
});

test('loads the database url from identity config', () => {
  expect(loadDatabaseConfig({}).url).toBe(localPostgresUrl);
  expect(loadDatabaseConfig({ IDENTITY_DATABASE__URL: 'postgres://prefixed/db' }).url).toBe(
    'postgres://prefixed/db',
  );
  expect(
    loadDatabaseConfig({
      DATABASE_URL: 'postgres://direct/db',
      IDENTITY_DATABASE__URL: 'postgres://prefixed/db',
    }).url,
  ).toBe('postgres://direct/db');
  expect(configuredDatabaseUrl()).toBe(useContainer().resolve(DatabaseSettings).url);
  expect(configuredDatabaseUrl({ DATABASE_URL: 'postgres://direct/db' })).toBe(
    'postgres://direct/db',
  );
});
