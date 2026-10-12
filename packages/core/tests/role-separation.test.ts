import { afterAll, beforeAll, expect, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { useContainer } from '@di-framework/core/container';
import { applyMigrations, grantServiceRole } from '@di-framework/identity-migrations';
import type { SqlDatabase } from '@di-framework/repo';
import type { AuditRepository } from '../src/audit/domain/audit-entry.ts';
import { IdentityModule } from '../src/composition.ts';
import { AUDIT } from '../src/shared/domain/tokens.ts';
import { ColumnEncryption } from '../src/shared/infrastructure/column-encryption.ts';
import type { IdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import { localPostgresUrl, openPostgresDatabase } from '../src/shared/infrastructure/postgres.ts';
import { databaseUrl, useTestDatabase } from './support/database.ts';

/**
 * Role separation on Postgres: migrations as the owner, the service as a role with DML and
 * EXECUTE only, which cannot undo the column encryption latch or its triggers.
 */
const NAME = 'identity_roles_test';
const suffix = randomBytes(4).toString('hex');
const SERVICE = `identity_svc_${suffix}`;
const SUPER = `identity_su_${suffix}`;
const PASSWORD = randomBytes(12).toString('hex');
let admin: SqlDatabase;
let owner: SqlDatabase;
let service: SqlDatabase;
let original: IdentitySettings;

const urlAs = (role: string) => databaseUrl(NAME).replace(/\/\/[^@]+@/, `//${role}:${PASSWORD}@`);

async function failure(statement: string): Promise<string> {
  return service.run(statement).then(
    () => 'succeeded',
    (error: unknown) => String((error as Error).message),
  );
}

beforeAll(async () => {
  original = IdentityModule.settings();
  admin = await openPostgresDatabase(localPostgresUrl, { max: 1 });
  await admin.exec(`DROP DATABASE IF EXISTS ${NAME} WITH (FORCE)`);
  await admin.exec(`CREATE DATABASE ${NAME}`);
  await admin.exec(`CREATE ROLE ${SERVICE} LOGIN PASSWORD '${PASSWORD}'`);
  await admin.exec(`CREATE ROLE ${SUPER} LOGIN SUPERUSER PASSWORD '${PASSWORD}'`);
  owner = await openPostgresDatabase(databaseUrl(NAME), { max: 1 });
  await applyMigrations(owner);
  service = await openPostgresDatabase(urlAs(SERVICE), { max: 1 });
});

afterAll(async () => {
  IdentityModule.configure(original);
  await useTestDatabase();
  await service?.close?.();
  await owner?.close?.();
  await admin.exec(`DROP DATABASE IF EXISTS ${NAME} WITH (FORCE)`);
  await admin.exec(`DROP ROLE IF EXISTS ${SERVICE}`);
  await admin.exec(`DROP ROLE IF EXISTS ${SUPER}`);
  await admin.close?.();
});

test('grants refuse a service role that is the owner, a superuser, or owns a table', async () => {
  await expect(grantServiceRole(owner, owner)).rejects.toThrow('must use different roles');
  const superuser = await openPostgresDatabase(urlAs(SUPER), { max: 1 });
  try {
    await expect(grantServiceRole(owner, superuser)).rejects.toThrow('must not be a superuser');
  } finally {
    await superuser.close?.();
  }
  await owner.exec(`GRANT CREATE ON SCHEMA public TO ${SERVICE}`);
  await service.exec('CREATE TABLE stray (id int)');
  await expect(grantServiceRole(owner, service)).rejects.toThrow('owns identity tables');
  await service.exec('DROP TABLE stray');
  await owner.exec(`REVOKE CREATE ON SCHEMA public FROM ${SERVICE}`);
});

test('the service role works with DML only and cannot undo the latch', async () => {
  expect(await grantServiceRole(owner, service)).toBe(SERVICE);
  // Idempotent: a second start grants the same set again.
  expect(await grantServiceRole(owner, service)).toBe(SERVICE);

  // The service opts in as the non-owner role (pgcrypto already exists) and writes ciphertext.
  IdentityModule.connect(service);
  IdentityModule.configure({
    ...original,
    encryption: {
      columns: true,
      columnKey: randomBytes(32).toString('base64'),
      bidxKey: randomBytes(32).toString('base64'),
    },
  });
  expect((await useContainer().resolve(ColumnEncryption).cipher()).enabled).toBe(true);
  await useContainer()
    .resolve<AuditRepository>(AUDIT)
    .append({ action: 'roles.test', actor: null, target: null, correlationId: null });
  expect(
    await owner.first<Record<string, unknown>>(
      `SELECT after_metadata, after_metadata_enc IS NOT NULL AS enc
       FROM auth_audit_records WHERE action = 'roles.test'`,
    ),
  ).toEqual({ after_metadata: null, enc: true });

  for (const [statement, expected] of [
    [
      'ALTER TABLE identity_column_encryption DISABLE TRIGGER identity_column_encryption_guard_row',
      'must be owner',
    ],
    ['ALTER TABLE users DISABLE TRIGGER users_reject_plaintext', 'must be owner'],
    ['DROP TRIGGER users_reject_plaintext ON users', 'must be owner'],
    [
      `CREATE OR REPLACE FUNCTION identity_reject_plaintext() RETURNS trigger
       LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'`,
      'permission denied for schema public',
    ],
    ['TRUNCATE identity_column_encryption', 'permission denied'],
    ['UPDATE identity_column_encryption SET enabled = false', 'cannot be turned off'],
    ['DELETE FROM identity_column_encryption', 'cannot be removed'],
    [`INSERT INTO _migrations (version) VALUES ('999')`, 'permission denied'],
    ['CREATE TABLE stray (id int)', 'permission denied'],
  ] as const) {
    expect([statement, await failure(statement)]).toEqual([
      statement,
      expect.stringContaining(expected),
    ]);
  }
  expect((await service.query('SELECT version FROM _migrations')).length).toBeGreaterThan(0);
});
