import { afterAll, expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { guestConfig } from '../../apps/guest/scripts/guest-config.ts';
import {
  DATABASE_ROOT_ENV,
  pgliteDatabase,
  type SqlDatabase,
} from '../../apps/guest/src/database.ts';
import { applySchema, embeddedMigrations } from '../../apps/guest/src/migrations.ts';
import { bootstrapFingerprint, handle, resetGuest } from '../../apps/guest/src/runtime.ts';
import { RUNTIME_SECRET_SETTINGS } from '../../apps/guest/src/settings.ts';
import { useContainer } from '../../apps/guest/tests/support/container.ts';
import { pgliteFixture } from '../../apps/guest/tests/support/pglite.ts';
import { Browser } from '../../apps/server/tests/support/browser.ts';
import { BootstrapReconciler } from '../../packages/core/src/bootstrap/application/bootstrap-reconciler.ts';
import { Readiness } from '../../packages/core/src/bootstrap/application/readiness.ts';
import { IdentityModule } from '../../packages/core/src/composition.ts';
import { NotificationWorker } from '../../packages/core/src/notifications/application/security-notifications.ts';
import { PasswordHasher } from '../../packages/core/src/shared/infrastructure/crypto/passwords.ts';
import { loadIdentitySettings } from '../../packages/core/src/shared/infrastructure/identity-settings.ts';
import { withContainer } from '../../packages/core/tests/support/container-lock.ts';
import {
  useTestDatabase,
  withThrowawayDatabase,
} from '../../packages/core/tests/support/database.ts';
import { rsaPrivateJwk } from '../../packages/core/tests/support/keys.ts';
import { readSource, type SourceSession, writeExport } from './export-core.ts';
import { importExport, type LoadedExport, loadExport } from './import-core.ts';
import { rehearseChecks } from './rehearse-core.ts';

/**
 * The cutover end to end on real engines: a Postgres-era source at V13, V14 and V15 (migrated by
 * the guest's own migration code, as the Postgres guest did), exported, imported into PGlite
 * (PostgreSQL 17.5, the provider's engine) behind the guest's adapter, and the current guest
 * booted on the result. The encryption layer and wasmtime are not in this path; import.ts runs
 * the same import through them (docs/guest-http-api.md#authproto-cutover).
 */

const work = mkdtempSync(join(tmpdir(), 'identity-cutover-roundtrip-'));
afterAll(() => rmSync(work, { recursive: true, force: true }));
let dirs = 0;

const USER_PASSWORD = 'legacy-password-1';
const SERVICE_SECRET = 'legacy-service-secret-1';
const SESSION_ID = 'a'.repeat(64);

const values = {
  ISSUER_URL: 'https://identity.legacy.test',
  AUTH_PUBLIC_ORIGIN: 'https://identity.legacy.test',
  AUTH_ACTIVE_PRIVATE_JWK: JSON.stringify(rsaPrivateJwk('legacy-kid')),
  AUTH_ACCESS_REDIRECT_URIS: 'http://localhost:3000/callback',
  AUTH_BOOTSTRAP_OWNER_PASSWORD: 'owner-legacy',
  AUTH_BOOTSTRAP_VIEWER_PASSWORD: 'viewer-legacy',
  AUTH_ACCESS_CLIENT_SECRET: 'access-legacy',
  AUTH_DIRECTORY_CLIENT_SECRET: 'directory-legacy',
  AUTH_PROVISIONER_CLIENT_SECRET: 'provisioner-legacy',
  SMTP_HOST: '127.0.0.1',
  SMTP_PASSWORD: 'smtp-legacy',
};

/**
 * The Postgres-era schema at `version`, as the Postgres guest applied it, with synthetic rows.
 * `runtime` are the setting rows of identity_runtime_secret, `fingerprint` its bootstrap
 * fingerprint row, and `extra` adds rows before the runtime rows.
 */
async function seed(
  source: SqlDatabase,
  version: number,
  runtime: Record<string, string> = values,
  fingerprint = 'stale-fingerprint',
  extra?: (source: SqlDatabase) => Promise<void>,
): Promise<void> {
  await applySchema(
    source,
    embeddedMigrations.filter((migration) => Number(migration.version) <= version),
  );
  const passwords = new PasswordHasher();
  const user = '00000000-0000-4000-8000-000000000001';
  const org = '00000000-0000-4000-8000-000000000002';
  await source.run(
    `INSERT INTO users (id, login, normalized_login, email, normalized_email, password_hash, display_name, email_verified, status, system_role)
     VALUES (?, 'legacy-user', 'legacy-user', 'legacy@example.test', 'legacy@example.test', ?, 'Legacy', true, 'active', 'user')`,
    [user, await passwords.hash(USER_PASSWORD)],
  );
  await source.run(
    `INSERT INTO organizations (id, slug, name) VALUES (?, 'legacy-org', 'Legacy')`,
    [org],
  );
  await source.run(
    `INSERT INTO organization_memberships (organization_id, user_id, role) VALUES (?, ?, 'member')`,
    [org, user],
  );
  await source.run(
    `INSERT INTO oauth2_registered_client (id, client_id, client_secret, client_name, client_authentication_methods, authorization_grant_types, redirect_uris, scopes, client_settings, token_settings)
     VALUES ('00000000-0000-4000-8000-000000000003', 'legacy-service', ?, 'legacy-service', 'client_secret_basic', 'client_credentials', '', 'directory:read',
       '{"requireProofKey":false,"requireAuthorizationConsent":false}',
       '{"authorizationCodeTtlSeconds":60,"accessTokenTtlSeconds":600,"refreshTokenTtlSeconds":2592000,"reuseRefreshTokens":false,"accessTokenFormat":"reference"}')`,
    [await passwords.hash(SERVICE_SECRET)],
  );
  await source.run(`INSERT INTO oauth_client_lifecycle (client_id) VALUES ('legacy-service')`);
  await source.run(
    `INSERT INTO oauth2_authorization_consent (registered_client_id, principal_name, authorities)
     VALUES ('00000000-0000-4000-8000-000000000003', 'legacy-user', 'SCOPE_openid')`,
  );
  // V17 strips a client secret a session kept before identity-server#54.
  await source.run(
    `INSERT INTO browser_sessions (id, user_id, csrf_token, attributes, expires_at)
     VALUES (?, ?, 'csrf', jsonb_build_object('IDENTITY_CLIENT_SECRET_REVEAL', 'old', 'keep', 1),
       now() + interval '1 day')`,
    [SESSION_ID, user],
  );
  await source.run(
    `INSERT INTO auth_audit_records (id, action, target) VALUES ('00000000-0000-4000-8000-000000000004', 'admin.user_created', ?)`,
    [user],
  );
  await extra?.(source);
  const rows: Array<[string, string]> = [
    ...Object.entries(runtime),
    ['bootstrap_fingerprint', fingerprint],
    ['bootstrap_client_fingerprints', '{}'],
    ['bootstrap_lease', '2026-10-01T00:00:00.000Z'],
  ];
  for (const [name, value] of rows) {
    await source.run('INSERT INTO identity_runtime_secret (name, value) VALUES (?, ?)', [
      name,
      value,
    ]);
  }
}

/** psql -XAtq: the single text cell of one statement. */
const sessionOf =
  (source: SqlDatabase): SourceSession =>
  async (sql) => {
    const row = await source.first<Record<string, unknown>>(sql);
    return String(Object.values(row ?? {})[0]);
  };

async function exportAt(
  version: number,
  scenario: {
    runtime?: Record<string, string>;
    fingerprint?: string;
    extra?: (source: SqlDatabase) => Promise<void>;
  } = {},
): Promise<{ dir: string; loaded: LoadedExport }> {
  const runtime = scenario.runtime ?? values;
  const dir = join(work, `${dirs++}-export-v${version}`);
  await withThrowawayDatabase(`identity_cutover_v${version}`, async (source) => {
    await seed(source, version, runtime, scenario.fingerprint, scenario.extra);
    const snapshot = await readSource(sessionOf(source));
    expect(snapshot.version).toBe(version);
    const manifest = await writeExport(dir, snapshot, {
      createdAt: '2026-10-12T00:00:00.000Z',
      backup: async (into) => {
        writeFileSync(join(into, 'directory.dump'), 'dump', { mode: 0o600 });
        return { file: 'directory.dump', sha256: 'test' };
      },
    });
    expect(manifest.runtimeRows).toEqual({
      values: Object.keys(runtime).sort(),
      state: ['bootstrap_client_fingerprints', 'bootstrap_fingerprint'],
      dropped: ['bootstrap_lease'],
    });
    expect(manifest.backup).toEqual({ file: 'directory.dump', sha256: 'test' });
  });
  return { dir, loaded: loadExport(dir) };
}

/** Hand the process-wide container back to the shared Postgres test database. */
async function restoreContainer(): Promise<void> {
  resetGuest();
  IdentityModule.bind();
  const services = (
    useContainer() as unknown as {
      services: Map<unknown, { hasInstance?: boolean; instance?: unknown }>;
    }
  ).services;
  for (const definition of services.values()) {
    definition.hasInstance = false;
    definition.instance = undefined;
  }
  useContainer().register(NotificationWorker);
  await useTestDatabase();
}

test('a V15 export imports into pglite and the current guest boots on it with the old secrets', async () => {
  const { dir, loaded } = await exportAt(15);
  expect(JSON.parse(readFileSync(join(dir, 'values.json'), 'utf8'))).toEqual(values);
  const fixture = pgliteFixture();
  const database = pgliteDatabase(fixture.module, () => ({ [DATABASE_ROOT_ENV]: '/data/import' }));
  try {
    const db = await database();
    const report = await importExport(db, loaded, embeddedMigrations);
    expect(report.sourceVersion).toBe(15);
    expect(report.migrationsApplied).toEqual(
      Array.from({ length: 15 }, (_, index) => String(index + 1)),
    );
    expect(report.rowsV16WouldDelete).toBe(0);
    expect(report.stateRows).toEqual(['bootstrap_client_fingerprints', 'bootstrap_fingerprint']);
    expect(Object.fromEntries(report.tables.map((t) => [t.name, t.imported]))).toMatchObject({
      users: 1,
      organizations: 1,
      organization_memberships: 1,
      oauth2_registered_client: 1,
      oauth_client_lifecycle: 1,
      oauth2_authorization_consent: 1,
      browser_sessions: 1,
      auth_audit_records: 1,
    });
    // The import refuses a database that already has tables.
    await expect(importExport(db, loaded, embeddedMigrations)).rejects.toThrow(
      'the target database already has tables',
    );

    await withContainer(async () => {
      try {
        resetGuest();
        useContainer().register(BootstrapReconciler);
        useContainer().register(Readiness);
        const config = Object.entries({
          ...guestConfig(),
          GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED: 'false',
        });
        const env = {
          ...Object.fromEntries(
            RUNTIME_SECRET_SETTINGS.flatMap((name) =>
              name in values ? [[name, values[name as keyof typeof values]]] : [],
            ),
          ),
          [DATABASE_ROOT_ENV]: '/data/import',
        };
        const fetch = (request: Request) =>
          handle(request, {
            database,
            config: { getAll: () => config },
            env: () => env,
            assets: new Map(),
            shell: '<!doctype html><div id="root"></div>',
          });
        const ready = await fetch(new Request('https://identity.test/ready'));
        expect(ready.status).toBe(200);

        // The guest applied V16..V20 to the imported data.
        const history = await db.first<{ v: number }>(
          'SELECT max(version::int) AS v FROM identity_schema_migrations',
        );
        expect(Number(history?.v)).toBe(Number(embeddedMigrations.at(-1)?.version));
        const names = (
          await db.query<{ name: string }>('SELECT name FROM identity_runtime_secret ORDER BY name')
        ).map((row) => row.name);
        expect(names).toEqual(['bootstrap_client_fingerprints', 'bootstrap_fingerprint']);
        const session = await db.first<{ attributes: unknown }>(
          'SELECT attributes FROM browser_sessions WHERE id = ?',
          [SESSION_ID],
        );
        const attributes =
          typeof session?.attributes === 'string'
            ? JSON.parse(session.attributes)
            : session?.attributes;
        expect(attributes).toEqual({ keep: 1 });

        // Same issuer and signing key; the old user and client credentials work.
        const discovery = (await (
          await fetch(new Request('https://identity.test/.well-known/openid-configuration'))
        ).json()) as { issuer: string };
        expect(discovery.issuer).toBe(values.ISSUER_URL);
        const jwks = (await (
          await fetch(new Request('https://identity.test/oauth2/jwks'))
        ).json()) as {
          keys: Array<{ kid: string }>;
        };
        expect(jwks.keys.map((key) => key.kid)).toContain('legacy-kid');
        const browser = new Browser(fetch);
        expect((await browser.signIn('legacy-user', USER_PASSWORD)).status).toBe(303);
        const page = await browser.send('GET', '/account/identity-links', { json: true });
        expect(((await page.json()) as { signedIn: boolean }).signedIn).toBe(true);
        const introspect = (secret: string) =>
          fetch(
            new Request('https://identity.test/oauth2/introspect', {
              method: 'POST',
              headers: {
                'content-type': 'application/x-www-form-urlencoded',
                authorization: `Basic ${Buffer.from(`legacy-service:${secret}`).toString('base64')}`,
              },
              body: new URLSearchParams({ token: 'x' }),
            }),
          );
        expect((await introspect(SERVICE_SECRET)).status).toBe(200);
        expect((await introspect('wrong')).status).toBe(401);
      } finally {
        await restoreContainer();
      }
    });
  } finally {
    await fixture.shutdown();
  }
}, 120_000);

test('V13 and V14 sources import, and the later migrations apply to the imported rows', async () => {
  for (const version of [13, 14]) {
    const { loaded } = await exportAt(version);
    const fixture = pgliteFixture();
    try {
      const db = await pgliteDatabase(fixture.module, () => ({
        [DATABASE_ROOT_ENV]: `/data/v${version}`,
      }))();
      const report = await importExport(db, loaded, embeddedMigrations);
      expect(report.migrationsApplied).toHaveLength(version);
      expect(await applySchema(db)).toHaveLength(embeddedMigrations.length - version);
      // V14 turned the session id from char(64) into varchar without padding.
      const session = await db.first<{ id: string }>('SELECT id FROM browser_sessions');
      expect(session?.id).toBe(SESSION_ID);
      const user = await db.first<{ n: number }>('SELECT count(*)::int AS n FROM users');
      expect(Number(user?.n)).toBe(1);
    } finally {
      await fixture.shutdown();
    }
  }
}, 120_000);

test('the import refuses exports that do not match, and leaves nothing behind', async () => {
  const { dir, loaded } = await exportAt(15);
  const attempt = async (
    edit: (loaded: LoadedExport) => LoadedExport,
    migrations = embeddedMigrations,
  ) => {
    const fixture = pgliteFixture();
    try {
      const db = await pgliteDatabase(fixture.module, () => ({
        [DATABASE_ROOT_ENV]: '/data/refuse',
      }))();
      const error = await importExport(db, edit(structuredClone(loaded)), migrations).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      const users = await db
        .first<{ n: number }>('SELECT count(*)::int AS n FROM users')
        .catch(() => undefined);
      return { error: String(error), users: users == null ? null : Number(users.n) };
    } finally {
      await fixture.shutdown();
    }
  };
  const withTable = (edit: (table: LoadedExport['manifest']['tables'][number]) => void) => {
    return (copy: LoadedExport) => {
      edit(copy.manifest.tables.find((table) => table.name === 'users') as never);
      return copy;
    };
  };

  const counted = await attempt(
    withTable((table) => {
      table.count = 2;
    }),
  );
  expect(counted).toEqual({
    error: 'Error: users: imported 1 rows, the export has 2',
    users: 0,
  });
  const columns = await attempt(
    withTable((table) => {
      table.columns.push('ghost');
    }),
  );
  expect(columns.error).toContain("users: the export's columns differ from the new schema's");
  const tables = await attempt((copy) => {
    copy.manifest.tables.push({ name: 'ghost', columns: ['id'], count: 0, sha256: '' });
    return copy;
  });
  expect(tables.error).toContain('not in the new schema: ghost; not in the export: none');
  const missing = await attempt((copy) => {
    copy.manifest.tables = copy.manifest.tables.filter((table) => table.name !== 'users');
    return copy;
  });
  expect(missing.error).toContain('not in the new schema: none; not in the export: users');
  const secretInState = await attempt((copy) => {
    copy.state.SMTP_PASSWORD = 'smtp-legacy';
    return copy;
  });
  expect(secretInState).toEqual({
    error: 'Error: identity_runtime_secret would lose 1 rows to V16',
    users: 0,
  });
  const gap = await attempt(
    (copy) => copy,
    embeddedMigrations.filter((migration) => migration.version !== '3'),
  );
  expect(gap.error).toContain('migrating the new database to V15 applied 1, 2, 4');

  // A schema with a sequence or an identity column is refused: the import does not reset them.
  const withV15 = (extra: string) =>
    embeddedMigrations.map((migration) =>
      migration.version === '15' ? { ...migration, sql: `${migration.sql};\n${extra}` } : migration,
    );
  const sequence = await attempt((copy) => copy, withV15('CREATE SEQUENCE extra_seq'));
  expect(sequence.error).toContain(
    'V15 has 1 sequences and 0 identity or generated columns, which this import does not carry; refusing',
  );
  const identity = await attempt(
    (copy) => copy,
    withV15('CREATE TABLE counted (n int GENERATED ALWAYS AS IDENTITY)'),
  );
  expect(identity.error).toContain('identity or generated columns');

  // The directory itself: modes, digests and state rows are checked before any import.
  writeFileSync(join(dir, 'tables', 'users.json'), '[]', { mode: 0o600 });
  expect(() => loadExport(dir)).toThrow('users.json does not match its digest');
  chmodSync(dir, 0o755);
  expect(() => loadExport(dir)).toThrow('must be mode 0700');
  const { dir: other } = await exportAt(15);
  writeFileSync(join(other, 'state.json'), '{"SMTP_HOST":"x"}');
  expect(() => loadExport(other)).toThrow('state.json holds rows that are not bootstrap state');
}, 120_000);

/**
 * authproto's identity_runtime_secret also overrides the eight bootstrap identity settings
 * (organization, owner and viewer), all to non-default values. The Postgres-era guest merged
 * those rows over wasi:config, bootstrapped that organization and those people, and stored the
 * fingerprint of those settings. The cutover must carry them so the new guest computes the same
 * fingerprint and does not reconcile a second organization, owner and viewer from the defaults.
 */
test('non-default bootstrap identity rows are carried and the new guest does not reconcile bootstrap', async () => {
  const identity = {
    AUTH_BOOTSTRAP_ORGANIZATION_SLUG: 'acme',
    AUTH_BOOTSTRAP_ORGANIZATION_NAME: 'Acme Corp',
    AUTH_BOOTSTRAP_OWNER_LOGIN: 'root-admin',
    AUTH_BOOTSTRAP_OWNER_EMAIL: 'root@acme.test',
    AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME: 'Root Admin',
    AUTH_BOOTSTRAP_VIEWER_LOGIN: 'auditor',
    AUTH_BOOTSTRAP_VIEWER_EMAIL: 'auditor@acme.test',
    AUTH_BOOTSTRAP_VIEWER_DISPLAY_NAME: 'Auditor',
  };
  const runtime = { ...values, ...identity };
  const defaults = guestConfig();
  for (const [name, value] of Object.entries(identity)) expect(defaults[name]).not.toBe(value);
  // The old guest's settings: every identity_runtime_secret row over wasi:config. Its
  // bootstrapFingerprint is the current one (unchanged since 23be792).
  const stored = bootstrapFingerprint(loadIdentitySettings({ ...defaults, ...runtime }));
  // Without the eight rows the new guest would see the defaults, and another fingerprint.
  expect(bootstrapFingerprint(loadIdentitySettings({ ...defaults, ...values }))).not.toBe(stored);

  const ids = {
    owner: '00000000-0000-4000-8000-0000000000a1',
    viewer: '00000000-0000-4000-8000-0000000000a2',
    org: '00000000-0000-4000-8000-0000000000a3',
  };
  // The viewer changed their password after bootstrap.
  const VIEWER_CHANGED = 'viewer-changed-it';
  const bootstrapRows = async (source: SqlDatabase) => {
    const passwords = new PasswordHasher();
    const person = `INSERT INTO users (id, login, normalized_login, email, normalized_email, password_hash, display_name, email_verified, status, system_role)
       VALUES (?, ?, ?, ?, ?, ?, ?, true, 'active', ?)`;
    await source.run(person, [
      ids.owner,
      identity.AUTH_BOOTSTRAP_OWNER_LOGIN,
      identity.AUTH_BOOTSTRAP_OWNER_LOGIN,
      identity.AUTH_BOOTSTRAP_OWNER_EMAIL,
      identity.AUTH_BOOTSTRAP_OWNER_EMAIL,
      await passwords.hash(values.AUTH_BOOTSTRAP_OWNER_PASSWORD),
      identity.AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME,
      'platform_admin',
    ]);
    await source.run(person, [
      ids.viewer,
      identity.AUTH_BOOTSTRAP_VIEWER_LOGIN,
      identity.AUTH_BOOTSTRAP_VIEWER_LOGIN,
      identity.AUTH_BOOTSTRAP_VIEWER_EMAIL,
      identity.AUTH_BOOTSTRAP_VIEWER_EMAIL,
      await passwords.hash(VIEWER_CHANGED),
      identity.AUTH_BOOTSTRAP_VIEWER_DISPLAY_NAME,
      'user',
    ]);
    await source.run('INSERT INTO organizations (id, slug, name) VALUES (?, ?, ?)', [
      ids.org,
      identity.AUTH_BOOTSTRAP_ORGANIZATION_SLUG,
      identity.AUTH_BOOTSTRAP_ORGANIZATION_NAME,
    ]);
    for (const [user, role] of [
      [ids.owner, 'owner'],
      [ids.viewer, 'member'],
    ]) {
      await source.run(
        'INSERT INTO organization_memberships (organization_id, user_id, role) VALUES (?, ?, ?)',
        [ids.org, user, role],
      );
    }
    const clients = [
      ['access', values.AUTH_ACCESS_CLIENT_SECRET, 'b1'],
      ['directory', values.AUTH_DIRECTORY_CLIENT_SECRET, 'b2'],
      ['provisioner', values.AUTH_PROVISIONER_CLIENT_SECRET, 'b3'],
    ] as const;
    for (const [client, secret, suffix] of clients) {
      await source.run(
        `INSERT INTO oauth2_registered_client (id, client_id, client_secret, client_name, client_authentication_methods, authorization_grant_types, redirect_uris, scopes, client_settings, token_settings)
         VALUES (?, ?, ?, ?, 'client_secret_basic', 'client_credentials', '', 'directory:read',
           '{"requireProofKey":false,"requireAuthorizationConsent":false}',
           '{"authorizationCodeTtlSeconds":60,"accessTokenTtlSeconds":600,"refreshTokenTtlSeconds":2592000,"reuseRefreshTokens":false,"accessTokenFormat":"reference"}')`,
        [
          `00000000-0000-4000-8000-0000000000${suffix}`,
          client,
          await passwords.hash(secret),
          client,
        ],
      );
      await source.run('INSERT INTO oauth_client_lifecycle (client_id) VALUES (?)', [client]);
    }
  };
  const { dir, loaded } = await exportAt(15, {
    runtime,
    fingerprint: stored,
    extra: bootstrapRows,
  });
  // The export carries the eight rows into values.json, name for name.
  expect(JSON.parse(readFileSync(join(dir, 'values.json'), 'utf8'))).toEqual(runtime);
  expect(loaded.state.bootstrap_fingerprint).toBe(stored);

  const fixture = pgliteFixture();
  const root = '/data/identity-overrides';
  const database = pgliteDatabase(fixture.module, () => ({ [DATABASE_ROOT_ENV]: root }));
  try {
    const db = await database();
    await importExport(db, loaded, embeddedMigrations);
    const count = async (sql: string, params: unknown[] = []) =>
      Number((await db.first<{ n: unknown }>(sql, params as never))?.n);
    const usersBefore = await count('SELECT count(*)::int AS n FROM users');
    const organizationsBefore = await count('SELECT count(*)::int AS n FROM organizations');

    const results = await withContainer(async () => {
      try {
        resetGuest();
        useContainer().register(BootstrapReconciler);
        useContainer().register(Readiness);
        // The rehearsal itself, as rehearse.ts runs it on the import (values from the export).
        return await rehearseChecks(db, runtime, loaded, { databaseRoot: root });
      } finally {
        await restoreContainer();
      }
    });
    const byName = Object.fromEntries(results.map((result) => [result.name, result]));
    expect(results.filter((result) => result.status === 'fail')).toEqual([]);
    expect(byName['bootstrap not reconciled']).toMatchObject({
      status: 'ok',
      detail: 'fingerprint unchanged',
    });
    expect(byName['bootstrap organization']?.status).toBe('ok');
    // The owner signs in with the source's login; the viewer's changed password is a note,
    // with its carried hash proven.
    expect(byName['owner sign-in']?.status).toBe('ok');
    expect(byName['owner password hash carried']?.status).toBe('ok');
    expect(byName['viewer password hash carried']?.status).toBe('ok');
    expect(byName['viewer sign-in']).toMatchObject({
      status: 'note',
      detail: expect.stringContaining('password changed since bootstrap'),
    });
    // No new organization, owner or viewer from the defaults; the fingerprint is the source's.
    expect(await count('SELECT count(*)::int AS n FROM organizations')).toBe(organizationsBefore);
    expect(
      await count("SELECT count(*)::int AS n FROM organizations WHERE slug = 'platform'"),
    ).toBe(0);
    expect(
      await count(
        "SELECT count(*)::int AS n FROM users WHERE normalized_login IN ('owner', 'viewer')",
      ),
    ).toBe(0);
    expect(await count('SELECT count(*)::int AS n FROM users')).toBe(usersBefore);
    const fingerprint = await db.first<{ value: string }>(
      "SELECT value FROM identity_runtime_secret WHERE name = 'bootstrap_fingerprint'",
    );
    expect(fingerprint?.value).toBe(stored);
    // Nothing the rehearsal reports holds a login, an email or a secret.
    const printed = JSON.stringify(results);
    for (const value of [...Object.values(identity), ...Object.values(values)]) {
      if (value.length > 4) expect(printed).not.toContain(value);
    }
  } finally {
    await fixture.shutdown();
  }
}, 180_000);
