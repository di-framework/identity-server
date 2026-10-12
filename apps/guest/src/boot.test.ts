import { afterAll, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { BootstrapReconciler } from '../../../packages/core/src/bootstrap/application/bootstrap-reconciler.ts';
import { Readiness } from '../../../packages/core/src/bootstrap/application/readiness.ts';
import { IdentityModule } from '../../../packages/core/src/composition.ts';
import { NotificationWorker } from '../../../packages/core/src/notifications/application/security-notifications.ts';
import { withContainer } from '../../../packages/core/tests/support/container-lock.ts';
import { useTestDatabase } from '../../../packages/core/tests/support/database.ts';
import { rsaPrivateJwk } from '../../../packages/core/tests/support/keys.ts';
import { authorizationCodeChecks, identityFlows } from '../tests/support/flows.ts';
import { type PgliteFixture, pgliteFixture } from '../tests/support/pglite.ts';
import { DATABASE_ROOT_ENV, pgliteDatabase } from './database.ts';
import { embeddedMigrations } from './migrations.ts';
import { type GuestRuntime, handle, resetGuest } from './runtime.ts';
import { RUNTIME_SECRET_SETTINGS } from './settings.ts';

const scratch = mkdtempSync(join(tmpdir(), 'identity-guest-pglite-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

/** The guest's settings as the deploy delivers them: wasi:config plus the identity-control env. */
function guestConfig(
  scheduler: boolean,
  redirects = 'http://localhost:3000/callback',
  extra: Array<[string, string]> = [],
): Array<[string, string]> {
  return [
    ['ISSUER_URL', 'http://identity.identity.localhost'],
    ['AUTH_PUBLIC_ORIGIN', 'http://identity.identity.localhost'],
    ['AUTH_SIGNING_ALGORITHM', 'RS256'],
    ['AUTH_ACTIVE_PRIVATE_JWK', JSON.stringify(rsaPrivateJwk('guest-active'))],
    ['SMTP_HOST', '127.0.0.1'],
    ['SMTP_PORT', '1025'],
    ['SMTP_FROM', 'no-reply@identity.local'],
    ['SMTP_AUTH', 'false'],
    ['SMTP_STARTTLS', 'false'],
    ['SMTP_SSL_ENABLE', 'false'],
    ['SERVER_SERVLET_SESSION_COOKIE_SECURE', 'false'],
    ['AUTH_BOOTSTRAP_ORGANIZATION_SLUG', 'platform'],
    ['AUTH_BOOTSTRAP_ORGANIZATION_NAME', 'Platform'],
    ['AUTH_BOOTSTRAP_OWNER_EMAIL', 'owner@identity.local'],
    ['AUTH_BOOTSTRAP_OWNER_LOGIN', 'owner'],
    ['AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME', 'Owner'],
    ['AUTH_BOOTSTRAP_OWNER_PASSWORD', 'owner-secret'],
    ['AUTH_ACCESS_CLIENT_ID', 'access'],
    ['AUTH_DIRECTORY_CLIENT_ID', 'directory'],
    ['AUTH_PROVISIONER_CLIENT_ID', 'provisioner'],
    ['AUTH_ACCESS_CLIENT_SECRET', 'access-secret'],
    ['AUTH_DIRECTORY_CLIENT_SECRET', 'directory-secret'],
    ['AUTH_PROVISIONER_CLIENT_SECRET', 'provisioner-secret'],
    ['AUTH_ACCESS_REDIRECT_URIS', redirects],
    ['GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED', scheduler ? 'true' : 'false'],
    // Last, so a test's override wins when the guest folds the list into settings.
    ...extra,
  ];
}

const SECRET_NAMES = new Set<string>(RUNTIME_SECRET_SETTINGS);

/** Splits the settings the way a deploy does: secrets in the env, the rest in wasi:config. */
function runtimeFor(
  database: () => Promise<SqlDatabase>,
  settings: Array<[string, string]>,
  assets = new Map<string, Uint8Array>(),
  shell = '<!doctype html><div id="root" data-guest="shell"></div>',
): GuestRuntime {
  return {
    database,
    config: { getAll: () => settings.filter(([key]) => !SECRET_NAMES.has(key)) },
    env: () => ({
      ...Object.fromEntries(settings.filter(([key]) => SECRET_NAMES.has(key))),
      [DATABASE_ROOT_ENV]: '/data/pglite',
    }),
    assets,
    shell,
  };
}

/** Each "realm" (request instance) re-registers the readiness chain, as a fresh boot would. */
function freshRealm(): void {
  resetGuest();
  useContainer().register(BootstrapReconciler);
  useContainer().register(Readiness);
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

const flowInputs = (fetch: (request: Request) => Promise<Response>, slug: string) => ({
  fetch,
  ownerLogin: 'owner',
  ownerPassword: 'owner-secret',
  accessClient: {
    id: 'access',
    secret: 'access-secret',
    redirectUri: 'http://localhost:3000/callback',
  },
  provisionerClient: { id: 'provisioner', secret: 'provisioner-secret' },
  organizationSlug: slug,
});

test('the guest boots on one pglite connection and serves the Bun routes and flows', async () => {
  await withContainer(async () => {
    // `s64` lifted as JavaScript numbers here; the other tests use bigint (componentize-qjs di.5).
    const fixture = pgliteFixture(undefined, { integers: 'number' });
    const database = pgliteDatabase(fixture.module, () => ({ [DATABASE_ROOT_ENV]: '/data/boot' }));
    const db = await database();
    const assets = new Map<string, Uint8Array>([['main.js', new Uint8Array([1, 2, 3])]]);
    const runtime = (settings: Array<[string, string]>) => runtimeFor(database, settings, assets);
    const secretOf = async (clientId: string) =>
      (
        await db.first<{ client_secret: string }>(
          'SELECT client_secret FROM oauth2_registered_client WHERE client_id = ?',
          [clientId],
        )
      )?.client_secret;
    try {
      freshRealm();
      const ready = await handle(
        new Request('https://identity.test/ready'),
        runtime(guestConfig(false)),
      );
      expect({ status: ready.status, report: await ready.json() }).toEqual({
        status: 200,
        report: { database: true, signing_key: true, smtp: true, bootstrap: true, ok: true },
      });
      // The instance opened its database once and keeps that one connection.
      expect(fixture.opened).toEqual(['/data/boot']);
      const login = await handle(
        new Request('https://identity.test/login'),
        runtime(guestConfig(false)),
      );
      expect(login.status).toBe(200);
      expect(await login.text()).toContain('data-guest="shell"');
      const script = await handle(
        new Request('https://identity.test/assets/main.js'),
        runtime(guestConfig(false)),
      );
      expect(script.status).toBe(200);

      // Database writes and reads through the real flows: an admin API write, a duplicate, a
      // read, then a browser sign-in, consent, a PKCE code exchange and UserInfo.
      const serve = (request: Request) => handle(request, runtime(guestConfig(false)));
      const report = await identityFlows(flowInputs(serve, 'acme'));
      expect(report.organization).toEqual({
        created: 201,
        duplicate: 409,
        read: 200,
        name: 'Org acme',
      });
      expect(report.login).toMatchObject({ signIn: 303, consent: 303, token: 200, userinfo: 200 });
      expect(await authorizationCodeChecks(flowInputs(serve, 'unused'))).toEqual({
        authorizeValidation: { unknownClient: 400, unregisteredRedirect: 400 },
        codeExchange: {
          wrongVerifier: 400,
          wrongRedirect: 400,
          exchange: 200,
          idTokenVerified: true,
          replay: 400,
          wrongClientSecret: 401,
        },
        refresh: {
          rotate: 200,
          narrow: 200,
          widen: 'invalid_scope',
          reuse: 'invalid_grant',
          familyRevoked: 400,
        },
      });
      expect(fixture.opened).toEqual(['/data/boot']);
      // Secrets stay out of the database: only bootstrap state is stored there.
      const stored = await db.query<{ name: string }>(
        'SELECT name FROM identity_runtime_secret ORDER BY name',
      );
      expect(stored.map((row) => row.name)).toEqual([
        'bootstrap_client_fingerprints',
        'bootstrap_fingerprint',
      ]);

      freshRealm();
      useContainer().registerValue(NotificationWorker, {
        runOnce: async () => {
          throw new Error('drain');
        },
      } as unknown as NotificationWorker);
      const drained = await handle(
        new Request('https://identity.test/health'),
        runtime(guestConfig(true)),
      );
      expect(drained.status).toBe(200);

      // Same secrets, new redirect URI: the stored fingerprint must not skip reconcile.
      freshRealm();
      const redirects = 'http://localhost:3000/callback,https://app.test/cb';
      const redirected = await handle(
        new Request('https://identity.test/health'),
        runtime(guestConfig(false, redirects)),
      );
      expect(redirected.status).toBe(200);
      expect(
        await db.first<Record<string, unknown>>(
          'SELECT redirect_uris FROM oauth2_registered_client WHERE client_id = ?',
          ['access'],
        ),
      ).toEqual({ redirect_uris: redirects });

      // A lease another realm holds: the fingerprint differs (new CLI client), so this realm
      // would reconcile, but it answers 503 at once and hashes nothing.
      const withCli = (extra: Array<[string, string]> = []) =>
        runtime(guestConfig(false, redirects, [['AUTH_CLI_CLIENT_ID', 'tenant-cli'], ...extra]));
      const held = new Date(Date.now() + 60_000).toISOString();
      await db.run(
        `INSERT INTO identity_runtime_secret (name, value) VALUES ('bootstrap_lease', ?)`,
        [held],
      );
      freshRealm();
      const busy = await handle(new Request('https://identity.test/health'), withCli());
      expect(busy.status).toBe(503);
      expect(busy.headers.get('retry-after')).toBe('5');
      expect(await busy.json()).toEqual({
        ok: false,
        error: `bootstrap in progress until ${held}`,
      });
      expect(await secretOf('tenant-cli')).toBeUndefined();

      // An expired lease is taken over and released after the store. Stored client
      // fingerprints that are not JSON settle nothing, so the access secret is hashed again.
      const accessHash = await secretOf('access');
      await db.run(`UPDATE identity_runtime_secret SET value = ? WHERE name = 'bootstrap_lease'`, [
        new Date(Date.now() - 1000).toISOString(),
      ]);
      await db.run(
        `UPDATE identity_runtime_secret SET value = 'not json' WHERE name = 'bootstrap_client_fingerprints'`,
      );
      freshRealm();
      const taken = await handle(new Request('https://identity.test/health'), withCli());
      expect(taken.status).toBe(200);
      expect(
        await db.query(`SELECT 1 FROM identity_runtime_secret WHERE name = 'bootstrap_lease'`),
      ).toHaveLength(0);
      expect(
        await db.first<Record<string, unknown>>(
          'SELECT client_authentication_methods FROM oauth2_registered_client WHERE client_id = ?',
          ['tenant-cli'],
        ),
      ).toEqual({ client_authentication_methods: 'none' });
      const rehashed = await secretOf('access');
      expect(rehashed).not.toBe(accessHash);

      // Stored fingerprints that are JSON but not an object settle nothing either.
      await db.run(
        `UPDATE identity_runtime_secret SET value = '[1]' WHERE name = 'bootstrap_client_fingerprints'`,
      );
      freshRealm();
      const renamed = await handle(
        new Request('https://identity.test/health'),
        withCli([['AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME', 'Owner Two']]),
      );
      expect(renamed.status).toBe(200);
      const rehashedAgain = await secretOf('access');
      expect(rehashedAgain).not.toBe(rehashed);

      // A change outside the clients reconciles with every client settled: no hash changes.
      freshRealm();
      const settled = await handle(
        new Request('https://identity.test/health'),
        withCli([['AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME', 'Owner Three']]),
      );
      expect(settled.status).toBe(200);
      expect(await secretOf('access')).toBe(rehashedAgain);

      // A reconcile that fails after the lease is taken (here: an invalid CLI redirect) leaves
      // the prints of only the settled clients behind, so the next realm hashes the rotated
      // access secret again instead of trusting the print of the secret it was rotated from.
      freshRealm();
      const aborted = await handle(
        new Request('https://identity.test/health'),
        withCli([
          ['AUTH_ACCESS_CLIENT_SECRET', 'rotated-secret'],
          ['AUTH_CLI_REDIRECT_URIS', 'https://evil.test/cb'],
        ]),
      );
      expect(aborted.status).toBe(503);
      const prints = await db.first<{ value: string }>(
        `SELECT value FROM identity_runtime_secret WHERE name = 'bootstrap_client_fingerprints'`,
      );
      expect(Object.keys(JSON.parse(prints?.value ?? '{}')).sort()).toEqual([
        'directory',
        'provisioner',
      ]);
      expect(
        await db.query(`SELECT 1 FROM identity_runtime_secret WHERE name = 'bootstrap_lease'`),
      ).toHaveLength(0);
      freshRealm();
      const repaired = await handle(
        new Request('https://identity.test/health'),
        withCli([['AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME', 'Owner Four']]),
      );
      expect(repaired.status).toBe(200);
      expect(await secretOf('access')).not.toBe(rehashedAgain);
    } finally {
      await fixture.shutdown();
      await restoreContainer();
    }
  });
}, 180_000);

test('data survives an instance restart on the same database root', async () => {
  await withContainer(async () => {
    const dataDir = (root: string) => join(scratch, root.replaceAll('/', '_'));
    let fixture: PgliteFixture = pgliteFixture(dataDir);
    const env = () => ({ [DATABASE_ROOT_ENV]: '/data/restart' });
    try {
      freshRealm();
      const first = pgliteDatabase(fixture.module, env);
      const serve = (request: Request) => handle(request, runtimeFor(first, guestConfig(false)));
      const before = await identityFlows(flowInputs(serve, 'persisted'));
      expect(before.organization.created).toBe(201);

      // A new instance: new engine on the same files, nothing cached in the guest.
      await (await first()).close?.();
      await fixture.shutdown();
      fixture = pgliteFixture(dataDir);
      freshRealm();
      const second = pgliteDatabase(fixture.module, env);
      const serveAgain = (request: Request) =>
        handle(request, runtimeFor(second, guestConfig(false)));
      const health = await serveAgain(new Request('https://identity.test/health'));
      expect(health.status).toBe(200);
      const db = await second();
      expect(
        await db.first<Record<string, unknown>>('SELECT name FROM organizations WHERE slug = ?', [
          'persisted',
        ]),
      ).toEqual({ name: 'Org persisted' });
      // The schema was already there, and the stored fingerprint skipped reconcile.
      expect(
        await db.first<{ n: number }>('SELECT count(*)::int AS n FROM identity_schema_migrations'),
      ).toEqual({ n: embeddedMigrations.length });
      // The owner signs in again with the bootstrap password hashed before the restart.
      const again = await identityFlows({
        ...flowInputs(serveAgain, 'second'),
      });
      expect(again.login.subject).toBe(before.login.subject);
    } finally {
      await fixture.shutdown();
      await restoreContainer();
    }
  });
}, 180_000);

test('transactions serialize on the single pglite connection instead of blocking on row locks', async () => {
  // The Bun server's pooled test (packages/core/tests/postgres.test.ts) proves FOR UPDATE makes a
  // second connection wait. The guest has one connection, so a second transaction cannot reach
  // the database at all until the first commits, and a plain statement issued meanwhile waits
  // for the same mutex: it sees the committed value, never a half-done transaction.
  const fixture = pgliteFixture();
  const db = await pgliteDatabase(fixture.module, () => ({}))();
  try {
    await db.exec(
      'CREATE TABLE pool_probe (id int PRIMARY KEY, value int NOT NULL); INSERT INTO pool_probe VALUES (1, 0);',
    );
    const order: string[] = [];
    let releaseFirst!: () => void;
    const firstHolds = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstLocked!: () => void;
    const locked = new Promise<void>((resolve) => {
      firstLocked = resolve;
    });
    const first = db.transaction(async (tx) => {
      await tx.query('SELECT value FROM pool_probe WHERE id = 1 FOR UPDATE');
      order.push('first-locked');
      firstLocked();
      await firstHolds;
      await tx.run('UPDATE pool_probe SET value = value + 1 WHERE id = 1');
      order.push('first-commit');
    });
    await locked;
    const second = db.transaction(async (tx) => {
      const row = await tx.first<{ value: number }>(
        'SELECT value FROM pool_probe WHERE id = 1 FOR UPDATE',
      );
      order.push(`second-saw-${row?.value}`);
    });
    const outside = db
      .first<{ value: number }>('SELECT value FROM pool_probe WHERE id = 1')
      .then((row) => order.push(`outside-saw-${row?.value}`));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(order).toEqual(['first-locked']);
    releaseFirst();
    await Promise.all([first, second, outside]);
    expect(order[0]).toBe('first-locked');
    expect(order[1]).toBe('first-commit');
    expect(order.slice(2).sort()).toEqual(['outside-saw-1', 'second-saw-1']);

    // A throwing transaction rolls back; a nested one is a savepoint.
    await expect(
      db.transaction(async (tx) => {
        await tx.run('UPDATE pool_probe SET value = 99 WHERE id = 1');
        throw new Error('abort');
      }),
    ).rejects.toThrow('abort');
    await db.transaction(async (tx) => {
      await tx.run('UPDATE pool_probe SET value = 5 WHERE id = 1');
      await tx
        .transaction(async (inner) => {
          await inner.run('UPDATE pool_probe SET value = 6 WHERE id = 1');
          throw new Error('inner');
        })
        .catch(() => undefined);
    });
    expect(
      await db.first<Record<string, unknown>>('SELECT value FROM pool_probe WHERE id = 1'),
    ).toEqual({ value: 5 });
  } finally {
    await fixture.shutdown();
  }
});
