import { expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import { pgScalar } from '@di-framework/repo/postgres';
import { SQL } from 'bun';
import { BootstrapReconciler } from '../../../packages/core/src/bootstrap/application/bootstrap-reconciler.ts';
import { Readiness } from '../../../packages/core/src/bootstrap/application/readiness.ts';
import { IdentityModule } from '../../../packages/core/src/composition.ts';
import { NotificationWorker } from '../../../packages/core/src/notifications/application/security-notifications.ts';
import { withContainer } from '../../../packages/core/tests/support/container-lock.ts';
import {
  databaseUrl,
  useTestDatabase,
  withThrowawayDatabase,
} from '../../../packages/core/tests/support/database.ts';
import { rsaPrivateJwk } from '../../../packages/core/tests/support/keys.ts';
import type { IdentityDatabase } from './bindings.ts';
import { handle, resetGuest } from './runtime.ts';

const textCell = (val: string) => ({ tag: 'text' as const, val });

function stream(rows: readonly unknown[]): AsyncIterable<unknown> {
  return {
    async *[Symbol.asyncIterator]() {
      for (const row of rows) yield row;
    },
  };
}

function table(columns: string[], rows: readonly unknown[]): unknown {
  return [columns, stream(rows), null];
}

function fromPg(value: unknown): unknown {
  if (value == null || typeof value !== 'object' || !('tag' in value)) return value;
  const tagged = value as { tag: unknown; val?: unknown };
  if (tagged.tag === 'null') return null;
  if (tagged.tag === 'bytea' && Array.isArray(tagged.val)) return Uint8Array.from(tagged.val);
  if (tagged.tag === 'timestamp-tz') {
    const iso = pgScalar(value);
    return typeof iso === 'string' ? new Date(iso) : null;
  }
  return tagged.val ?? null;
}

function cellOf(value: unknown): unknown {
  if (value == null) return { tag: 'null' };
  if (typeof value === 'string') return textCell(value);
  if (typeof value === 'boolean') return { tag: 'bool', val: value };
  if (typeof value === 'bigint') return { tag: 'int8', val: Number(value) };
  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? { tag: 'int8', val: value }
      : { tag: 'numeric', val: String(value) };
  }
  if (value instanceof Date) return { tag: 'timestamp', val: value.toISOString() };
  if (value instanceof Uint8Array) return { tag: 'bytea', val: [...value] };
  if (typeof value === 'object') return { tag: 'jsonb', val: JSON.stringify(value) };
  return textCell(String(value));
}

function asTable(result: unknown): unknown {
  const rows = Array.isArray(result) ? result : [];
  const first = rows[0];
  const columns = first != null && typeof first === 'object' ? Object.keys(first as object) : [];
  return table(
    columns,
    rows.map((row) => columns.map((column) => cellOf((row as Record<string, unknown>)[column]))),
  );
}

/**
 * The binding as the host serves it: every call takes whichever pooled connection is free, so
 * consecutive statements of one request land on different connections. Rotating through the
 * reserved connections reproduces that, including for `BEGIN` / `COMMIT` pairs, which is why
 * the guest must not rely on them.
 */
function bridge(connections: SQL[]): IdentityDatabase {
  let turn = 0;
  const next = () => connections[turn++ % connections.length] as SQL;
  return {
    async batch(sql: string) {
      await next().unsafe(sql);
    },
    async rows(sql: string, params: readonly { val: string }[] = []) {
      const result = await next().unsafe(
        sql,
        params.map((param) => param.val),
      );
      return Array.isArray(result) ? (result as Record<string, unknown>[]) : [];
    },
    async query(sql: string, params: readonly unknown[] = []) {
      return asTable(await next().unsafe(sql, params.map(fromPg)));
    },
    async queryBatch(sql: string) {
      await next().unsafe(sql);
    },
  } as unknown as IdentityDatabase;
}

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

test('the guest boots with no connection affinity and serves the Bun routes', async () => {
  await withContainer(() =>
    withThrowawayDatabase('identity_guest_http', async () => {
      const sql = new SQL(databaseUrl('identity_guest_http'));
      const reserved = await sql.reserve();
      const other = await sql.reserve();
      // Two connections, used in turn: a `BEGIN` on one would never pair with a `COMMIT` on the
      // other, so this boot and every write below prove the guest does without them.
      const database = bridge([reserved, other]);
      const shell = '<!doctype html><div id="root" data-guest="shell"></div>';
      const fresh = () => {
        useContainer().register(BootstrapReconciler);
        useContainer().register(Readiness);
      };
      const assets = new Map<string, Uint8Array>([['main.js', new Uint8Array([1, 2, 3])]]);
      try {
        fresh();
        const ready = await handle(new Request('https://identity.test/ready'), {
          database,
          config: { getAll: () => guestConfig(false) },
          assets,
          shell,
        });
        const report = await ready.json();
        expect({ status: ready.status, report }).toEqual({
          status: 200,
          report: {
            database: true,
            signing_key: true,
            smtp: true,
            bootstrap: true,
            ok: true,
          },
        });
        const health = await handle(new Request('https://identity.test/health'), {
          database,
          config: { getAll: () => guestConfig(false) },
          assets,
          shell,
        });
        expect(health.status).toBe(200);
        const login = await handle(new Request('https://identity.test/login'), {
          database,
          config: { getAll: () => guestConfig(false) },
          assets,
          shell,
        });
        expect(login.status).toBe(200);
        expect(await login.text()).toContain('data-guest="shell"');
        const script = await handle(new Request('https://identity.test/assets/main.js'), {
          database,
          config: { getAll: () => guestConfig(false) },
          assets,
          shell,
        });
        expect(script.status).toBe(200);
        const organizations = await handle(
          new Request('https://identity.test/api/admin/organizations', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ slug: 'acme', name: 'Acme' }),
          }),
          {
            database,
            config: { getAll: () => guestConfig(false) },
            assets,
            shell,
          },
        );
        expect(organizations.status).not.toBe(404);

        resetGuest();
        fresh();
        useContainer().registerValue(NotificationWorker, {
          runOnce: async () => {
            throw new Error('drain');
          },
        } as unknown as NotificationWorker);
        const drained = await handle(new Request('https://identity.test/health'), {
          database,
          config: { getAll: () => guestConfig(true) },
          assets,
          shell,
        });
        expect(drained.status).toBe(200);

        // Same secrets, new redirect URI: the stored fingerprint must not skip reconcile.
        resetGuest();
        fresh();
        const redirected = await handle(new Request('https://identity.test/health'), {
          database,
          config: {
            getAll: () => guestConfig(false, 'http://localhost:3000/callback,https://app.test/cb'),
          },
          assets,
          shell,
        });
        expect(redirected.status).toBe(200);
        const [access] = await reserved.unsafe(
          `SELECT redirect_uris FROM oauth2_registered_client WHERE client_id = 'access'`,
        );
        expect(access.redirect_uris).toBe('http://localhost:3000/callback,https://app.test/cb');

        // A lease another realm holds: the fingerprint differs (new CLI client), so this realm
        // would reconcile, but it answers 503 at once and hashes nothing.
        const redirects = 'http://localhost:3000/callback,https://app.test/cb';
        const withCli = (extra: Array<[string, string]> = []) => ({
          database,
          config: {
            getAll: () =>
              guestConfig(false, redirects, [['AUTH_CLI_CLIENT_ID', 'tenant-cli'], ...extra]),
          },
          assets,
          shell,
        });
        const secretOf = async (clientId: string) =>
          (
            await reserved.unsafe(
              `SELECT client_secret FROM oauth2_registered_client WHERE client_id = '${clientId}'`,
            )
          )[0]?.client_secret as string | undefined;
        const held = new Date(Date.now() + 60_000).toISOString();
        await reserved.unsafe(
          `INSERT INTO identity_runtime_secret (name, value) VALUES ('bootstrap_lease', $1)`,
          [held],
        );
        resetGuest();
        fresh();
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
        await reserved.unsafe(
          `UPDATE identity_runtime_secret SET value = $1 WHERE name = 'bootstrap_lease'`,
          [new Date(Date.now() - 1000).toISOString()],
        );
        await reserved.unsafe(
          `UPDATE identity_runtime_secret SET value = 'not json' WHERE name = 'bootstrap_client_fingerprints'`,
        );
        resetGuest();
        fresh();
        const taken = await handle(new Request('https://identity.test/health'), withCli());
        expect(taken.status).toBe(200);
        expect(
          await reserved.unsafe(
            `SELECT 1 FROM identity_runtime_secret WHERE name = 'bootstrap_lease'`,
          ),
        ).toHaveLength(0);
        const [cli] = await reserved.unsafe(
          `SELECT client_authentication_methods FROM oauth2_registered_client WHERE client_id = 'tenant-cli'`,
        );
        expect(cli.client_authentication_methods).toBe('none');
        const rehashed = await secretOf('access');
        expect(rehashed).not.toBe(accessHash);

        // Stored fingerprints that are JSON but not an object settle nothing either.
        await reserved.unsafe(
          `UPDATE identity_runtime_secret SET value = '[1]' WHERE name = 'bootstrap_client_fingerprints'`,
        );
        resetGuest();
        fresh();
        const renamed = await handle(
          new Request('https://identity.test/health'),
          withCli([['AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME', 'Owner Two']]),
        );
        expect(renamed.status).toBe(200);
        const rehashedAgain = await secretOf('access');
        expect(rehashedAgain).not.toBe(rehashed);

        // A change outside the clients reconciles with every client settled: no hash changes.
        resetGuest();
        fresh();
        const settled = await handle(
          new Request('https://identity.test/health'),
          withCli([['AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME', 'Owner Three']]),
        );
        expect(settled.status).toBe(200);
        expect(await secretOf('access')).toBe(rehashedAgain);
      } finally {
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
        reserved.release();
        other.release();
        await sql.end();
        await useTestDatabase();
      }
    }),
  );
}, 120_000);
