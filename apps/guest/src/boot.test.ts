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

function bridge(reserved: SQL, options: { splitTransactions?: boolean } = {}): IdentityDatabase {
  let txid = 0;
  return {
    async batch(sql: string) {
      await reserved.unsafe(sql);
    },
    async rows(sql: string, params: readonly { val: string }[] = []) {
      const result = await reserved.unsafe(
        sql,
        params.map((param) => param.val),
      );
      return Array.isArray(result) ? (result as Record<string, unknown>[]) : [];
    },
    async query(sql: string, params: readonly unknown[] = []) {
      if (options.splitTransactions && sql.includes('txid_current')) {
        txid += 1;
        return table(['tx'], [[textCell(String(txid))]]);
      }
      return asTable(await reserved.unsafe(sql, params.map(fromPg)));
    },
  } as unknown as IdentityDatabase;
}

function guestConfig(
  scheduler: boolean,
  redirects = 'http://localhost:3000/callback',
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
  ];
}

test('the guest boots on one connection and serves the Bun routes', async () => {
  await withContainer(() =>
    withThrowawayDatabase('identity_guest_http', async () => {
      const sql = new SQL(databaseUrl('identity_guest_http'));
      const reserved = await sql.reserve();
      const shell = '<!doctype html><div id="root" data-guest="shell"></div>';
      const fresh = () => {
        useContainer().register(BootstrapReconciler);
        useContainer().register(Readiness);
      };
      const assets = new Map<string, Uint8Array>([['main.js', new Uint8Array([1, 2, 3])]]);
      try {
        fresh();
        const refused = await handle(new Request('https://identity.test/ready'), {
          database: bridge(reserved, { splitTransactions: true }),
          config: { getAll: () => guestConfig(false) },
          assets,
          shell,
        });
        expect(refused.status).toBe(503);
        expect(await refused.json()).toEqual({
          ok: false,
          error: 'postgres queries do not share a transaction',
        });

        resetGuest();
        fresh();
        const ready = await handle(new Request('https://identity.test/ready'), {
          database: bridge(reserved),
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
          database: bridge(reserved),
          config: { getAll: () => guestConfig(false) },
          assets,
          shell,
        });
        expect(health.status).toBe(200);
        const login = await handle(new Request('https://identity.test/login'), {
          database: bridge(reserved),
          config: { getAll: () => guestConfig(false) },
          assets,
          shell,
        });
        expect(login.status).toBe(200);
        expect(await login.text()).toContain('data-guest="shell"');
        const script = await handle(new Request('https://identity.test/assets/main.js'), {
          database: bridge(reserved),
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
            database: bridge(reserved),
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
          database: bridge(reserved),
          config: { getAll: () => guestConfig(true) },
          assets,
          shell,
        });
        expect(drained.status).toBe(200);

        // Same secrets, new redirect URI: the stored fingerprint must not skip reconcile.
        resetGuest();
        fresh();
        const redirected = await handle(new Request('https://identity.test/health'), {
          database: bridge(reserved),
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
        await sql.end();
        await useTestDatabase();
      }
    }),
  );
}, 120_000);
