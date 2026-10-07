import { afterAll, beforeAll, expect, spyOn, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import { PostgresGateway } from '@di-framework/identity/src/shared/infrastructure/postgres-gateway.ts';
import {
  bearerFor,
  formRequest,
  registerClient,
} from '@di-framework/identity/tests/support/clients.ts';
import { useIsolatedDatabase } from '@di-framework/identity/tests/support/database.ts';
import type { SqlDatabase } from '@di-framework/repo';
import { ControlPlaneController, controlPlane, IdentityServer } from '../src/control-plane.ts';
import { ControlPlaneHandlers } from '../src/handlers.ts';

test('unknown paths are not control-plane routes', async () => {
  const response = await controlPlane.fetch(new Request('https://identity.test/login'));
  expect(response.status).toBe(404);
});

let isolated: Awaited<ReturnType<typeof useIsolatedDatabase>>;
let adminToken = '';

beforeAll(async () => {
  isolated = await useIsolatedDatabase('identity_control_test');
  adminToken = await bearerFor(
    (request) => controlPlane.fetch(request),
    ['admin:read', 'admin:write', 'directory:read'],
  );
});

afterAll(async () => {
  await isolated.release();
});

test('reports a server error with no body when an operation throws', async () => {
  const logged = spyOn(console, 'error').mockImplementation(() => {});
  const handlers = useContainer().resolve(ControlPlaneHandlers);
  const failing = {
    get(): string | null {
      throw new Error('internal detail');
    },
  };
  const response = await handlers.createUser(
    {},
    { transport: 'http', request: { headers: failing } },
  );
  expect(response.status).toBe(500);
  expect(await response.text()).toBe('');
  expect(logged).toHaveBeenCalledWith('control-plane createUser failed', expect.any(Error));
  logged.mockRestore();
});

test('serves the JSON control plane through application services', async () => {
  const database: SqlDatabase = isolated.database;

  const gateway = useContainer().resolve(PostgresGateway);
  expect(gateway.isUnique(null)).toBe(false);
  expect(gateway.isUnique('x')).toBe(false);
  expect(gateway.isUnique({ code: '23505' })).toBe(true);
  expect(gateway.isUnique({ message: 'duplicate key value' })).toBe(true);
  expect(gateway.isUnique({ message: 'other' })).toBe(false);

  const server = useContainer().resolve(IdentityServer).start();
  const served = await fetch(`http://127.0.0.1:${server.port}/api/admin/users`, {
    headers: { authorization: `Bearer ${adminToken}` },
  });
  expect(served.status).toBe(200);
  await server.stop(true);

  const controller = useContainer().resolve(ControlPlaneController);
  expect(() => controller.dispatch('missing', new Request('https://identity.test/'))).toThrow(
    'No handler',
  );

  expect((await call('GET', '/api/admin/users')).body).toEqual([]);
  expect((await call('POST', '/api/admin/users', { body: [] })).status).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/users', {
        body: { login: ' ', email: 'a@b.c', displayName: 'A' },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/users', {
        body: { login: 'a'.repeat(129), email: 'a@b.c', displayName: 'A' },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/users', {
        body: { login: 'ok', email: `${'a'.repeat(250)}@b.com`, displayName: 'A' },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/users', {
        body: { login: 'ok', email: 'a@b.c', displayName: 'a'.repeat(256) },
      })
    ).status,
  ).toBe(400);

  const adaAdmin = await registerClient({ clientId: 'ada-admin', scopes: ['admin:write'] });
  const adaToken = (await (
    await controlPlane.fetch(
      formRequest(
        '/oauth2/token',
        { grant_type: 'client_credentials', scope: 'admin:write' },
        {
          authorization: adaAdmin.basic,
        },
      ),
    )
  ).json()) as { access_token: string };
  const created = await call('POST', '/api/admin/users', {
    headers: { authorization: `Bearer ${adaToken.access_token}`, 'x-actor-id': 'spoofed' },
    body: { login: '  Ada  ', email: 'ada@example.com', displayName: 'Ada Lovelace' },
  });
  expect(created.status).toBe(201);
  const ada = created.body as { id: string; status: string };
  expect(ada.status).toBe('pending');
  expect((await call('GET', `/api/admin/users/${ada.id}`)).body).toMatchObject({
    login: 'Ada',
    email: 'ada@example.com',
    display_name: 'Ada Lovelace',
    email_verified: false,
    status: 'pending',
  });
  expect((await call('GET', '/api/admin/users/not-a-uuid')).status).toBe(404);
  expect((await call('GET', `/api/admin/users/${crypto.randomUUID()}`)).status).toBe(404);

  const replay = await call('POST', '/api/admin/users', {
    headers: { 'idempotency-key': 'user-key' },
    body: { login: 'Grace', email: 'grace@example.com', displayName: 'Grace' },
  });
  expect(replay.status).toBe(201);
  expect(
    (
      await call('POST', '/api/admin/users', {
        headers: { 'idempotency-key': 'user-key' },
        body: { login: 'Grace', email: 'grace@example.com', displayName: 'Grace' },
      })
    ).body,
  ).toEqual(replay.body);
  expect(
    (
      await call('POST', '/api/admin/users', {
        headers: { 'idempotency-key': 'user-key' },
        body: { login: 'Grace', email: 'grace@example.com', displayName: 'Other' },
      })
    ).status,
  ).toBe(409);
  expect(
    (
      await call('POST', '/api/admin/users', {
        body: { login: 'ada', email: 'other@example.com', displayName: 'Other' },
      })
    ).status,
  ).toBe(409);

  const missingTarget = crypto.randomUUID();
  await database.run(
    `INSERT INTO auth_audit_records (id, action, actor_client_id, target, correlation_id, before_metadata, after_metadata)
     VALUES (?, 'admin.user_created', 'system', ?, 'user-missing', '{}', '{}')`,
    [crypto.randomUUID(), missingTarget],
  );
  expect(
    (
      await call('POST', '/api/admin/users', {
        headers: { 'idempotency-key': 'user-missing' },
        body: { login: 'Lin', email: 'lin@example.com', displayName: 'Lin' },
      })
    ).status,
  ).toBe(201);

  expect((await call('PATCH', `/api/admin/users/${ada.id}`, { body: {} })).status).toBe(400);
  expect(
    (
      await call('PATCH', `/api/admin/users/${ada.id}`, {
        body: { displayName: 'a'.repeat(256) },
      })
    ).status,
  ).toBe(400);
  expect(
    (await call('PATCH', '/api/admin/users/bad', { body: { displayName: 'Ada' } })).status,
  ).toBe(400);
  expect(
    (
      await call('PATCH', `/api/admin/users/${crypto.randomUUID()}`, {
        body: { displayName: 'Ada' },
      })
    ).status,
  ).toBe(404);
  expect(
    (await call('PATCH', `/api/admin/users/${ada.id}`, { body: { displayName: 'Ada' } })).status,
  ).toBe(200);

  const org = await call('POST', '/api/admin/organizations', {
    headers: { 'idempotency-key': 'org-key' },
    body: { slug: 'acme', name: 'Acme' },
  });
  expect(org.status).toBe(201);
  expect(
    (
      await call('POST', '/api/admin/organizations', {
        headers: { 'idempotency-key': 'org-key' },
        body: { slug: 'acme', name: 'Acme' },
      })
    ).body,
  ).toEqual(org.body);
  expect(
    (
      await call('POST', '/api/admin/organizations', {
        headers: { 'idempotency-key': 'org-key' },
        body: { slug: 'acme', name: 'Other' },
      })
    ).status,
  ).toBe(409);
  expect(
    (await call('POST', '/api/admin/organizations', { body: { slug: 'acme', name: 'Again' } }))
      .status,
  ).toBe(409);
  expect(
    (await call('POST', '/api/admin/organizations', { body: { slug: ' ', name: 'Nope' } })).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/organizations', {
        body: { slug: 'a'.repeat(129), name: 'Nope' },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/organizations', {
        body: { slug: 'valid-slug', name: 'a'.repeat(256) },
      })
    ).status,
  ).toBe(400);
  await database.run(
    `INSERT INTO auth_audit_records (id, action, actor_client_id, target, correlation_id, before_metadata, after_metadata)
     VALUES (?, 'admin.organization_created', 'system', 'missing-org', 'org-missing', '{}', '{}')`,
    [crypto.randomUUID()],
  );
  expect(
    (
      await call('POST', '/api/admin/organizations', {
        headers: { 'idempotency-key': 'org-missing' },
        body: { slug: 'other', name: 'Other' },
      })
    ).status,
  ).toBe(201);
  expect((await call('GET', '/api/admin/organizations')).body).toEqual(
    expect.arrayContaining([expect.objectContaining({ slug: 'acme', name: 'Acme' })]),
  );
  expect((await call('GET', '/api/admin/organizations/missing')).status).toBe(404);
  expect((await call('PATCH', '/api/admin/organizations/acme', { body: {} })).status).toBe(400);
  expect(
    (
      await call('PATCH', '/api/admin/organizations/acme', {
        body: { name: 'a'.repeat(256) },
      })
    ).status,
  ).toBe(400);
  expect(
    (await call('PATCH', '/api/admin/organizations/missing', { body: { name: 'Nope' } })).status,
  ).toBe(404);
  expect(
    (await call('PATCH', '/api/admin/organizations/acme', { body: { name: 'Acme Inc' } })).body,
  ).toMatchObject({
    slug: 'acme',
    name: 'Acme Inc',
  });

  expect(
    (
      await call('PUT', `/api/admin/organizations/acme/members/${ada.id}`, {
        body: { role: 'admin' },
      })
    ).status,
  ).toBe(400);
  expect(
    (await call('PUT', '/api/admin/organizations/acme/members/bad', { body: { role: 'member' } }))
      .status,
  ).toBe(400);
  expect(
    (
      await call('PUT', `/api/admin/organizations/missing/members/${ada.id}`, {
        body: { role: 'member' },
      })
    ).status,
  ).toBe(404);
  expect(
    (
      await call('PUT', `/api/admin/organizations/acme/members/${crypto.randomUUID()}`, {
        body: { role: 'member' },
      })
    ).status,
  ).toBe(404);
  expect(
    (
      await call('PUT', `/api/admin/organizations/acme/members/${ada.id}`, {
        body: { role: 'owner' },
      })
    ).status,
  ).toBe(204);
  expect((await call('GET', `/api/admin/organizations/acme/members/${ada.id}`)).body).toMatchObject(
    { role: 'owner' },
  );
  expect(
    (
      await call('PUT', `/api/admin/organizations/acme/members/${ada.id}`, {
        body: { role: 'member' },
      })
    ).status,
  ).toBe(204);
  expect((await call('GET', `/api/admin/organizations/missing/members/${ada.id}`)).status).toBe(
    404,
  );
  expect((await call('GET', '/api/admin/organizations/acme/members/bad')).status).toBe(404);
  expect((await call('DELETE', '/api/admin/organizations/acme')).status).toBe(409);
  expect((await call('DELETE', `/api/admin/users/${ada.id}`)).status).toBe(409);

  const second = await call('POST', '/api/admin/users', {
    body: { login: 'Bea', email: 'bea@example.com', displayName: 'Bea' },
  });
  const bea = second.body as { id: string };
  expect(
    (
      await call('PUT', `/api/admin/organizations/acme/members/${bea.id}`, {
        body: { role: 'member' },
      })
    ).status,
  ).toBe(204);
  await database.run(`UPDATE users SET avatar_url = ? WHERE id = ?`, [
    'https://example.com/bea.png',
    bea.id,
  ]);
  const page = await call('GET', '/api/v1/organizations/acme/members?limit=1');
  expect(page.status).toBe(200);
  const firstPage = page.body as {
    items: Array<{ subject: string; picture: string | null }>;
    next_cursor: string;
  };
  expect(firstPage.items).toHaveLength(1);
  expect(firstPage.next_cursor).toBeString();
  const secondPage = await call(
    'GET',
    `/api/v1/organizations/acme/members?cursor=${firstPage.next_cursor}&limit=1`,
  );
  expect((secondPage.body as { items: unknown[]; next_cursor: null }).items).toHaveLength(1);
  expect((secondPage.body as { next_cursor: null }).next_cursor).toBeNull();
  expect((await call('GET', '/api/v1/organizations/acme/members?cursor=abc')).status).toBe(400);
  expect((await call('GET', '/api/v1/organizations/acme/members?cursor=a')).status).toBe(400);
  expect((await call('GET', '/api/v1/organizations/acme/members?limit=abc')).body).toMatchObject({
    items: expect.any(Array),
  });
  expect(
    ((await call('GET', '/api/v1/organizations/acme/members?limit=0')).body as { items: unknown[] })
      .items,
  ).toHaveLength(1);
  expect(
    (
      (await call('GET', '/api/v1/organizations/acme/members?limit=1000')).body as {
        items: unknown[];
      }
    ).items,
  ).toHaveLength(2);
  const pictured = (
    (await call('GET', '/api/v1/organizations/acme/members')).body as {
      items: Array<{ subject: string; picture: string | null; issuer: string }>;
    }
  ).items.find((item) => item.subject === bea.id);
  expect(pictured).toMatchObject({
    picture: 'https://example.com/bea.png',
    issuer: 'https://identity.test',
  });

  expect((await call('DELETE', `/api/admin/organizations/acme/members/${ada.id}`)).status).toBe(
    204,
  );
  expect((await call('DELETE', `/api/admin/organizations/acme/members/${bea.id}`)).status).toBe(
    204,
  );
  expect((await call('DELETE', `/api/admin/organizations/acme/members/${ada.id}`)).status).toBe(
    404,
  );
  expect((await call('DELETE', `/api/admin/users/${ada.id}`)).status).toBe(204);
  expect((await call('DELETE', `/api/admin/users/${ada.id}`)).status).toBe(204);
  expect((await call('DELETE', '/api/admin/users/bad')).status).toBe(404);
  expect(
    (await call('PATCH', `/api/admin/users/${ada.id}`, { body: { displayName: 'Again' } })).status,
  ).toBe(409);
  expect(
    (
      await call('PUT', `/api/admin/organizations/acme/members/${ada.id}`, {
        body: { role: 'member' },
      })
    ).status,
  ).toBe(409);

  const machine = await call('POST', '/api/admin/oauth-clients', {
    body: { clientId: 'machine', organizationSlug: 'acme' },
  });
  expect(machine.status).toBe(201);
  const machineSecret = (machine.body as { client_secret: string }).client_secret;
  const stored = await database.query<{ client_secret: string }>(
    `SELECT client_secret FROM oauth2_registered_client WHERE client_id = ?`,
    ['machine'],
  );
  expect(stored[0]?.client_secret).toStartWith('$argon2id$v=19$m=16384,t=2,p=1$');
  expect(await Bun.password.verify(machineSecret, stored[0]?.client_secret ?? '')).toBe(true);
  expect((await call('GET', '/api/admin/oauth-clients')).body).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ client_id: 'machine', browser: false, organization_slug: 'acme' }),
    ]),
  );
  expect((await call('DELETE', '/api/admin/organizations/acme')).status).toBe(409);
  expect(
    (await call('POST', '/api/admin/oauth-clients', { body: { clientId: 'machine' } })).status,
  ).toBe(409);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients', {
        body: { clientId: 'browser', browser: true },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients', {
        body: { clientId: 'a'.repeat(101) },
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients', {
        body: { clientId: 'valid-cli', organizationSlug: 'a'.repeat(129) },
      })
    ).status,
  ).toBe(400);
  const browser = await call('POST', '/api/admin/oauth-clients', {
    headers: { 'idempotency-key': 'client-key' },
    body: {
      clientId: 'browser',
      browser: true,
      redirectUris: ['https://app.example/callback', 1],
      scopes: ['openid'],
    },
  });
  expect(browser.status).toBe(201);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients', {
        headers: { 'idempotency-key': 'client-key' },
        body: {
          clientId: 'browser',
          browser: true,
          redirectUris: ['https://app.example/callback'],
          scopes: ['openid'],
        },
      })
    ).body,
  ).toEqual(browser.body);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients', {
        headers: { 'idempotency-key': 'client-key' },
        body: {
          clientId: 'browser',
          browser: true,
          redirectUris: ['https://app.example/callback'],
          scopes: ['openid', 'profile'],
        },
      })
    ).status,
  ).toBe(409);
  await database.run(
    `INSERT INTO auth_audit_records (id, action, actor_client_id, target, correlation_id, before_metadata, after_metadata)
     VALUES (?, 'admin.oauth_client_created', 'system', 'missing-client', 'client-missing', '{}', '{}')`,
    [crypto.randomUUID()],
  );
  expect(
    (
      await call('POST', '/api/admin/oauth-clients', {
        headers: { 'idempotency-key': 'client-missing' },
        body: { clientId: 'fresh' },
      })
    ).status,
  ).toBe(201);
  expect((await call('GET', '/api/admin/oauth-clients/missing')).status).toBe(404);
  expect((await call('POST', '/api/admin/oauth-clients', { body: {} })).status).toBe(400);
  expect(
    (await call('PUT', '/api/admin/oauth-clients/browser', { body: { browser: true } })).status,
  ).toBe(400);
  expect(
    (
      await call('PUT', '/api/admin/oauth-clients/browser', {
        body: { organizationSlug: 'a'.repeat(129) },
      })
    ).status,
  ).toBe(400);
  expect(
    (await call('PUT', '/api/admin/oauth-clients/missing', { body: { scopes: ['a'] } })).status,
  ).toBe(404);
  expect(
    (
      await call('PUT', '/api/admin/oauth-clients/browser', {
        body: { redirectUris: ['https://app.example/cb'], scopes: ['openid'] },
      })
    ).status,
  ).toBe(200);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients/missing/rotate-secret', {
        body: { version: 'v2' },
      })
    ).status,
  ).toBe(404);
  expect(
    (await call('POST', '/api/admin/oauth-clients/browser/rotate-secret', { body: {} })).status,
  ).toBe(400);
  const rotated = await call('POST', '/api/admin/oauth-clients/browser/rotate-secret', {
    headers: { 'idempotency-key': 'rotate-key' },
    body: { version: 'v2' },
  });
  expect(rotated.status).toBe(200);
  const again = await call('POST', '/api/admin/oauth-clients/browser/rotate-secret', {
    headers: { 'idempotency-key': 'rotate-key' },
    body: { version: 'v2' },
  });
  expect(again.body).toEqual(rotated.body);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients/browser/rotate-secret', {
        body: { version: 'v3' },
      })
    ).status,
  ).toBe(200);
  expect((await call('DELETE', '/api/admin/oauth-clients/missing')).status).toBe(404);
  expect((await call('DELETE', '/api/admin/oauth-clients/machine')).status).toBe(204);
  expect((await call('DELETE', '/api/admin/oauth-clients/machine')).status).toBe(204);
  expect(
    (await call('PUT', '/api/admin/oauth-clients/machine', { body: { scopes: ['a'] } })).status,
  ).toBe(409);
  expect(
    (
      await call('POST', '/api/admin/oauth-clients/machine/rotate-secret', {
        body: { version: 'v2' },
      })
    ).status,
  ).toBe(409);
  expect((await call('DELETE', '/api/admin/organizations/acme')).status).toBe(204);
  expect((await call('DELETE', '/api/admin/organizations/missing')).status).toBe(404);

  const audits = (await call('GET', '/api/admin/audit')).body as Array<{
    actor_client_id: string;
    action: string;
  }>;
  expect(
    audits.some(
      (record) => record.actor_client_id === 'ada-admin' && record.action === 'admin.user_created',
    ),
  ).toBe(true);
  expect(audits.some((record) => record.actor_client_id === 'system')).toBe(true);
}, 60_000);

async function call(
  method: string,
  path: string,
  init?: { body?: unknown; headers?: Record<string, string> },
): Promise<{ status: number; body: unknown }> {
  const headers = new Headers(init?.headers);
  if (!headers.has('authorization')) headers.set('authorization', `Bearer ${adminToken}`);
  let body: string | undefined;
  if (init && 'body' in init) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(init.body);
  } else if (method === 'POST' || method === 'PUT' || method === 'PATCH') {
    headers.set('content-type', 'application/json');
    body = '{}';
  }
  const response = await controlPlane.fetch(
    new Request(`https://identity.test${path}`, { method, headers, body }),
  );
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : undefined };
}
