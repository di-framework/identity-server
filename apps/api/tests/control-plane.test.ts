import { afterAll, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { useContainer } from '@di-framework/core/container';
import { IdentityModule } from '@di-framework/identity/src/composition.ts';
import {
  localPostgresUrl,
  openPostgresDatabase,
} from '@di-framework/identity/src/shared/infrastructure/postgres.ts';
import { PostgresGateway } from '@di-framework/identity/src/shared/infrastructure/postgres-gateway.ts';
import { applyMigrations } from '@di-framework/identity-migrations';
import type { SqlDatabase } from '@di-framework/repo';
import { ControlPlaneController, controlPlane, IdentityServer } from '../src/control-plane.ts';

const databaseName = 'identity_control_test';
let database: SqlDatabase | undefined;

afterAll(async () => {
  await database?.close?.();
  const admin = await openPostgresDatabase(localPostgresUrl);
  await admin.exec(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  await admin.close?.();
});

test('reports a server error when the database is not connected', async () => {
  const response = await controlPlane.fetch(new Request('https://identity.test/api/admin/users'));
  expect(response.status).toBe(500);
});

test('serves the JSON control plane through application services', async () => {
  const admin = await openPostgresDatabase(localPostgresUrl);
  await admin.exec(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  await admin.exec(`CREATE DATABASE ${databaseName}`);
  await admin.close?.();
  database = await IdentityModule.connectFromConfig({
    DATABASE_URL: localPostgresUrl.replace(/\/identity$/, `/${databaseName}`),
  });
  await applyMigrations(database);

  const gateway = useContainer().resolve(PostgresGateway);
  expect(gateway.isUnique(null)).toBe(false);
  expect(gateway.isUnique('x')).toBe(false);
  expect(gateway.isUnique({ code: '23505' })).toBe(true);
  expect(gateway.isUnique({ message: 'duplicate key value' })).toBe(true);
  expect(gateway.isUnique({ message: 'other' })).toBe(false);

  const server = useContainer().resolve(IdentityServer).start();
  const served = await fetch(`http://127.0.0.1:${server.port}/api/admin/users`);
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

  const created = await call('POST', '/api/admin/users', {
    headers: { 'x-actor-id': 'ada-admin' },
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
    issuer: 'https://issuer.example',
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
  expect(stored[0]?.client_secret).toBe(createHash('sha256').update(machineSecret).digest('hex'));
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

  expect((await call('GET', '/api/v1/account/identity-links')).status).toBe(400);
  expect(
    (
      await call('GET', '/api/v1/account/identity-links', {
        headers: { 'x-user-id': crypto.randomUUID() },
      })
    ).status,
  ).toBe(404);
  const linked = await call('POST', '/api/admin/users', {
    body: { login: 'Ida', email: 'ida@example.com', displayName: 'Ida' },
  });
  const ida = linked.body as { id: string };
  await database.run(`UPDATE users SET status = 'active' WHERE id = ?`, [ida.id]);
  await database.run(
    `INSERT INTO identity_links (id, user_id, issuer, subject, provider_name) VALUES (?, ?, ?, ?, ?)`,
    [crypto.randomUUID(), ida.id, 'https://example.com/Team', 'subject-1', 'Example'],
  );
  const headers = { 'x-user-id': ida.id, 'x-session-id': 'session-a' };
  expect(
    (
      await call(
        'POST',
        `/api/v1/account/identity-links/unlink/prepare?issuer=${encodeURIComponent('not-a-url')}&subject=subject-1`,
        { headers },
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await call(
        'POST',
        `/api/v1/account/identity-links/unlink/prepare?issuer=${encodeURIComponent('ftp://example.com')}&subject=subject-1`,
        { headers },
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await call(
        'POST',
        `/api/v1/account/identity-links/unlink/prepare?issuer=${encodeURIComponent('http://example.com?x=1')}&subject=subject-1`,
        { headers },
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await call('POST', '/api/v1/account/identity-links/unlink/prepare?subject=subject-1', {
        headers,
      })
    ).status,
  ).toBe(400);
  expect(
    (
      await call(
        'POST',
        '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com&subject=',
        { headers },
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await call(
        'POST',
        '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com&subject=missing',
        { headers },
      )
    ).status,
  ).toBe(404);
  expect(
    (
      await call(
        'POST',
        '/api/v1/account/identity-links/unlink/prepare?issuer=https://Example.COM:443/Team/&subject=subject-1',
      )
    ).status,
  ).toBe(400);
  const pending = await call('POST', '/api/admin/users', {
    body: { login: 'Ned', email: 'ned@example.com', displayName: 'Ned' },
  });
  const ned = pending.body as { id: string };
  expect(
    (
      await call(
        'POST',
        `/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com&subject=subject-1`,
        {
          headers: { 'x-user-id': ned.id, 'x-session-id': 'session-a' },
        },
      )
    ).status,
  ).toBe(409);

  const prepared = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://Example.COM:443/Team/&subject=subject-1',
    { headers },
  );
  expect(prepared.status).toBe(200);
  const token = prepared.body as {
    confirmation_token: string;
    identity: { issuer: string; subjectHint: string };
  };
  expect(token.identity.issuer).toBe('https://example.com/Team');
  expect(token.identity.subjectHint).toHaveLength(16);
  expect((await call('GET', '/api/v1/account/identity-links', { headers })).body).toEqual(
    expect.arrayContaining([expect.objectContaining({ issuer: 'https://example.com/Team' })]),
  );
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=short`,
        { headers },
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=${token.confirmation_token}`,
        {
          headers: { 'x-user-id': ida.id, 'x-session-id': 'other-session' },
        },
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=${token.confirmation_token}`,
        { headers },
      )
    ).status,
  ).toBe(400);

  const blocked = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com/Team&subject=subject-1',
    { headers },
  );
  expect(blocked.status).toBe(200);
  const blockedToken = (blocked.body as { confirmation_token: string }).confirmation_token;
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=${blockedToken}`,
        { headers },
      )
    ).status,
  ).toBe(409);
  const dormant = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com/Team&subject=subject-1',
    { headers },
  );
  const dormantToken = (dormant.body as { confirmation_token: string }).confirmation_token;
  await database.run(`UPDATE users SET status = 'pending' WHERE id = ?`, [ida.id]);
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=${dormantToken}`,
        { headers },
      )
    ).status,
  ).toBe(409);
  await database.run(`UPDATE users SET status = 'active' WHERE id = ?`, [ida.id]);

  await database.run(`UPDATE users SET email_verified = true WHERE id = ?`, [ida.id]);
  const ready = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com/Team&subject=subject-1',
    { headers },
  );
  const readyToken = (ready.body as { confirmation_token: string }).confirmation_token;
  await database.run(
    `UPDATE identity_unlink_confirmations SET expires_at = now() - interval '1 minute' WHERE token_hash = ?`,
    [createHash('sha256').update(readyToken).digest('hex')],
  );
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=${readyToken}`,
        { headers },
      )
    ).status,
  ).toBe(400);

  const mismatch = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com/Team&subject=subject-1',
    { headers },
  );
  const mismatchToken = (mismatch.body as { confirmation_token: string }).confirmation_token;
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Other&subject=subject-1&confirmationToken=${mismatchToken}`,
        { headers },
      )
    ).status,
  ).toBe(400);

  await database.run(`UPDATE users SET status = 'pending', email_verified = false WHERE id = ?`, [
    ida.id,
  ]);
  const changed = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com/Team&subject=subject-1',
    { headers },
  );
  expect(changed.status).toBe(409);
  await database.run(`UPDATE users SET status = 'active', email_verified = true WHERE id = ?`, [
    ida.id,
  ]);
  const gone = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com/Team&subject=subject-1',
    { headers },
  );
  const goneToken = (gone.body as { confirmation_token: string }).confirmation_token;
  await database.run(`DELETE FROM identity_links WHERE user_id = ?`, [ida.id]);
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=${goneToken}`,
        { headers },
      )
    ).status,
  ).toBe(404);

  const passwordUser = await call('POST', '/api/admin/users', {
    body: { login: 'Pam', email: 'pam@example.com', displayName: 'Pam' },
  });
  const pam = passwordUser.body as { id: string };
  await database.run(`UPDATE users SET status = 'active', password_hash = 'hash' WHERE id = ?`, [
    pam.id,
  ]);
  await database.run(
    `INSERT INTO identity_links (id, user_id, issuer, subject, provider_name) VALUES (?, ?, ?, ?, ?)`,
    [crypto.randomUUID(), pam.id, 'http://example.com:8443/a/b', 'subject-2', 'Port'],
  );
  const pamHeaders = { 'x-user-id': pam.id, 'x-session-id': 'session-b' };
  const pamPrepared = await call(
    'POST',
    `/api/v1/account/identity-links/unlink/prepare?issuer=${encodeURIComponent('http://example.com:8443/a/b/')}&subject=subject-2`,
    { headers: pamHeaders },
  );
  expect(pamPrepared.status).toBe(200);
  const pamToken = (pamPrepared.body as { confirmation_token: string }).confirmation_token;
  const unlinked = await call(
    `DELETE`,
    `/api/v1/account/identity-links?issuer=http://example.com:8443/a/b&subject=subject-2&confirmationToken=${pamToken}`,
    { headers: pamHeaders },
  );
  expect(unlinked.body).toMatchObject({ unlinked: true, issuer: 'http://example.com:8443/a/b' });

  await database.run(
    `INSERT INTO identity_links (id, user_id, issuer, subject, provider_name) VALUES (?, ?, ?, ?, ?)`,
    [crypto.randomUUID(), ida.id, 'https://example.com/Team', 'subject-1', 'Example'],
  );
  const finalPrepared = await call(
    'POST',
    '/api/v1/account/identity-links/unlink/prepare?issuer=https://example.com/Team&subject=subject-1',
    { headers },
  );
  const finalToken = (finalPrepared.body as { confirmation_token: string }).confirmation_token;
  expect(
    (
      await call(
        'DELETE',
        `/api/v1/account/identity-links?issuer=https://example.com/Team&subject=subject-1&confirmationToken=${finalToken}`,
        { headers },
      )
    ).body,
  ).toMatchObject({
    unlinked: true,
  });
}, 60_000);

async function call(
  method: string,
  path: string,
  init?: { body?: unknown; headers?: Record<string, string> },
): Promise<{ status: number; body: unknown }> {
  const headers = new Headers(init?.headers);
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
