import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { type RedTeamContext, setupRedTeamServer } from './red-team-harness.ts';

describe('Red-Team Category 3: API Authorization & Access Control', () => {
  let ctx: RedTeamContext;
  let adminToken = '';
  let readOnlyAdminToken = '';
  let directoryOnlyToken = '';

  beforeAll(async () => {
    ctx = await setupRedTeamServer();

    // 1. Issue full admin token
    const res1 = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: ctx.fixtures.confidentialClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'admin:read admin:write',
      }),
    });
    adminToken = ((await res1.json()) as { access_token: string }).access_token;

    // 2. Issue read-only admin token
    const res2 = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: ctx.fixtures.backendClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'admin:read',
      }),
    });
    readOnlyAdminToken = ((await res2.json()) as { access_token: string }).access_token;

    // 3. Issue low-privilege directory-only token
    const res3 = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: ctx.fixtures.unprivilegedClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'directory:read',
      }),
    });
    directoryOnlyToken = ((await res3.json()) as { access_token: string }).access_token;
  });

  afterAll(async () => {
    await ctx?.stop();
  });

  test('BFLA: Unauthenticated calls to admin API are rejected with 401', async () => {
    const endpoints = [
      '/api/admin/users',
      '/api/admin/organizations',
      '/api/admin/oauth-clients',
      '/api/admin/audit',
    ];

    for (const endpoint of endpoints) {
      const res = await fetch(`${ctx.baseUrl}${endpoint}`);
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBe('Bearer');
    }
  });

  test('BFLA: Low-privilege token (directory:read) is rejected with 403 on admin routes', async () => {
    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${directoryOnlyToken}` },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get('www-authenticate')).toContain('insufficient_scope');
  });

  test('BFLA: Read-only admin token cannot perform mutating operations (POST/PUT/DELETE)', async () => {
    // 1. GET is allowed with admin:read
    const getRes = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${readOnlyAdminToken}` },
    });
    expect(getRes.status).toBe(200);

    // 2. POST /api/admin/users requires admin:write -> 403
    const postRes = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${readOnlyAdminToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        login: 'hacker-created',
        email: 'hacker@test.corp',
        displayName: 'Hacker User',
      }),
    });
    expect(postRes.status).toBe(403);
    expect(postRes.headers.get('www-authenticate')).toContain('admin:write');
  });

  test('Actor Spoofing: Injected X-Actor-Id or X-Principal headers are ignored', async () => {
    // Attempt to spoof actor as another admin in audit log
    const fakeActorId = 'spoofed-fake-admin-uuid';
    const uniqueLogin = `actor-test-${crypto.randomUUID().slice(0, 6)}`;

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
        'x-actor-id': fakeActorId,
        'x-principal': fakeActorId,
        'x-authenticated-user': fakeActorId,
      },
      body: JSON.stringify({
        login: uniqueLogin,
        email: `${uniqueLogin}@test.corp`,
        displayName: 'Actor Spoof Test',
      }),
    });
    expect(res.status).toBe(201);

    // Fetch audit log to confirm actor was set to client principal, not spoofed header
    const auditRes = await fetch(`${ctx.baseUrl}/api/admin/audit`, {
      headers: { authorization: `Bearer ${adminToken}` },
    });
    expect(auditRes.status).toBe(200);
    const auditEntries = (await auditRes.json()) as Array<{
      action: string;
      actor: string;
      target: string;
    }>;
    const entry = auditEntries.find((e) => e.action === 'admin.user_created');
    expect(entry).toBeTruthy();
    expect(entry!.actor).not.toBe(fakeActorId);
  });

  test('BOLA: Account links unlink requires recent session and cannot be bypassed via Bearer token', async () => {
    // Call unlink prepare with bearer token
    const res = await fetch(
      `${ctx.baseUrl}/api/v1/account/identity-links/unlink/prepare?issuer=https://idp.example&subject=sub123`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${adminToken}`,
          'content-type': 'application/json',
        },
        body: '{}',
        redirect: 'manual',
      },
    );
    // Unlink step-up requires recent interactive authentication session; bearer tokens cannot pass step-up
    expect([401, 403]).toContain(res.status);
  });

  test('Idempotency Tampering: Replaying Idempotency-Key with conflicting body fails', async () => {
    const key = `idem-${crypto.randomUUID()}`;
    const userPayload = {
      login: `idem-user-${crypto.randomUUID().slice(0, 6)}`,
      email: 'idem@test.corp',
      displayName: 'Original Name',
    };

    // First request
    const firstRes = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
        'idempotency-key': key,
      },
      body: JSON.stringify(userPayload),
    });
    expect(firstRes.status).toBe(201);

    // Replay with identical key but different email / login (tampered payload)
    const tamperedRes = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
        'idempotency-key': key,
      },
      body: JSON.stringify({
        ...userPayload,
        email: 'tampered-email@test.corp',
      }),
    });
    // Server must reject or return conflict (409 or 400)
    expect([400, 409]).toContain(tamperedRes.status);
  });
});
