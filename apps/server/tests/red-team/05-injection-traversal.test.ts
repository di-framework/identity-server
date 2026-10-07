import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { type RedTeamContext, setupRedTeamServer } from './red-team-harness.ts';

describe('Red-Team Category 5: Path Traversal & Injection Attacks', () => {
  let ctx: RedTeamContext;
  let adminToken = '';

  beforeAll(async () => {
    ctx = await setupRedTeamServer();

    const res = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: ctx.fixtures.confidentialClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'admin:read admin:write directory:read',
      }),
    });
    adminToken = ((await res.json()) as { access_token: string }).access_token;
    expect(adminToken).toBeTruthy();
  });

  afterAll(async () => {
    await ctx?.stop();
  });

  test('Static Asset Traversal: Probing directory traversal vectors returns 404 and does not leak files', async () => {
    // 1. Verify valid asset returns 200
    const validAsset = await fetch(`${ctx.baseUrl}/assets/main.js`);
    expect(validAsset.status).toBe(200);

    // 2. Traversal attack vectors probing directory traversal
    const traversalVectors = [
      '/assets/...',
      '/assets/%2e%2e',
      '/assets/.env',
      '/assets/.git',
      '/assets/.gitignore',
      '/assets/%00main.js',
      '/assets/nested/sub/asset.js',
    ];

    for (const vector of traversalVectors) {
      const res = await fetch(`${ctx.baseUrl}${vector}`, { redirect: 'manual' });
      // Either rejected by asset regex with 404, or URL-normalized away from assets to 302
      expect([404, 302]).toContain(res.status);
      // Ensure file content is not leaked
      const body = await res.text();
      expect(body).not.toContain('"name": "@di-framework/identity"');
      expect(body).not.toContain('DATABASE_URL');
    }
  });

  test('SQL Injection: Path parameters reject or safely handle single quotes and SQL metacharacters', async () => {
    const sqliVectors = [
      "' OR '1'='1",
      "'; DROP TABLE identity_test; --",
      "' UNION SELECT null, null, null--",
      "admin'--",
      "1' AND 1=1--",
    ];

    for (const payload of sqliVectors) {
      // 1. In user ID param
      const userRes = await fetch(`${ctx.baseUrl}/api/admin/users/${encodeURIComponent(payload)}`, {
        headers: { authorization: `Bearer ${adminToken}` },
      });
      // Parameter validation should return 400 or 404 (not 500 database error)
      expect([400, 404]).toContain(userRes.status);
      const userBody = await userRes.text();
      expect(userBody.toLowerCase()).not.toContain('syntax error');
      expect(userBody.toLowerCase()).not.toContain('postgresql');

      // 2. In organization slug param
      const orgRes = await fetch(
        `${ctx.baseUrl}/api/v1/organizations/${encodeURIComponent(payload)}/members`,
        {
          headers: { authorization: `Bearer ${adminToken}` },
        },
      );
      expect([200, 400, 404]).toContain(orgRes.status);
      if (orgRes.status === 200) {
        const body = (await orgRes.json()) as { items?: unknown[] };
        expect(body.items).toBeDefined();
        // If SQLi bypassed the filter, it would have returned members from all organizations
        expect(body.items?.length).toBe(0);
      }
    }
  });

  test('SQL Injection: Query string parameters with SQL injections do not cause SQL errors', async () => {
    const sqliQueries = ["' OR 1=1--", "' UNION SELECT 1, '2', '3'--", '1; SELECT pg_sleep(5);--'];

    for (const query of sqliQueries) {
      const res = await fetch(
        `${ctx.baseUrl}/api/v1/organizations/${ctx.fixtures.orgAlpha.slug}/members?cursor=${encodeURIComponent(query)}&limit=10`,
        {
          headers: { authorization: `Bearer ${adminToken}` },
        },
      );
      expect([200, 400]).toContain(res.status);
      const body = await res.text();
      expect(body.toLowerCase()).not.toContain('syntax error');
      expect(body.toLowerCase()).not.toContain('pg_catalog');
    }
  });

  test('SQL Injection: JSON payload fields are properly parameterized and escape quotes', async () => {
    const sqliPayload = {
      login: `sqli-${crypto.randomUUID().slice(0, 6)}`,
      email: 'sqli@test.corp',
      displayName: "O'Reilly'); DROP TABLE dummy; --",
    };

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(sqliPayload),
    });

    // Successfully creates or validates cleanly without SQL injection
    expect([201, 400]).toContain(res.status);
    if (res.status === 201) {
      const created = (await res.json()) as { id: string };
      // Verify fetched displayName retains literal quotes without corruption
      const getRes = await fetch(`${ctx.baseUrl}/api/admin/users/${created.id}`, {
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(getRes.status).toBe(200);
      const user = (await getRes.json()) as { display_name: string };
      expect(user.display_name).toBe(sqliPayload.displayName);
    }
  });
});
