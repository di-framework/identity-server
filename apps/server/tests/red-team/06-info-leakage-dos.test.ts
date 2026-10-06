import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { type RedTeamContext, setupRedTeamServer } from './red-team-harness.ts';

describe('Red-Team Category 6: Information Disclosure & DoS Resilience', () => {
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

  test('Operations Metadata: /health and /ready do not disclose credentials or infrastructure details', async () => {
    // 1. /health check
    const healthRes = await fetch(`${ctx.baseUrl}/health`);
    expect(healthRes.status).toBe(200);
    const healthBody = (await healthRes.json()) as { ok: boolean };
    expect(healthBody).toEqual({ ok: true });

    // 2. /ready check
    const readyRes = await fetch(`${ctx.baseUrl}/ready`);
    expect([200, 503]).toContain(readyRes.status);
    const readyBody = (await readyRes.json()) as Record<string, unknown>;
    // Ensure body only contains boolean keys, no db host or credentials
    for (const [_key, value] of Object.entries(readyBody)) {
      expect(typeof value).toBe('boolean');
    }
  });

  test('OIDC Discovery: Endpoints advertise public origin without leaking internal addresses', async () => {
    const res = await fetch(`${ctx.baseUrl}/.well-known/openid-configuration`);
    expect(res.status).toBe(200);
    const config = (await res.json()) as {
      issuer: string;
      authorization_endpoint: string;
      token_endpoint: string;
      jwks_uri: string;
    };

    expect(config.issuer).toBe(ctx.settings.publicOrigin);
    expect(config.authorization_endpoint.startsWith(ctx.settings.publicOrigin)).toBe(true);
    expect(config.token_endpoint.startsWith(ctx.settings.publicOrigin)).toBe(true);
    expect(config.jwks_uri.startsWith(ctx.settings.publicOrigin)).toBe(true);
    // Should not leak local IP addresses or internal docker aliases
    expect(JSON.stringify(config)).not.toContain('127.0.0.1');
    expect(JSON.stringify(config)).not.toContain('identity-postgres');
  });

  test('Error Sanitization: Bad JSON payloads return clean 400 without leaking stack traces or internal paths', async () => {
    const malformedJson = '{ "login": "test", broken: json here }';

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
      },
      body: malformedJson,
    });
    // Server should reject bad JSON with 400
    expect(res.status).toBe(400);
    const text = await res.text();
    // Verify no internal file paths or node stack traces are exposed
    expect(text).not.toContain('/Volumes/safe-vol');
    expect(text).not.toContain('at async');
    expect(text).not.toContain('node_modules');
  });

  test('Pagination Boundaries: Extreme or negative limits are bounded without crash or memory exhaustion', async () => {
    const boundaryLimits = ['-1', '0', '999999999', 'NaN', '1e6'];

    for (const limit of boundaryLimits) {
      const res = await fetch(
        `${ctx.baseUrl}/api/v1/organizations/${ctx.fixtures.orgAlpha.slug}/members?limit=${limit}`,
        {
          headers: { authorization: `Bearer ${adminToken}` },
        },
      );
      // Endpoint should either return 200 with clamped results or 400 bad request, never 500
      expect([200, 400]).toContain(res.status);
    }
  });

  test('Oversized Payload Handling: Abnormally large payloads do not crash the server', async () => {
    // 2MB string payload
    const largeString = 'A'.repeat(2 * 1024 * 1024);
    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        login: 'large-user',
        email: 'large@test.corp',
        displayName: largeString,
      }),
    });
    // Should reject or handle without hanging or crashing; body must not leak DB exception details
    expect([400, 413]).toContain(res.status);
    const body = await res.text();
    expect(body.toLowerCase()).not.toContain('character varying');
    expect(body.toLowerCase()).not.toContain('postgresql');

    // Verify server is still completely responsive
    const ping = await fetch(`${ctx.baseUrl}/health`);
    expect(ping.status).toBe(200);
  });
});
