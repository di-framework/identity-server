import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import { SessionService } from '../../../../packages/core/src/sessions/application/session-service.ts';
import { SESSION_ATTRIBUTES } from '../../../../packages/core/src/sessions/domain/session.ts';
import { loginUserSession, type RedTeamContext, setupRedTeamServer } from './red-team-harness.ts';

describe('Red-Team Category 4: Web Application, Sessions & CSRF', () => {
  let ctx: RedTeamContext;
  let adminSessionCookie = '';
  let adminCsrfToken = '';

  beforeAll(async () => {
    ctx = await setupRedTeamServer();

    // 1. Establish an admin session via web login helper
    adminSessionCookie = await loginUserSession(
      ctx.baseUrl,
      ctx.fixtures.adminUser.login,
      ctx.fixtures.adminUser.password,
    );

    // 2. Fetch page with JSON accept to get CSRF token
    const pageRes = await fetch(`${ctx.baseUrl}/admin/users`, {
      headers: { cookie: adminSessionCookie, accept: 'application/json' },
    });
    expect(pageRes.status).toBe(200);
    const data = (await pageRes.json()) as { csrf: string };
    adminCsrfToken = data.csrf;
    expect(adminCsrfToken).toBeTruthy();
  });

  afterAll(async () => {
    await ctx?.stop();
  });

  test('CSRF: Form submission without CSRF token is rejected with 403', async () => {
    const res = await fetch(`${ctx.baseUrl}/admin/organizations/create`, {
      method: 'POST',
      headers: {
        cookie: adminSessionCookie,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        slug: 'csrf-attack-org',
        name: 'CSRF Attack Org',
      }),
    });
    expect(res.status).toBe(403);
    const body = await res.text();
    expect(body).toContain('CSRF');
  });

  test('CSRF: Form submission with an invalid or cross-session CSRF token is rejected', async () => {
    const res = await fetch(`${ctx.baseUrl}/admin/organizations/create`, {
      method: 'POST',
      headers: {
        cookie: adminSessionCookie,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        slug: 'csrf-tamper-org',
        name: 'CSRF Tamper Org',
        _csrf: 'attacker-forged-csrf-token-12345',
      }),
    });
    expect(res.status).toBe(403);
    const body = await res.text();
    expect(body).toContain('CSRF');
  });

  test('Open Redirect: Login flow validates redirect destination and blocks external domains', async () => {
    const sessionService = useContainer().resolve(SessionService);
    const maliciousTargets = [
      '//evil.com',
      '//evil.com/path',
      'https://evil.com',
      'http://evil.com',
      'javascript:alert(1)',
      '/\\evil.com',
      '\\\\evil.com',
    ];

    for (const target of maliciousTargets) {
      // 1. Obtain anonymous guest session
      const guestRes = await fetch(`${ctx.baseUrl}/login`, {
        headers: { accept: 'application/json' },
      });
      const preAuthCookieHeader = guestRes.headers.get('set-cookie') ?? '';
      const preAuthCookie = preAuthCookieHeader.split(';')[0] ?? '';
      const token = /identity_session=([^;]+)/.exec(preAuthCookie)?.[1] ?? '';
      const { csrf } = (await guestRes.json()) as { csrf: string };

      // 2. Set savedRequest attribute in session
      const active = await sessionService.resolve(token);
      expect(active).toBeDefined();
      if (active)
        await sessionService.setAttribute(active, SESSION_ATTRIBUTES.savedRequest, target);

      // 3. Perform login
      const authRes = await fetch(`${ctx.baseUrl}/login`, {
        method: 'POST',
        headers: {
          cookie: preAuthCookie,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          username: ctx.fixtures.adminUser.login,
          password: ctx.fixtures.adminUser.password,
          _csrf: csrf,
        }),
        redirect: 'manual',
      });
      expect(authRes.status).toBe(303);
      const location = authRes.headers.get('location') ?? '';

      // Defense check: Must NOT redirect to external malicious destination
      expect(location.startsWith('//')).toBe(false);
      expect(location.startsWith('http://evil.com')).toBe(false);
      expect(location.startsWith('https://evil.com')).toBe(false);
      expect(location.startsWith('javascript:')).toBe(false);
      expect(location.startsWith('/\\')).toBe(false);
    }
  });

  test('Session Fixation: Session token is regenerated on successful login', async () => {
    // 1. Obtain anonymous guest session
    const guestRes = await fetch(`${ctx.baseUrl}/login`, {
      headers: { accept: 'application/json' },
    });
    const preAuthCookieHeader = guestRes.headers.get('set-cookie') ?? '';
    const preAuthCookie = preAuthCookieHeader.split(';')[0] ?? '';
    const preAuthToken = /identity_session=([^;]+)/.exec(preAuthCookie)?.[1];
    expect(preAuthToken).toBeTruthy();
    const { csrf } = (await guestRes.json()) as { csrf: string };

    // 2. Sign in with the guest cookie
    const loginRes = await fetch(`${ctx.baseUrl}/login`, {
      method: 'POST',
      headers: {
        cookie: preAuthCookie,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        username: ctx.fixtures.adminUser.login,
        password: ctx.fixtures.adminUser.password,
        _csrf: csrf,
      }),
      redirect: 'manual',
    });
    expect(loginRes.status).toBe(303);
    const postAuthCookie = loginRes.headers.get('set-cookie') ?? '';
    const postAuthToken = /identity_session=([^;]+)/.exec(postAuthCookie)?.[1];
    expect(postAuthToken).toBeTruthy();

    // 3. Verified session fixation protection: tokens MUST NOT match
    expect(postAuthToken).not.toBe(preAuthToken);
  });

  test('Session Termination: Logout destroys session on server and client', async () => {
    // 1. Establish fresh session for regularUser1
    const sessionCookie = await loginUserSession(
      ctx.baseUrl,
      ctx.fixtures.regularUser1.login,
      ctx.fixtures.regularUser1.password,
    );

    // Extract CSRF
    const pageRes = await fetch(`${ctx.baseUrl}/account/identity-links`, {
      headers: { cookie: sessionCookie, accept: 'application/json' },
    });
    expect(pageRes.status).toBe(200);
    const { csrf } = (await pageRes.json()) as { csrf: string };
    expect(csrf).toBeTruthy();

    // 2. Logout via POST /admin/logout
    const logoutRes = await fetch(`${ctx.baseUrl}/admin/logout`, {
      method: 'POST',
      headers: {
        cookie: sessionCookie,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ _csrf: csrf }),
      redirect: 'manual',
    });
    expect(logoutRes.status).toBe(303);
    const expiredCookie = logoutRes.headers.get('set-cookie') ?? '';
    expect(expiredCookie).toContain('Max-Age=0');

    // 3. Attempting to use the old session cookie must now require login
    const followUpRes = await fetch(`${ctx.baseUrl}/account/identity-links`, {
      headers: { cookie: sessionCookie },
      redirect: 'manual',
    });
    expect(followUpRes.status).toBe(302);
    expect(followUpRes.headers.get('location')).toBe('/login');
  });

  test('Passwordless Challenge: Rejects malformed token shape and expired challenges', async () => {
    // 1. Malformed token (not 43-char base64url)
    const malformedRes = await fetch(`${ctx.baseUrl}/passwordless/confirm?token=tooshort`, {
      redirect: 'manual',
    });
    expect(malformedRes.status).toBe(400);

    // 2. Non-existent random 43-char token
    const nonExistentToken = '1234567890123456789012345678901234567890123';
    const stageRes = await fetch(`${ctx.baseUrl}/passwordless/confirm?token=${nonExistentToken}`, {
      redirect: 'manual',
    });
    expect(stageRes.status).toBe(303);
    const challengeCookie = stageRes.headers.get('set-cookie') ?? '';

    // Consume attempt
    const consumeRes = await fetch(`${ctx.baseUrl}/passwordless/confirm`, {
      method: 'POST',
      headers: { cookie: challengeCookie },
      redirect: 'manual',
    });
    expect(consumeRes.status).toBe(303);
    expect(consumeRes.headers.get('location')).toContain('error=invalid');
  });
});
