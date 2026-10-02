import { describe, expect, test } from 'bun:test';
import { authFailure, createExampleApp } from './app.ts';

const password = 'correct horse battery staple';
const app = createExampleApp({
  secret: 'example-only-secret-not-for-production-use',
  issuer: 'http://127.0.0.1:3000',
});

function call(path: string, init?: RequestInit): Promise<Response> {
  return app.fetch(new Request(`http://127.0.0.1:3000${path}`, init));
}

function cookie(response: Response, name: string): string | undefined {
  return response.headers.getSetCookie().find((header) => header.startsWith(`${name}=`));
}

function attributes(header: string): string[] {
  return header
    .split(';')
    .slice(1)
    .map((part) => part.trim().toLowerCase());
}

function pair(header: string): string {
  return (header.split(';', 1)[0] ?? '').trim();
}

describe('example app journeys', () => {
  test('rejects a short password and does not echo it', async () => {
    const response = await call('/auth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: 'weak@example.com', password: 'too-short' }),
    });
    const text = await response.text();
    expect(response.status).toBe(400);
    expect(text).not.toContain('too-short');
  });

  test('registers, opens /me, rejects a wrong password, and logout revokes the session', async () => {
    const identifier = `person-${Date.now()}@example.com`;
    const registered = await call('/auth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier, password }),
    });
    const registeredText = await registered.text();
    const registeredBody = JSON.parse(registeredText) as { principal?: { sub?: string } };
    const sid = cookie(registered, '__Host-sid');
    expect(registered.ok).toBe(true);
    expect(registeredBody.principal?.sub).toBeTruthy();
    expect(registeredText).not.toContain(password);
    expect(sid).toBeDefined();
    const flags = attributes(sid ?? '');
    expect(flags).toContain('httponly');
    expect(flags).toContain('secure');
    expect(flags).toContain('path=/');
    expect(flags).toContain('samesite=lax');
    expect(flags.some((item) => item.startsWith('domain'))).toBe(false);

    const health = await call('/health');
    expect(await health.json()).toEqual({ ok: true });

    const anonymous = await call('/me');
    expect(anonymous.status).toBe(401);

    const me = await call('/me', { headers: { cookie: pair(sid ?? '') } });
    const meBody = (await me.json()) as { sub?: string };
    expect(me.ok).toBe(true);
    expect(meBody.sub).toBe(registeredBody.principal?.sub);
    expect(me.headers.get('cache-control')).toBe('no-store');

    const forged = await call('/me', { headers: { cookie: '__Host-sid=forged' } });
    expect(forged.status).toBe(401);

    const badPassword = await call('/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier, password: 'not-the-password' }),
    });
    const badText = await badPassword.text();
    expect(badPassword.status).toBe(401);
    expect(cookie(badPassword, '__Host-sid')).toBeUndefined();
    expect(badText).toContain('Invalid credentials');
    expect(badText).not.toContain('Password mismatch');

    const loggedOut = await call('/auth/logout', {
      method: 'POST',
      headers: { cookie: pair(sid ?? ''), 'content-type': 'application/json' },
      body: '{}',
    });
    const cleared = cookie(loggedOut, '__Host-sid');
    expect(loggedOut.status).toBe(204);
    expect(cleared).toBeDefined();
    expect(attributes(cleared ?? '')).toContain('max-age=0');
    const afterLogout = await call('/me', { headers: { cookie: pair(sid ?? '') } });
    expect(afterLogout.status).toBe(401);
  });

  test('an unexpected failure does not return the internal message', async () => {
    const recorded: unknown[] = [];
    const original = console.error;
    console.error = (...args: unknown[]) => {
      recorded.push(args);
    };
    try {
      const leaked = authFailure(new Error('Password mismatch for user secret-id'));
      const safe = authFailure({ status: 401, publicMessage: 'Invalid credentials' });
      const leakedText = await leaked.text();
      const safeText = await safe.text();
      expect(leaked.status).toBe(500);
      expect(recorded).toHaveLength(1);
      expect(leakedText).toContain('Internal Server Error');
      expect(leakedText).not.toContain('Password mismatch');
      expect(leakedText).not.toContain('secret-id');
      expect(safe.status).toBe(401);
      expect(safeText).toContain('Invalid credentials');
      expect(safe.headers.get('cache-control')).toBe('no-store');
    } finally {
      console.error = original;
    }
  });
});
