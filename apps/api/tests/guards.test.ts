import { beforeAll, describe, expect, test } from 'bun:test';
import { bearerFor } from '@di-framework/identity/tests/support/clients.ts';
import { useTestDatabase } from '@di-framework/identity/tests/support/database.ts';
import { controlPlane } from '../src/control-plane.ts';
import { AdminApiPolicy, DirectoryApiPolicy } from '../src/guards/api-policies.ts';
import { requiredScope } from '../src/guards/bearer-guard.ts';
import { RequestContext } from '../src/guards/request-context.ts';

const fetchPlane = (request: Request) => controlPlane.fetch(request);
let readToken = '';
let writeToken = '';
let directoryToken = '';

beforeAll(async () => {
  await useTestDatabase();
  readToken = await bearerFor(fetchPlane, ['admin:read']);
  writeToken = await bearerFor(fetchPlane, ['admin:write']);
  directoryToken = await bearerFor(fetchPlane, ['directory:read']);
});

function call(method: string, path: string, token?: string): Promise<Response> {
  const headers = new Headers({ 'content-type': 'application/json' });
  if (token) headers.set('authorization', `Bearer ${token}`);
  const body = method === 'GET' || method === 'DELETE' ? undefined : '{}';
  return controlPlane.fetch(new Request(`https://identity.test${path}`, { method, headers, body }));
}

const ADMIN: Array<[string, string]> = [
  ['GET', '/api/admin/users'],
  ['POST', '/api/admin/users'],
  ['GET', `/api/admin/users/${crypto.randomUUID()}`],
  ['PATCH', `/api/admin/users/${crypto.randomUUID()}`],
  ['DELETE', `/api/admin/users/${crypto.randomUUID()}`],
  ['GET', '/api/admin/organizations'],
  ['POST', '/api/admin/organizations'],
  ['GET', '/api/admin/organizations/acme'],
  ['PATCH', '/api/admin/organizations/acme'],
  ['DELETE', '/api/admin/organizations/acme'],
  ['GET', `/api/admin/organizations/acme/members/${crypto.randomUUID()}`],
  ['PUT', `/api/admin/organizations/acme/members/${crypto.randomUUID()}`],
  ['DELETE', `/api/admin/organizations/acme/members/${crypto.randomUUID()}`],
  ['GET', '/api/admin/oauth-clients'],
  ['POST', '/api/admin/oauth-clients'],
  ['GET', '/api/admin/oauth-clients/x'],
  ['PUT', '/api/admin/oauth-clients/x'],
  ['DELETE', '/api/admin/oauth-clients/x'],
  ['POST', '/api/admin/oauth-clients/x/rotate-secret'],
  ['GET', '/api/admin/audit'],
];

describe('bearer guard', () => {
  test('maps paths and methods to scopes', () => {
    expect(requiredScope('GET', '/api/admin/users')).toBe('admin:read');
    expect(requiredScope('HEAD', '/api/admin')).toBe('admin:read');
    expect(requiredScope('POST', '/api/admin/users')).toBe('admin:write');
    expect(requiredScope('GET', '/api/v1/organizations/acme/members')).toBe('directory:read');
    expect(requiredScope('GET', '/api/v1/account/identity-links')).toBeUndefined();
    expect(RequestContext.current()).toBeUndefined();
    expect(new RequestContext()).toBeDefined();
    RequestContext.run({ kind: 'token', principalName: 'p', clientId: 'c', scopes: [] }, () =>
      expect(RequestContext.current()?.principalName).toBe('p'),
    );
    const adminPolicy = new AdminApiPolicy();
    adminPolicy.read();
    adminPolicy.write();
    const dirPolicy = new DirectoryApiPolicy();
    dirPolicy.read();
    expect(adminPolicy).toBeDefined();
    expect(dirPolicy).toBeDefined();
  });

  test('every admin operation requires a valid token with the right scope', async () => {
    for (const [method, path] of ADMIN) {
      const missing = await call(method, path);
      expect([method, path, missing.status]).toEqual([method, path, 401]);
      expect(missing.headers.get('www-authenticate')).toBe('Bearer');
      expect(await missing.text()).toBe('');
      const invalid = await call(method, path, 'not-a-real-token');
      expect(invalid.status).toBe(401);
      expect(invalid.headers.get('www-authenticate')).toBe('Bearer error="invalid_token"');
      const wrong = await call(method, path, method === 'GET' ? writeToken : readToken);
      expect([method, path, wrong.status]).toEqual([method, path, 403]);
      expect(wrong.headers.get('www-authenticate')).toContain('insufficient_scope');
      const right = await call(method, path, method === 'GET' ? readToken : writeToken);
      expect([method, path, right.status === 401 || right.status === 403]).toEqual([
        method,
        path,
        false,
      ]);
    }
  });

  test('directory members require directory:read', async () => {
    const path = '/api/v1/organizations/nobody/members';
    expect((await call('GET', path)).status).toBe(401);
    expect((await call('GET', path, readToken)).status).toBe(403);
    const allowed = await call('GET', path, directoryToken);
    expect(allowed.status).toBe(200);
    expect(await allowed.json()).toEqual({ items: [], next_cursor: null });
  });

  test('malformed authorization headers are unauthenticated', async () => {
    for (const header of ['Basic abc', 'Bearer', 'Bearer a b']) {
      const response = await controlPlane.fetch(
        new Request('https://identity.test/api/admin/users', {
          headers: { authorization: header },
        }),
      );
      expect(response.status).toBe(401);
    }
  });
});
