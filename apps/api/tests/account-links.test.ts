import { beforeAll, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type {
  AuthorizationRepository,
  RegisteredClientRepository,
} from '@di-framework/identity/src/authorization/domain/models.ts';
import type { DirectoryRepository } from '@di-framework/identity/src/directory/domain/directory-repository.ts';
import type { LinkRepository } from '@di-framework/identity/src/linking/domain/identity-link.ts';
import { SessionService } from '@di-framework/identity/src/sessions/application/session-service.ts';
import {
  AUTHORIZATIONS,
  DIRECTORY,
  LINKS,
  REGISTERED_CLIENTS,
} from '@di-framework/identity/src/shared/domain/tokens.ts';
import { Hashing } from '@di-framework/identity/src/shared/infrastructure/crypto/hashing.ts';
import { registerClient } from '@di-framework/identity/tests/support/clients.ts';
import { useTestDatabase } from '@di-framework/identity/tests/support/database.ts';
import { controlPlane } from '../src/control-plane.ts';
import { cookieValue } from '../src/guards/account-guard.ts';

let userId = '';
let cookie = '';
let bearer = '';
const subject = `api-subject-${crypto.randomUUID()}`;

beforeAll(async () => {
  await useTestDatabase();
  userId = crypto.randomUUID();
  await useContainer()
    .resolve<DirectoryRepository>(DIRECTORY)
    .insertAccount({
      id: userId,
      login: `api-${userId.slice(0, 8)}`,
      email: `api-${userId.slice(0, 8)}@example.com`,
      displayName: 'Api',
      passwordHash: null,
      emailVerified: true,
      systemRole: 'user',
      status: 'active',
    });
  await useContainer().resolve<LinkRepository>(LINKS).insert({
    id: crypto.randomUUID(),
    userId,
    issuer: 'https://idp.example',
    subject,
    providerName: 'Example',
    providerEmail: null,
  });
  const sessions = useContainer().resolve(SessionService);
  const signed = await sessions.signIn(await sessions.start(), userId, true);
  cookie = `other=1; identity_session=${signed.token}`;
  const client = await registerClient({ grantTypes: ['authorization_code'], scopes: ['openid'] });
  const registered = await useContainer()
    .resolve<RegisteredClientRepository>(REGISTERED_CLIENTS)
    .find(client.clientId);
  bearer = Hashing.token();
  await useContainer()
    .resolve<AuthorizationRepository>(AUTHORIZATIONS)
    .save({
      id: crypto.randomUUID(),
      registeredClientId: registered?.id ?? '',
      principalName: userId,
      grantType: 'authorization_code',
      authorizedScopes: ['openid'],
      attributes: {},
      state: null,
      code: null,
      access: {
        hash: Hashing.sha256Hex(bearer),
        issuedAt: Date.now(),
        expiresAt: Date.now() + 60_000,
        invalidated: false,
        scopes: ['openid'],
      },
      refresh: null,
      idToken: null,
    });
});

function call(method: string, path: string, headers: Record<string, string> = {}) {
  return controlPlane.fetch(new Request(`https://identity.test${path}`, { method, headers }));
}

test('account routes need a session cookie or a user bearer token', async () => {
  expect((await call('GET', '/api/v1/account/identity-links')).status).toBe(401);
  expect(
    (await call('GET', '/api/v1/account/identity-links', { cookie: 'identity_session=nope' }))
      .status,
  ).toBe(401);
  expect(
    (await call('GET', '/api/v1/account/identity-links', { authorization: 'Bearer nope' })).status,
  ).toBe(401);
  expect(
    (await call('GET', '/api/v1/account/identity-links', { authorization: 'Basic x' })).status,
  ).toBe(401);
  const viaBearer = await call('GET', '/api/v1/account/identity-links', {
    authorization: `Bearer ${bearer}`,
  });
  expect(viaBearer.status).toBe(200);
  expect(await viaBearer.json()).toEqual([expect.objectContaining({ providerName: 'Example' })]);
  const prepareWithBearer = await call(
    'POST',
    `/api/v1/account/identity-links/unlink/prepare?issuer=https://idp.example&subject=${subject}`,
    { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' },
  );
  expect(prepareWithBearer.status).toBe(403);
  expect(cookieValue('a=1; broken; identity_session=x', 'identity_session')).toBe('x');
  expect(cookieValue(null, 'identity_session')).toBeUndefined();
});

test('a recently signed-in session prepares and confirms an unlink, revoking tokens', async () => {
  const list = await call('GET', '/api/v1/account/identity-links', { cookie });
  expect(list.status).toBe(200);
  const prepared = await call(
    'POST',
    `/api/v1/account/identity-links/unlink/prepare?issuer=${encodeURIComponent('https://IDP.example/')}&subject=${subject}`,
    { cookie, 'content-type': 'application/json' },
  );
  expect(prepared.status).toBe(200);
  const { confirmation_token: token } = (await prepared.json()) as { confirmation_token: string };
  const removed = await call(
    'DELETE',
    `/api/v1/account/identity-links?issuer=https://idp.example&subject=${subject}&confirmationToken=${token}`,
    { cookie },
  );
  expect(removed.status).toBe(200);
  expect(await removed.json()).toEqual({
    unlinked: true,
    issuer: 'https://idp.example',
    subject_hint: Hashing.sha256Hex(subject).slice(0, 16),
  });
  expect(
    (await call('GET', '/api/v1/account/identity-links', { authorization: `Bearer ${bearer}` }))
      .status,
  ).toBe(401);
});
