import { beforeAll, describe, expect, spyOn, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { AuditRepository } from '@di-framework/identity/src/audit/domain/audit-entry.ts';
import type {
  AuthorizationRepository,
  RegisteredClientRepository,
} from '@di-framework/identity/src/authorization/domain/models.ts';
import type { DirectoryRepository } from '@di-framework/identity/src/directory/domain/directory-repository.ts';
import {
  AUDIT,
  AUTHORIZATIONS,
  DIRECTORY,
  REGISTERED_CLIENTS,
} from '@di-framework/identity/src/shared/domain/tokens.ts';
import { Hashing } from '@di-framework/identity/src/shared/infrastructure/crypto/hashing.ts';
import { basic, bearerFor, formRequest } from '@di-framework/identity/tests/support/clients.ts';
import { useTestDatabase } from '@di-framework/identity/tests/support/database.ts';
import type { SqlDatabase } from '@di-framework/repo';
import { controlPlane } from '../src/control-plane.ts';

/**
 * `/api/admin/oauth-clients` for tenant clients (identity-server#48): token audiences, public
 * PKCE clients, the required organization, and keyed creates. Ids carry a random prefix, so
 * the cases share the migrated test database with every other suite.
 */

let database: SqlDatabase;
let adminToken = '';
const prefix = `tenant-${Hashing.token(4)}`;
const ORG = 'acme';
const AUDIENCES = ['https://acme.example', 'api://acme'];

beforeAll(async () => {
  database = await useTestDatabase();
  adminToken = await bearerFor(
    (request) => controlPlane.fetch(request),
    ['admin:read', 'admin:write'],
  );
});

async function call(
  method: string,
  path: string,
  init?: { body?: unknown; headers?: Record<string, string> },
): Promise<{ status: number; body: Record<string, unknown> }> {
  const headers = new Headers(init?.headers);
  headers.set('authorization', `Bearer ${adminToken}`);
  let body: string | undefined;
  if (init && 'body' in init) {
    headers.set('content-type', 'application/json');
    body = JSON.stringify(init.body);
  }
  const response = await controlPlane.fetch(
    new Request(`https://identity.test${path}`, { method, headers, body }),
  );
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : {} };
}

const create = (body: Record<string, unknown>, headers?: Record<string, string>) =>
  call('POST', '/api/admin/oauth-clients', { body, headers });
const read = (clientId: string) => call('GET', `/api/admin/oauth-clients/${clientId}`);

/** A confidential tenant client: client credentials unless `browser` redirects are given. */
function confidential(clientId: string, extra: Record<string, unknown> = {}) {
  return {
    clientId,
    organizationSlug: ORG,
    scopes: ['admin:read'],
    audiences: AUDIENCES,
    ...extra,
  };
}

/** A public native client on a loopback redirect (`tokenEndpointAuthMethod` `none`). */
function publicClient(clientId: string, extra: Record<string, unknown> = {}) {
  return {
    clientId,
    organizationSlug: ORG,
    redirectUris: ['http://127.0.0.1/callback'],
    scopes: ['openid', 'profile'],
    audiences: AUDIENCES,
    tokenEndpointAuthMethod: 'none',
    ...extra,
  };
}

async function introspect(token: string, clientId: string, secret: string) {
  const response = await controlPlane.fetch(
    formRequest('/oauth2/introspect', { token }, { authorization: basic(clientId, secret) }),
  );
  return (await response.json()) as Record<string, unknown>;
}

async function clientCredentials(clientId: string, secret: string, scope: string) {
  const response = await controlPlane.fetch(
    formRequest(
      '/oauth2/token',
      { grant_type: 'client_credentials', scope },
      { authorization: basic(clientId, secret) },
    ),
  );
  return (await response.json()) as { access_token: string };
}

function claims(jwt: string): Record<string, unknown> {
  const [, payload] = jwt.split('.');
  return JSON.parse(Buffer.from(payload ?? '', 'base64url').toString('utf8'));
}

describe('tenant OAuth clients', () => {
  test('registers a confidential client with audiences that its tokens carry', async () => {
    const clientId = `${prefix}-console`;
    const created = await create(
      confidential(clientId, {
        audiences: [' https://acme.example ', 'api://acme', 'api://acme'],
        redirectUris: ['https://acme.example/callback'],
        browser: true,
      }),
    );
    expect(created.status).toBe(201);
    expect(created.body).toEqual({ client_id: clientId, client_secret: expect.any(String) });
    expect(await read(clientId)).toEqual({
      status: 200,
      body: {
        client_id: clientId,
        organization_slug: ORG,
        redirect_uris: ['https://acme.example/callback'],
        scopes: ['admin:read'],
        audiences: AUDIENCES,
        browser: true,
        token_endpoint_auth_method: 'client_secret_basic',
        revoked_at: null,
        created_at: expect.any(String),
      },
    });
    expect((await call('GET', '/api/admin/oauth-clients')).body).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ client_id: clientId, audiences: AUDIENCES }),
      ]),
    );

    const machineId = `${prefix}-machine`;
    const machine = await create(confidential(machineId));
    const secret = String(machine.body.client_secret);
    const issued = await clientCredentials(machineId, secret, 'admin:read');
    expect(await introspect(issued.access_token, machineId, secret)).toMatchObject({
      active: true,
      client_id: machineId,
      aud: AUDIENCES,
    });

    const plainId = `${prefix}-plain`;
    const plain = await create(confidential(plainId, { audiences: [] }));
    const plainSecret = String(plain.body.client_secret);
    const plainToken = await clientCredentials(plainId, plainSecret, 'admin:read');
    expect(await introspect(plainToken.access_token, plainId, plainSecret)).toMatchObject({
      aud: [plainId],
    });

    const updated = await call('PUT', `/api/admin/oauth-clients/${plainId}`, {
      body: confidential(plainId, { audiences: ['https://acme.example'] }),
    });
    expect(updated.body).toMatchObject({ audiences: ['https://acme.example'], browser: false });
    const afterUpdate = await clientCredentials(plainId, plainSecret, 'admin:read');
    expect(await introspect(afterUpdate.access_token, plainId, plainSecret)).toMatchObject({
      aud: ['https://acme.example'],
    });
  });

  test('a bootstrap-style client gets audiences through the registered client repository', async () => {
    const clients = useContainer().resolve<RegisteredClientRepository>(REGISTERED_CLIENTS);
    const clientId = `${prefix}-bootstrap`;
    const secret = Hashing.token();
    await clients.insert({
      clientId,
      clientName: clientId,
      secretHash: await Bun.password.hash(secret, { algorithm: 'argon2id' }),
      authenticationMethods: ['client_secret_basic'],
      grantTypes: ['client_credentials'],
      redirectUris: [],
      scopes: ['admin:read'],
      settings: { requireProofKey: false, requireAuthorizationConsent: false },
      organizationSlug: null,
    });
    expect((await clients.find(clientId))?.audiences).toEqual([]);
    await clients.update(clientId, { audiences: ['https://platform.example'] });
    expect((await clients.find(clientId))?.audiences).toEqual(['https://platform.example']);
    const issued = await clientCredentials(clientId, secret, 'admin:read');
    expect(await introspect(issued.access_token, clientId, secret)).toMatchObject({
      aud: ['https://platform.example'],
    });
    await clients.update(clientId, { scopes: ['admin:read'], audiences: [] });
    expect((await clients.find(clientId))?.audiences).toEqual([]);
  });

  test('registers a public PKCE client on loopback redirects without a secret', async () => {
    const clientId = `${prefix}-cli`;
    const created = await create(publicClient(clientId));
    expect(created.status).toBe(201);
    expect(created.body).toEqual({ client_id: clientId });
    expect((await read(clientId)).body).toMatchObject({
      browser: true,
      audiences: AUDIENCES,
      token_endpoint_auth_method: 'none',
    });
    const [row] = await database.query<{
      client_secret: string | null;
      client_authentication_methods: string;
      authorization_grant_types: string;
      client_settings: string;
    }>(
      `SELECT client_secret, client_authentication_methods, authorization_grant_types, client_settings
       FROM oauth2_registered_client WHERE client_id = ?`,
      [clientId],
    );
    expect(row).toMatchObject({
      client_secret: null,
      client_authentication_methods: 'none',
      authorization_grant_types: 'authorization_code,refresh_token',
    });
    expect(JSON.parse(row?.client_settings ?? '{}')).toEqual({
      requireProofKey: true,
      requireAuthorizationConsent: true,
    });

    // No secret to rotate, and the auth method is fixed at registration.
    const rotate = await call('POST', `/api/admin/oauth-clients/${clientId}/rotate-secret`, {
      body: { version: 'v2' },
    });
    expect(rotate.status).toBe(409);
    const confidentialAgain = await call('PUT', `/api/admin/oauth-clients/${clientId}`, {
      body: publicClient(clientId, { tokenEndpointAuthMethod: 'client_secret_basic' }),
    });
    expect(confidentialAgain.status).toBe(409);
    const { tokenEndpointAuthMethod: _omitted, ...withoutMethod } = publicClient(clientId, {
      audiences: ['https://cli.acme.example'],
      redirectUris: ['http://[::1]/cb', 'http://127.0.0.1/cb'],
    });
    const updated = await call('PUT', `/api/admin/oauth-clients/${clientId}`, {
      body: withoutMethod,
    });
    expect(updated.status).toBe(200);
    expect(updated.body).toMatchObject({
      audiences: ['https://cli.acme.example'],
      redirect_uris: ['http://[::1]/cb', 'http://127.0.0.1/cb'],
      token_endpoint_auth_method: 'none',
    });
    for (const redirectUris of [[], ['https://cli.acme.example/cb'], ['http://localhost/cb']]) {
      const refused = await call('PUT', `/api/admin/oauth-clients/${clientId}`, {
        body: publicClient(clientId, { redirectUris }),
      });
      expect(refused.status).toBe(400);
    }
  });

  test('a public client exchanges a code with PKCE for tokens whose ID token names the audiences', async () => {
    const clientId = `${prefix}-native`;
    expect(
      (await create(publicClient(clientId, { audiences: ['https://acme.example'] }))).status,
    ).toBe(201);
    const registered = await useContainer()
      .resolve<RegisteredClientRepository>(REGISTERED_CLIENTS)
      .find(clientId);
    const userId = crypto.randomUUID();
    await useContainer()
      .resolve<DirectoryRepository>(DIRECTORY)
      .insertAccount({
        id: userId,
        login: `native-${userId.slice(0, 8)}`,
        email: `native-${userId.slice(0, 8)}@example.com`,
        displayName: 'Native User',
        passwordHash: null,
        emailVerified: true,
        systemRole: 'user',
        status: 'active',
      });
    const verifier = Hashing.token();
    const code = Hashing.token();
    const redirect = 'http://127.0.0.1:50123/callback';
    const now = Date.now();
    await useContainer()
      .resolve<AuthorizationRepository>(AUTHORIZATIONS)
      .save({
        id: crypto.randomUUID(),
        registeredClientId: registered?.id ?? '',
        principalName: userId,
        grantType: 'authorization_code',
        authorizedScopes: ['openid', 'profile'],
        attributes: {
          redirect_uri: redirect,
          requested_redirect_uri: redirect,
          code_challenge: Hashing.pkceChallenge(verifier),
          nonce: null,
          auth_time: now,
        },
        state: null,
        code: {
          hash: Hashing.sha256Hex(code),
          issuedAt: now,
          expiresAt: now + 60_000,
          invalidated: false,
        },
        access: null,
        refresh: null,
        idToken: null,
      });
    const exchanged = await controlPlane.fetch(
      formRequest('/oauth2/token', {
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: redirect,
        code_verifier: verifier,
      }),
    );
    expect(exchanged.status).toBe(200);
    const tokens = (await exchanged.json()) as { id_token: string; refresh_token?: string };
    expect(tokens.refresh_token).toBeDefined();
    expect(claims(tokens.id_token)).toMatchObject({
      sub: userId,
      aud: [clientId, 'https://acme.example'],
      azp: clientId,
    });
  });

  test('requires the tenant organization and refuses bad metadata', async () => {
    const clientId = `${prefix}-invalid`;
    const refused = async (body: Record<string, unknown>) => (await create(body)).status;
    expect(await refused({ clientId })).toBe(400);
    expect(await refused({ clientId, organizationSlug: ' ' })).toBe(400);
    expect(await refused({ clientId, organizationSlug: 'o'.repeat(129) })).toBe(400);
    expect(
      await refused(confidential(clientId, { tokenEndpointAuthMethod: 'client_secret_post' })),
    ).toBe(400);
    expect(
      await refused(confidential(clientId, { audiences: ['https://acme.example', 'a b'] })),
    ).toBe(400);
    expect(await refused(confidential(clientId, { audiences: ['a,b'] }))).toBe(400);
    expect(
      await refused(confidential(clientId, { audiences: ['x'.repeat(600), 'y'.repeat(600)] })),
    ).toBe(400);
    expect(await refused(publicClient(clientId, { redirectUris: [] }))).toBe(400);
    expect(
      await refused(publicClient(clientId, { redirectUris: ['https://acme.example/cb'] })),
    ).toBe(400);
    expect(await refused(publicClient(clientId, { redirectUris: ['not a url'] }))).toBe(400);
    expect((await read(clientId)).status).toBe(404);

    const existing = `${prefix}-existing`;
    expect((await create(confidential(existing))).status).toBe(201);
    const noOrganization = await call('PUT', `/api/admin/oauth-clients/${existing}`, {
      body: { scopes: ['openid'] },
    });
    expect(noOrganization.status).toBe(400);
    const badMethod = await call('PUT', `/api/admin/oauth-clients/${existing}`, {
      body: confidential(existing, { tokenEndpointAuthMethod: 'none' }),
    });
    expect(badMethod.status).toBe(409);
  });

  test('replays a keyed create, refuses the key for another client, and keeps revoked ids', async () => {
    const clientId = `${prefix}-keyed`;
    const key = `${clientId}-create`;
    const first = await create(publicClient(clientId), { 'idempotency-key': key });
    expect(first.status).toBe(201);
    expect(await create(publicClient(clientId), { 'idempotency-key': key })).toEqual(first);
    const other = publicClient(clientId, { audiences: ['https://other.example'] });
    expect((await create(other, { 'idempotency-key': key })).status).toBe(409);
    expect((await create(confidential(clientId), { 'idempotency-key': key })).status).toBe(409);
    expect((await create(publicClient(clientId))).status).toBe(409);
    expect((await call('DELETE', `/api/admin/oauth-clients/${clientId}`)).status).toBe(204);
    expect((await read(clientId)).body.revoked_at).toEqual(expect.any(String));
    expect((await create(publicClient(clientId))).status).toBe(409);
  });

  test('writes the idempotency record with the client, so a racing keyed create replays', async () => {
    const clientId = `${prefix}-raced`;
    const key = `${clientId}-create`;
    const audit = useContainer().resolve<AuditRepository>(AUDIT);
    const append = audit.append.bind(audit);
    let held = false;
    let reached!: () => void;
    const reachedGate = new Promise<void>((resolve) => {
      reached = resolve;
    });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    // The first create pauses between inserting the client and writing its idempotency record.
    const paused = spyOn(audit, 'append').mockImplementation(async (entry) => {
      if (!held && entry.action === 'admin.oauth_client_created' && entry.target === clientId) {
        held = true;
        reached();
        await gate;
      }
      return append(entry);
    });
    try {
      const first = create(confidential(clientId), { 'idempotency-key': key });
      await reachedGate;
      // Meanwhile a second keyed create finds no record and runs into the client's unique index.
      const second = create(confidential(clientId), { 'idempotency-key': key });
      await Bun.sleep(100);
      release();
      const [a, b] = await Promise.all([first, second]);
      expect(a.status).toBe(201);
      expect(a.body.client_secret).toEqual(expect.any(String));
      expect(b).toEqual(a);
    } finally {
      paused.mockRestore();
    }
  });
});
