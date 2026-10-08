import { beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import { UserClaims } from '@di-framework/identity/src/authorization/application/claims.ts';
import type { ClientAuthenticator } from '@di-framework/identity/src/authorization/application/client-authenticator.ts';
import { Introspector } from '@di-framework/identity/src/authorization/application/introspector.ts';
import { ServerMetadata } from '@di-framework/identity/src/authorization/application/server-metadata.ts';
import { TokenService } from '@di-framework/identity/src/authorization/application/token-service.ts';
import type {
  Authorization,
  AuthorizationRepository,
  RegisteredClientRepository,
} from '@di-framework/identity/src/authorization/domain/models.ts';
import { ClientColumns } from '@di-framework/identity/src/authorization/infrastructure/postgres-registered-client-repository.ts';
import type { DirectoryRepository } from '@di-framework/identity/src/directory/domain/directory-repository.ts';
import type { OAuthRepository } from '@di-framework/identity/src/oauth/domain/oauth-client.ts';
import {
  AUTHORIZATIONS,
  DIRECTORY,
  OAUTH,
  REGISTERED_CLIENTS,
} from '@di-framework/identity/src/shared/domain/tokens.ts';
import { Hashing } from '@di-framework/identity/src/shared/infrastructure/crypto/hashing.ts';
import { SigningKeys } from '@di-framework/identity/src/shared/infrastructure/crypto/signing-keys.ts';
import { loadIdentitySettings } from '@di-framework/identity/src/shared/infrastructure/identity-settings.ts';
import {
  basic,
  formRequest,
  registerClient,
} from '@di-framework/identity/tests/support/clients.ts';
import { useTestDatabase } from '@di-framework/identity/tests/support/database.ts';
import { akpPrivateJwk } from '@di-framework/identity/tests/support/keys.ts';
import type { SqlDatabase } from '@di-framework/repo';
import { AuthorizationEndpoints } from '../src/authorization/endpoints.ts';
import { controlPlane } from '../src/control-plane.ts';

let database: SqlDatabase;
const authorizations = () => useContainer().resolve<AuthorizationRepository>(AUTHORIZATIONS);
const clients = () => useContainer().resolve<RegisteredClientRepository>(REGISTERED_CLIENTS);

beforeAll(async () => {
  database = await useTestDatabase();
});

async function token(form: Record<string, string>, headers: Record<string, string> = {}) {
  const response = await controlPlane.fetch(formRequest('/oauth2/token', form, headers));
  return { response, body: (await response.json()) as Record<string, unknown> };
}

function authorizationFor(
  registeredClientId: string,
  overrides: Partial<Authorization> = {},
): Authorization {
  return {
    id: crypto.randomUUID(),
    registeredClientId,
    principalName: 'principal',
    grantType: 'client_credentials',
    authorizedScopes: ['admin:read'],
    attributes: {},
    state: null,
    code: null,
    access: null,
    refresh: null,
    idToken: null,
    ...overrides,
  };
}

describe('discovery and keys', () => {
  test('publishes issuer-based metadata, the configured algorithm, and public JWKS', async () => {
    const openid = (await (
      await controlPlane.fetch(
        new Request('https://identity.test/.well-known/openid-configuration'),
      )
    ).json()) as Record<string, unknown>;
    expect(openid).toMatchObject({
      issuer: 'https://identity.test',
      authorization_endpoint: 'https://identity.test/oauth2/authorize',
      token_endpoint: 'https://identity.test/oauth2/token',
      jwks_uri: 'https://identity.test/oauth2/jwks',
      userinfo_endpoint: 'https://identity.test/userinfo',
      introspection_endpoint: 'https://identity.test/oauth2/introspect',
      revocation_endpoint: 'https://identity.test/oauth2/revoke',
      id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    });
    const server = (await (
      await controlPlane.fetch(
        new Request('https://identity.test/.well-known/oauth-authorization-server'),
      )
    ).json()) as Record<string, unknown>;
    expect(server.issuer).toBe('https://identity.test');
    expect(server).not.toHaveProperty('userinfo_endpoint');
    const jwks = (await (
      await controlPlane.fetch(new Request('https://identity.test/oauth2/jwks'))
    ).json()) as { keys: Array<Record<string, unknown>> };
    expect(jwks.keys[0]).toMatchObject({ kid: 'test-active', kty: 'RSA', alg: 'RS256' });
    expect(jwks.keys[0]).not.toHaveProperty('d');
  });

  test('advertises ML-DSA-65 when that algorithm is configured', () => {
    const settings = loadIdentitySettings({ ISSUER_URL: 'https://pq.example' });
    const keys = SigningKeys.load({
      activePrivate: JSON.stringify(akpPrivateJwk('pq')),
      previousPublicSet: '',
      signingAlgorithm: 'ML-DSA-65',
    });
    const metadata = new ServerMetadata(settings, keys);
    expect(metadata.openidConfiguration().id_token_signing_alg_values_supported).toEqual([
      'ML-DSA-65',
    ]);
    expect((metadata.jwks() as { keys: Array<{ kty: string }> }).keys[0]?.kty).toBe('AKP');
  });

  test('rejects wrong methods, unknown paths, and unexpected failures', async () => {
    expect(
      (await controlPlane.fetch(new Request('https://identity.test/oauth2/token'))).status,
    ).toBe(405);
    expect(
      (
        await controlPlane.fetch(
          new Request('https://identity.test/oauth2/jwks', { method: 'POST' }),
        )
      ).headers.get('allow'),
    ).toBe('GET');
    const endpoints = useContainer().resolve(AuthorizationEndpoints);
    expect((await endpoints.fetch(new Request('https://identity.test/oauth2/nope'))).status).toBe(
      404,
    );
    const failing = new AuthorizationEndpoints(
      {
        authenticate: async () => {
          throw new Error('database down');
        },
      } as unknown as ClientAuthenticator,
      useContainer().resolve(TokenService),
      useContainer().resolve(Introspector),
      useContainer().resolve(ServerMetadata),
      useContainer().resolve(UserClaims),
    );
    const response = await failing.fetch(formRequest('/oauth2/token', {}));
    expect(response.status).toBe(500);
    expect(await response.text()).toBe('');
    expect(controlPlane.handles('/oauth2/token')).toBe(true);
    expect(controlPlane.handles('/api/admin/users')).toBe(true);
    expect(controlPlane.handles('/login')).toBe(false);
  });
});

describe('token endpoint', () => {
  test('client_credentials with Basic and post authentication issues opaque tokens', async () => {
    const client = await registerClient({ scopes: ['admin:read', 'admin:write'] });
    const viaBasic = await token(
      { grant_type: 'client_credentials', scope: 'admin:read admin:read' },
      { authorization: client.basic },
    );
    expect(viaBasic.response.status).toBe(200);
    expect(viaBasic.response.headers.get('cache-control')).toBe('no-store');
    expect(viaBasic.body).toEqual({
      access_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      token_type: 'Bearer',
      expires_in: 600,
      scope: 'admin:read',
    });
    const stored = await database.query<{ access_token_value: string; principal_name: string }>(
      `SELECT access_token_value, principal_name FROM oauth2_authorization WHERE access_token_value = ?`,
      [Hashing.sha256Hex(String(viaBasic.body.access_token))],
    );
    expect(stored[0]?.principal_name).toBe(client.clientId);

    const viaPost = await token({
      grant_type: 'client_credentials',
      client_id: client.clientId,
      client_secret: client.secret,
    });
    expect(viaPost.response.status).toBe(200);
    expect(viaPost.body).not.toHaveProperty('scope');
  });

  test('client authentication failures are invalid_client with 401', async () => {
    const client = await registerClient({ methods: ['client_secret_basic'] });
    const revoked = await registerClient();
    await useContainer().resolve<OAuthRepository>(OAUTH).revoke(revoked.clientId);
    const cases: Array<[Record<string, string>, Record<string, string>]> = [
      [{ grant_type: 'client_credentials' }, { authorization: basic(client.clientId, 'wrong') }],
      [{ grant_type: 'client_credentials' }, { authorization: basic('missing-client', 'x') }],
      [
        {
          grant_type: 'client_credentials',
          client_id: client.clientId,
          client_secret: client.secret,
        },
        {},
      ],
      [{ grant_type: 'client_credentials' }, { authorization: revoked.basic }],
      [{ grant_type: 'client_credentials' }, { authorization: `Basic ${btoa('no-colon')}` }],
      [{ grant_type: 'client_credentials' }, { authorization: `Basic ${btoa('%E0%A4%A:x')}` }],
      [{ grant_type: 'client_credentials', client_id: client.clientId }, {}],
    ];
    for (const [form, headers] of cases) {
      const result = await token(form, headers);
      expect(result.response.status).toBe(401);
      expect(result.body).toEqual({ error: 'invalid_client' });
    }
  });

  test('grant and scope errors', async () => {
    const machine = await registerClient({ scopes: ['admin:read'] });
    const browser = await registerClient({
      grantTypes: ['authorization_code', 'refresh_token'],
      redirectUris: ['https://app.example/cb'],
    });
    expect(
      (
        await token(
          { grant_type: 'client_credentials', scope: 'admin:write' },
          { authorization: machine.basic },
        )
      ).body,
    ).toEqual({ error: 'invalid_scope' });
    expect(
      (await token({ grant_type: 'password' }, { authorization: machine.basic })).body,
    ).toEqual({
      error: 'unsupported_grant_type',
    });
    expect((await token({}, { authorization: machine.basic })).body).toEqual({
      error: 'unsupported_grant_type',
    });
    expect(
      (await token({ grant_type: 'client_credentials' }, { authorization: browser.basic })).body,
    ).toEqual({ error: 'unauthorized_client' });
    const publicMachine = await registerClient({
      methods: ['none'],
      grantTypes: ['client_credentials'],
      requireProofKey: true,
      scopes: ['openid'],
    });
    expect(
      (
        await token({
          grant_type: 'client_credentials',
          client_id: publicMachine.clientId,
          scope: 'openid',
        })
      ).body,
    ).toEqual({ error: 'unauthorized_client' });
    const wrongType = await controlPlane.fetch(
      new Request('https://identity.test/oauth2/token', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: machine.basic },
        body: '{}',
      }),
    );
    expect(wrongType.status).toBe(400);
    expect(await wrongType.json()).toEqual({ error: 'invalid_request' });
  });
});

describe('introspection and revocation', () => {
  test('introspect reports active tokens only to the issuing client', async () => {
    const client = await registerClient({ scopes: ['admin:read'] });
    const other = await registerClient();
    const issued = await token(
      { grant_type: 'client_credentials', scope: 'admin:read' },
      { authorization: client.basic },
    );
    const access = String(issued.body.access_token);
    const own = await controlPlane.fetch(
      formRequest('/oauth2/introspect', { token: access }, { authorization: client.basic }),
    );
    const body = (await own.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      active: true,
      client_id: client.clientId,
      sub: client.clientId,
      aud: [client.clientId],
      scope: 'admin:read',
      token_type: 'Bearer',
    });
    expect(Number(body.exp) - Number(body.iat)).toBe(600);
    const foreign = await controlPlane.fetch(
      formRequest('/oauth2/introspect', { token: access }, { authorization: other.basic }),
    );
    expect(await foreign.json()).toEqual({ active: false });
    const missing = await controlPlane.fetch(
      formRequest('/oauth2/introspect', {}, { authorization: client.basic }),
    );
    expect(await missing.json()).toEqual({ error: 'invalid_request' });

    const principal = await useContainer().resolve(Introspector).accessToken(access);
    expect(principal).toMatchObject({
      principalName: client.clientId,
      clientId: client.clientId,
      scopes: ['admin:read'],
    });
  });

  test('access tokens are rejected when invalidated, expired, orphaned, or the client is revoked', async () => {
    const client = await registerClient();
    const registered = await clients().find(client.clientId);
    const introspector = useContainer().resolve(Introspector);
    const now = Date.now();
    const save = async (
      stored: { invalidated: boolean; expiresAt: number },
      registeredClientId = registered?.id ?? '',
    ) => {
      const value = Hashing.token();
      await authorizations().save({
        ...authorizationFor(registeredClientId),
        access: {
          hash: Hashing.sha256Hex(value),
          issuedAt: now - 1000,
          expiresAt: stored.expiresAt,
          invalidated: stored.invalidated,
          scopes: ['admin:read'],
        },
      });
      return value;
    };
    expect(await introspector.accessToken('unknown')).toBeUndefined();
    expect(
      await introspector.accessToken(await save({ invalidated: true, expiresAt: now + 60_000 })),
    ).toBeUndefined();
    expect(
      await introspector.accessToken(await save({ invalidated: false, expiresAt: now - 1 })),
    ).toBeUndefined();
    expect(
      await introspector.accessToken(
        await save({ invalidated: false, expiresAt: now + 60_000 }, 'gone'),
      ),
    ).toBeUndefined();
    const live = await save({ invalidated: false, expiresAt: now + 60_000 });
    expect(await introspector.accessToken(live)).toBeDefined();
    await useContainer().resolve<OAuthRepository>(OAUTH).revoke(client.clientId);
    expect(await introspector.accessToken(live)).toBeUndefined();
  });

  test('revocation invalidates access tokens and deletes refresh-token authorizations', async () => {
    const client = await registerClient();
    const other = await registerClient();
    const issued = await token(
      { grant_type: 'client_credentials' },
      { authorization: client.basic },
    );
    const access = String(issued.body.access_token);
    const revokeAs = (as: string, value: string) =>
      controlPlane.fetch(formRequest('/oauth2/revoke', { token: value }, { authorization: as }));
    expect((await revokeAs(other.basic, access)).status).toBe(200);
    expect(await useContainer().resolve(Introspector).accessToken(access)).toBeDefined();
    expect((await revokeAs(client.basic, 'unknown-token')).status).toBe(200);
    expect((await revokeAs(client.basic, access)).status).toBe(200);
    expect(await useContainer().resolve(Introspector).accessToken(access)).toBeUndefined();
    expect(
      (await controlPlane.fetch(formRequest('/oauth2/revoke', {}, { authorization: client.basic })))
        .status,
    ).toBe(400);

    const registered = await clients().find(client.clientId);
    const refresh = Hashing.token();
    const authorization = {
      ...authorizationFor(registered?.id ?? ''),
      refresh: {
        hash: Hashing.sha256Hex(refresh),
        issuedAt: Date.now(),
        expiresAt: Date.now() + 60_000,
        invalidated: false,
      },
    };
    await authorizations().save(authorization);
    const introspected = await controlPlane.fetch(
      formRequest('/oauth2/introspect', { token: refresh }, { authorization: client.basic }),
    );
    expect(await introspected.json()).toMatchObject({ active: true, scope: 'admin:read' });
    expect((await revokeAs(client.basic, refresh)).status).toBe(200);
    expect(await authorizations().findById(authorization.id)).toBeUndefined();
  });
});

describe('authorization persistence', () => {
  test('round-trips every token, consent, and refresh history', async () => {
    const repository = authorizations();
    const now = Date.now();
    const token = (offset: number) => ({
      hash: Hashing.sha256Hex(Hashing.token()),
      issuedAt: now,
      expiresAt: now + offset,
      invalidated: false,
    });
    const authorization: Authorization = {
      ...authorizationFor('client-row'),
      principalName: 'user-1',
      grantType: 'authorization_code',
      attributes: { redirect_uri: 'https://app.example/cb' },
      state: 'state-hash',
      code: token(60_000),
      access: { ...token(600_000), scopes: ['openid'] },
      refresh: token(86_400_000),
      idToken: { ...token(600_000), claims: { sub: 'user-1' } },
    };
    await repository.save(authorization);
    expect(await repository.findById(authorization.id)).toEqual(authorization);
    const code = authorization.code as NonNullable<Authorization['code']>;
    expect((await repository.findByToken('code', code.hash))?.id).toBe(authorization.id);
    await database.transaction(async () => {
      expect((await repository.findByToken('code', code.hash, true))?.id).toBe(authorization.id);
    });
    await repository.save({ ...authorization, code: { ...code, invalidated: true } });
    expect((await repository.findById(authorization.id))?.code?.invalidated).toBe(true);

    expect(await repository.findConsent('client-row', 'user-1')).toEqual([]);
    await repository.saveConsent('client-row', 'user-1', ['openid', 'profile']);
    await repository.saveConsent('client-row', 'user-1', ['openid', 'email']);
    expect(await repository.findConsent('client-row', 'user-1')).toEqual(['openid', 'email']);
    await database.run(
      `UPDATE oauth2_authorization_consent SET authorities = 'ROLE_X,SCOPE_openid' WHERE principal_name = 'user-1'`,
    );
    expect(await repository.findConsent('client-row', 'user-1')).toEqual(['openid']);

    const old = Hashing.sha256Hex('old-refresh');
    await repository.rememberRefresh(old, authorization.id, now + 60_000);
    await repository.rememberRefresh(old, authorization.id, now + 60_000);
    expect(await repository.lockReplayedRefresh(old, now)).toBe(authorization.id);
    await repository.markRefreshReused(old, now);
    expect(await repository.lockReplayedRefresh(old, now)).toBeUndefined();
    const expired = Hashing.sha256Hex('expired-refresh');
    await repository.rememberRefresh(expired, authorization.id, now - 1);
    expect(await repository.lockReplayedRefresh(expired, now)).toBeUndefined();

    await database.run(
      `INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, authorization_grant_type)
       VALUES (?, 'client-row', 'user-1', 'client_credentials')`,
      [crypto.randomUUID()],
    );
    expect(await repository.deleteByPrincipal('user-1')).toBe(2);
    expect(await repository.deleteByPrincipal('user-1')).toBe(0);
  });

  test('registered clients map every column and tolerate unreadable settings', async () => {
    const repository = clients();
    const client = await registerClient({
      grantTypes: ['authorization_code', 'refresh_token'],
      redirectUris: ['https://a.example/cb'],
      scopes: ['openid'],
      requireProofKey: true,
      requireAuthorizationConsent: true,
      organizationSlug: 'endpoint-test-org',
    });
    const found = await repository.find(client.clientId);
    expect(found).toMatchObject({
      clientId: client.clientId,
      clientName: client.clientId,
      authenticationMethods: ['client_secret_basic', 'client_secret_post'],
      grantTypes: ['authorization_code', 'refresh_token'],
      redirectUris: ['https://a.example/cb'],
      scopes: ['openid'],
      settings: { requireProofKey: true, requireAuthorizationConsent: true },
      organizationSlug: 'endpoint-test-org',
      revokedAt: null,
    });
    expect((await repository.findById(found?.id ?? ''))?.clientId).toBe(client.clientId);
    expect(await repository.find('nobody')).toBeUndefined();
    expect(await repository.findById('nobody')).toBeUndefined();

    await repository.update(client.clientId, {
      secretHash: 'hash',
      clientName: 'Renamed',
      authenticationMethods: ['client_secret_basic'],
      grantTypes: ['client_credentials'],
      redirectUris: [],
      scopes: ['admin:read'],
      settings: { requireProofKey: false, requireAuthorizationConsent: false },
      organizationSlug: null,
    });
    expect(await repository.find(client.clientId)).toMatchObject({
      secretHash: 'hash',
      clientName: 'Renamed',
      authenticationMethods: ['client_secret_basic'],
      grantTypes: ['client_credentials'],
      redirectUris: [],
      scopes: ['admin:read'],
      settings: { requireProofKey: false, requireAuthorizationConsent: false },
      organizationSlug: null,
    });
    await repository.update(client.clientId, {});

    const orphan = `orphan-${Hashing.token(6)}`;
    await database.run(
      `INSERT INTO oauth2_registered_client (id, client_id, client_name, client_authentication_methods,
         authorization_grant_types, scopes, client_settings, token_settings)
       VALUES (?, ?, ?, 'client_secret_basic', 'client_credentials', '', 'not json', '{}')`,
      [crypto.randomUUID(), orphan, orphan],
    );
    expect((await repository.find(orphan))?.settings).toEqual({
      requireProofKey: false,
      requireAuthorizationConsent: false,
    });
    expect(ClientColumns).toBeDefined();

    expect(ClientColumns.readSettings('7')).toEqual({
      requireProofKey: false,
      requireAuthorizationConsent: false,
    });
    await repository.ensureLifecycle(orphan, 'endpoint-test-org');
    await repository.ensureLifecycle(orphan, 'other');
    expect((await repository.find(orphan))?.organizationSlug).toBe('endpoint-test-org');

    await database.run(
      `INSERT INTO oauth2_authorization (id, registered_client_id, principal_name, authorization_grant_type)
       VALUES (?, 'x', 'nobody-else', 'client_credentials')`,
      [crypto.randomUUID()],
    );
    const bare = await database.first<{ id: string }>(
      `SELECT id FROM oauth2_authorization WHERE principal_name = 'nobody-else'`,
    );
    expect((await authorizations().findById(bare?.id ?? ''))?.attributes).toEqual({});
  });
});

describe('public clients', () => {
  test('exchange a code with PKCE and no secret, refresh, revoke, but cannot introspect', async () => {
    const native = await registerClient({
      methods: ['none'],
      grantTypes: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile'],
      redirectUris: ['http://127.0.0.1/callback'],
      requireProofKey: true,
    });
    const registered = await clients().find(native.clientId);
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
    await authorizations().save(
      authorizationFor(registered?.id ?? '', {
        grantType: 'authorization_code',
        principalName: userId,
        authorizedScopes: ['openid', 'profile'],
        attributes: {
          redirect_uri: redirect,
          requested_redirect_uri: redirect,
          code_challenge: Hashing.pkceChallenge(verifier),
          nonce: null,
          auth_time: now,
        },
        code: {
          hash: Hashing.sha256Hex(code),
          issuedAt: now,
          expiresAt: now + 60_000,
          invalidated: false,
        },
      }),
    );
    const exchanged = await token({
      grant_type: 'authorization_code',
      client_id: native.clientId,
      code,
      redirect_uri: redirect,
      code_verifier: verifier,
    });
    expect(exchanged.response.status).toBe(200);
    expect(exchanged.body).toMatchObject({ token_type: 'Bearer', scope: 'openid profile' });
    const refresh = String(exchanged.body.refresh_token);
    expect(refresh).toMatch(/^[A-Za-z0-9_-]{43}$/);

    // A secret from a public client is a method it is not registered for.
    const withSecret = await token({
      grant_type: 'refresh_token',
      client_id: native.clientId,
      client_secret: 'anything',
      refresh_token: refresh,
    });
    expect(withSecret.response.status).toBe(401);
    const refreshed = await token({
      grant_type: 'refresh_token',
      client_id: native.clientId,
      refresh_token: refresh,
    });
    expect(refreshed.response.status).toBe(200);

    const introspected = await controlPlane.fetch(
      formRequest('/oauth2/introspect', {
        token: String(refreshed.body.access_token),
        client_id: native.clientId,
      }),
    );
    expect(introspected.status).toBe(401);
    expect(await introspected.json()).toEqual({ error: 'invalid_client' });

    const revoked = await controlPlane.fetch(
      formRequest('/oauth2/revoke', {
        token: String(refreshed.body.refresh_token),
        client_id: native.clientId,
      }),
    );
    expect(revoked.status).toBe(200);
    const afterRevoke = await token({
      grant_type: 'refresh_token',
      client_id: native.clientId,
      refresh_token: String(refreshed.body.refresh_token),
    });
    expect(afterRevoke.response.status).toBe(400);

    // `none` without PKCE is refused: nothing would protect the grant.
    const loose = await registerClient({
      methods: ['none'],
      grantTypes: ['authorization_code', 'refresh_token'],
      requireProofKey: false,
    });
    const refused = await token({
      grant_type: 'refresh_token',
      client_id: loose.clientId,
      refresh_token: 'x',
    });
    expect(refused.response.status).toBe(401);
  });
});
