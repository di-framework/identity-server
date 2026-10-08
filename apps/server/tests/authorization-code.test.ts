import { beforeAll, describe, expect, test } from 'bun:test';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { ORGANIZATION_ROLES_CLAIM } from '../../../packages/core/src/authorization/application/claims.ts';
import type { AuthorizationRepository } from '../../../packages/core/src/authorization/domain/models.ts';
import type { DirectoryRepository } from '../../../packages/core/src/directory/domain/directory-repository.ts';
import { AUTHORIZATIONS, DIRECTORY } from '../../../packages/core/src/shared/domain/tokens.ts';
import { Hashing } from '../../../packages/core/src/shared/infrastructure/crypto/hashing.ts';
import { PasswordHasher } from '../../../packages/core/src/shared/infrastructure/crypto/passwords.ts';
import { verifyJws } from '../../../packages/core/src/shared/infrastructure/crypto/signing-keys.ts';
import { registerClient, type TestClient } from '../../../packages/core/tests/support/clients.ts';
import { useTestDatabase } from '../../../packages/core/tests/support/database.ts';
import { routeRequest } from '../src/serve.ts';
import { Browser } from './support/browser.ts';

let database: SqlDatabase;
let assets: URL;
let app: TestClient;
let plain: TestClient;
let userId = '';
let login = '';
const PASSWORD = 'an-authorization-password';
const CALLBACK = 'https://app.example/callback';
const fetchApp = (request: Request) => routeRequest(request, assets);

beforeAll(async () => {
  database = await useTestDatabase();
  assets = new URL(`${await mkdtemp(join(tmpdir(), 'identity-assets-'))}/`, 'file:');
  app = await registerClient({
    grantTypes: ['authorization_code', 'refresh_token'],
    redirectUris: [CALLBACK],
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    requireProofKey: true,
    requireAuthorizationConsent: true,
  });
  plain = await registerClient({
    grantTypes: ['authorization_code'],
    redirectUris: [CALLBACK, 'https://app.example/other'],
    scopes: ['openid', 'profile'],
  });
  userId = crypto.randomUUID();
  login = `oidc-${userId.slice(0, 8)}`;
  const directory = useContainer().resolve<DirectoryRepository>(DIRECTORY);
  await directory.insertAccount({
    id: userId,
    login,
    email: `${login}@example.com`,
    displayName: 'Oidc User',
    passwordHash: await new PasswordHasher().hash(PASSWORD),
    emailVerified: true,
    systemRole: 'user',
    status: 'active',
  });
  const orgId = crypto.randomUUID();
  await directory.insertOrganization({
    id: orgId,
    slug: `oidc-${userId.slice(0, 6)}`,
    name: 'Oidc',
  });
  await directory.upsertMembership(orgId, userId, 'owner');
  await database.run(`UPDATE users SET avatar_url = 'https://img.example/a.png' WHERE id = ?`, [
    userId,
  ]);
});

function authorizeUrl(client: TestClient, extra: Record<string, string> = {}) {
  const verifier = Hashing.token();
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: CALLBACK,
    scope: 'openid profile email',
    state: 'client-state',
    nonce: 'n-0S6',
    code_challenge: Hashing.pkceChallenge(verifier),
    code_challenge_method: 'S256',
    ...extra,
  });
  return { url: `/oauth2/authorize?${params}`, verifier };
}

async function token(client: TestClient, form: Record<string, string>) {
  const response = await fetchApp(
    new Request('https://identity.test/oauth2/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: client.basic },
      body: new URLSearchParams(form),
    }),
  );
  return { status: response.status, body: (await response.json()) as Record<string, string> };
}

function codeFrom(location: string | null): string {
  const url = new URL(location ?? '');
  expect(url.origin + url.pathname).toBe(CALLBACK);
  expect(url.searchParams.get('state')).toBe('client-state');
  return url.searchParams.get('code') ?? '';
}

async function signedInBrowser(): Promise<Browser> {
  const browser = new Browser(fetchApp);
  expect((await browser.signIn(login, PASSWORD)).status).toBe(303);
  return browser;
}

describe('authorization code flow', () => {
  test('login, consent, code, tokens, ID token, UserInfo, consent reuse, and code replay', async () => {
    const browser = new Browser(fetchApp);
    const { url, verifier } = authorizeUrl(app);
    const first = await browser.send('GET', url);
    expect(first.status).toBe(302);
    expect(first.headers.get('location')).toBe('/login');
    const signIn = await browser.signIn(login, PASSWORD);
    expect(signIn.headers.get('location')).toBe(url);
    const consentRedirect = await browser.send('GET', url);
    const consentUrl = new URL(
      consentRedirect.headers.get('location') ?? '',
      'https://identity.test',
    );
    expect(consentUrl.pathname).toBe('/oauth2/consent');
    expect(consentUrl.searchParams.get('scope')).toBe('openid profile email');
    const consent = await browser.page<{
      page: string;
      scopes: string[];
      openid: boolean;
      state: string;
    }>(`${consentUrl.pathname}${consentUrl.search}`);
    expect(consent).toMatchObject({ page: 'consent', scopes: ['profile', 'email'], openid: true });
    const approved = await browser.send('POST', '/oauth2/authorize', {
      form: { client_id: app.clientId, state: consent.state, scope: ['openid', 'profile'] },
    });
    expect(approved.status).toBe(303);
    const code = codeFrom(approved.headers.get('location'));

    const exchanged = await token(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: CALLBACK,
      code_verifier: verifier,
    });
    expect(exchanged.status).toBe(200);
    expect(exchanged.body).toMatchObject({
      token_type: 'Bearer',
      expires_in: 600,
      scope: 'openid profile',
    });
    expect(exchanged.body.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const jwks = (await (
      await fetchApp(new Request('https://identity.test/oauth2/jwks'))
    ).json()) as {
      keys: Record<string, unknown>[];
    };
    const idClaims = verifyJws(exchanged.body.id_token ?? '', jwks.keys, ['RS256']);
    expect(idClaims).toMatchObject({
      iss: 'https://identity.test',
      sub: userId,
      aud: [app.clientId],
      azp: app.clientId,
      nonce: 'n-0S6',
      preferred_username: login,
      name: 'Oidc User',
      email: `${login}@example.com`,
      email_verified: true,
      picture: 'https://img.example/a.png',
    });
    expect(idClaims[ORGANIZATION_ROLES_CLAIM]).toEqual([
      { slug: `oidc-${userId.slice(0, 6)}`, role: 'owner' },
    ]);
    expect(Number(idClaims.exp) - Number(idClaims.iat)).toBe(1800);

    const userinfo = await fetchApp(
      new Request('https://identity.test/userinfo', {
        headers: { authorization: `Bearer ${exchanged.body.access_token}` },
      }),
    );
    expect(await userinfo.json()).toMatchObject({
      sub: userId,
      preferred_username: login,
      email_verified: true,
    });
    const posted = await fetchApp(
      new Request('https://identity.test/userinfo', {
        method: 'POST',
        headers: { authorization: `Bearer ${exchanged.body.access_token}` },
      }),
    );
    expect(posted.status).toBe(200);

    const again = authorizeUrl(app, { scope: 'openid profile' });
    const remembered = await browser.send('GET', again.url);
    const secondCode = codeFrom(remembered.headers.get('location'));
    expect(
      (
        await token(app, {
          grant_type: 'authorization_code',
          code: secondCode,
          redirect_uri: CALLBACK,
          code_verifier: again.verifier,
        })
      ).status,
    ).toBe(200);

    const replay = await token(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: CALLBACK,
      code_verifier: verifier,
    });
    expect(replay).toEqual({ status: 400, body: { error: 'invalid_grant' } });
    const revoked = await fetchApp(
      new Request('https://identity.test/userinfo', {
        headers: { authorization: `Bearer ${exchanged.body.access_token}` },
      }),
    );
    expect(revoked.status).toBe(401);
  });

  test('refresh tokens rotate and a reused one revokes the whole authorization', async () => {
    const browser = await signedInBrowser();
    const { url, verifier } = authorizeUrl(app, { scope: 'openid profile', nonce: '' });
    const code = codeFrom((await browser.send('GET', url)).headers.get('location'));
    const first = await token(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: CALLBACK,
      code_verifier: verifier,
    });
    expect(
      verifyJws(
        first.body.id_token ?? '',
        (
          (await (await fetchApp(new Request('https://identity.test/oauth2/jwks'))).json()) as {
            keys: Record<string, unknown>[];
          }
        ).keys,
        ['RS256'],
      ),
    ).not.toHaveProperty('nonce');
    const rotated = await token(app, {
      grant_type: 'refresh_token',
      refresh_token: first.body.refresh_token ?? '',
    });
    expect(rotated.status).toBe(200);
    expect(rotated.body.refresh_token).not.toBe(first.body.refresh_token);
    expect(rotated.body.id_token).toBeDefined();
    const narrowed = await token(app, {
      grant_type: 'refresh_token',
      refresh_token: rotated.body.refresh_token ?? '',
      scope: 'profile',
    });
    expect(narrowed.body).toMatchObject({ scope: 'profile' });
    expect(narrowed.body.id_token).toBeUndefined();
    expect(
      await token(app, {
        grant_type: 'refresh_token',
        refresh_token: narrowed.body.refresh_token ?? '',
        scope: 'admin:write',
      }),
    ).toEqual({
      status: 400,
      body: { error: 'invalid_scope' },
    });

    const reused = await token(app, {
      grant_type: 'refresh_token',
      refresh_token: first.body.refresh_token ?? '',
    });
    expect(reused).toEqual({ status: 400, body: { error: 'invalid_grant' } });
    expect(
      await token(app, {
        grant_type: 'refresh_token',
        refresh_token: narrowed.body.refresh_token ?? '',
      }),
    ).toEqual({
      status: 400,
      body: { error: 'invalid_grant' },
    });
    const audit = await database.first<{ target: string }>(
      `SELECT target FROM auth_audit_records WHERE action = 'oauth.refresh_reuse_detected' ORDER BY created_at DESC LIMIT 1`,
    );
    expect(audit?.target).toBeDefined();
    expect(
      await token(app, { grant_type: 'refresh_token', refresh_token: 'never-issued' }),
    ).toMatchObject({ status: 400 });
  });

  test('authorize request validation', async () => {
    const browser = await signedInBrowser();
    const get = (path: string) => browser.send('GET', path);
    const errorPage = async (path: string) => {
      const response = await browser.send('GET', path, { json: true });
      expect(response.status).toBe(400);
      return (await response.json()) as { page: string; message: string };
    };
    expect(await errorPage('/oauth2/authorize?client_id=missing')).toMatchObject({
      page: 'error',
      message: 'The client is not valid.',
    });
    const machine = await registerClient();
    expect(await errorPage(`/oauth2/authorize?client_id=${machine.clientId}`)).toMatchObject({
      message: 'The client is not valid.',
    });
    expect(
      await errorPage(authorizeUrl(app, { redirect_uri: 'https://evil.example/cb' }).url),
    ).toMatchObject({
      message: 'The redirect URI is not valid.',
    });
    expect(
      await errorPage(`/oauth2/authorize?client_id=${plain.clientId}&response_type=code`),
    ).toMatchObject({
      message: 'The redirect URI is not valid.',
    });
    const errorOf = async (path: string) =>
      new URL((await get(path)).headers.get('location') ?? '').searchParams.get('error');
    expect(await errorOf(authorizeUrl(app, { response_type: 'token' }).url)).toBe(
      'unsupported_response_type',
    );
    expect(await errorOf(authorizeUrl(app, { scope: 'openid admin:write' }).url)).toBe(
      'invalid_scope',
    );
    expect(await errorOf(authorizeUrl(app, { code_challenge_method: 'plain' }).url)).toBe(
      'invalid_request',
    );
    const noPkce = new URLSearchParams({
      response_type: 'code',
      client_id: app.clientId,
      redirect_uri: CALLBACK,
      scope: 'openid',
    });
    expect(await errorOf(`/oauth2/authorize?${noPkce}`)).toBe('invalid_request');

    const single = await registerClient({
      grantTypes: ['authorization_code'],
      redirectUris: [CALLBACK],
      scopes: ['openid'],
    });
    const implicit = new URLSearchParams({
      response_type: 'code',
      client_id: single.clientId,
      scope: 'openid',
    });
    const implicitCode =
      new URL(
        (await get(`/oauth2/authorize?${implicit}`)).headers.get('location') ?? '',
      ).searchParams.get('code') ?? '';
    expect(
      (await token(single, { grant_type: 'authorization_code', code: implicitCode })).body,
    ).not.toHaveProperty('refresh_token');

    const plainCode =
      new URL(
        (
          await get(
            `/oauth2/authorize?${new URLSearchParams({ response_type: 'code', client_id: plain.clientId, redirect_uri: CALLBACK, scope: 'profile' })}`,
          )
        ).headers.get('location') ?? '',
      ).searchParams.get('code') ?? '';
    const plainTokens = await token(plain, {
      grant_type: 'authorization_code',
      code: plainCode,
      redirect_uri: CALLBACK,
    });
    expect(plainTokens.body).toMatchObject({ scope: 'profile' });
    expect(plainTokens.body).not.toHaveProperty('id_token');
    const noOpenid = await fetchApp(
      new Request('https://identity.test/userinfo', {
        headers: { authorization: `Bearer ${plainTokens.body.access_token}` },
      }),
    );
    expect(noOpenid.status).toBe(403);
    expect((await fetchApp(new Request('https://identity.test/userinfo'))).status).toBe(401);
  });

  test('code exchange checks the client, expiry, redirect URI, and PKCE', async () => {
    const browser = await signedInBrowser();
    const issue = async (client: TestClient, extra: Record<string, string> = {}) => {
      const request = authorizeUrl(client, extra);
      const location = (await browser.send('GET', request.url)).headers.get('location') ?? '';
      return { code: new URL(location).searchParams.get('code') ?? '', verifier: request.verifier };
    };
    const consentless = await registerClient({
      grantTypes: ['authorization_code', 'refresh_token'],
      redirectUris: [CALLBACK],
      scopes: ['openid', 'profile'],
      requireProofKey: true,
    });
    const bad = (body: { status: number; body: Record<string, string> }) =>
      expect(body).toEqual({ status: 400, body: { error: 'invalid_grant' } });

    const a = await issue(consentless, { scope: 'openid' });
    bad(
      await token(plain, {
        grant_type: 'authorization_code',
        code: a.code,
        redirect_uri: CALLBACK,
      }),
    );
    bad(
      await token(consentless, {
        grant_type: 'authorization_code',
        code: a.code,
        redirect_uri: 'https://app.example/other',
        code_verifier: a.verifier,
      }),
    );
    bad(
      await token(consentless, {
        grant_type: 'authorization_code',
        code: a.code,
        redirect_uri: CALLBACK,
      }),
    );
    bad(
      await token(consentless, {
        grant_type: 'authorization_code',
        code: a.code,
        redirect_uri: CALLBACK,
        code_verifier: Hashing.token(),
      }),
    );
    bad(await token(consentless, { grant_type: 'authorization_code', code: 'nope' }));

    const b = await issue(consentless, { scope: 'openid' });
    await database.run(
      `UPDATE oauth2_authorization SET authorization_code_expires_at = now() - interval '1 second' WHERE authorization_code_value = ?`,
      [Hashing.sha256Hex(b.code)],
    );
    bad(
      await token(consentless, {
        grant_type: 'authorization_code',
        code: b.code,
        redirect_uri: CALLBACK,
        code_verifier: b.verifier,
      }),
    );

    const plainRequest = new URLSearchParams({
      response_type: 'code',
      client_id: plain.clientId,
      redirect_uri: CALLBACK,
      scope: 'openid',
    });
    const plainCode =
      new URL(
        (await browser.send('GET', `/oauth2/authorize?${plainRequest}`)).headers.get('location') ??
          '',
      ).searchParams.get('code') ?? '';
    bad(
      await token(plain, {
        grant_type: 'authorization_code',
        code: plainCode,
        redirect_uri: CALLBACK,
        code_verifier: 'unexpected',
      }),
    );

    const c = await issue(consentless, { scope: 'openid profile' });
    const tokens = await token(consentless, {
      grant_type: 'authorization_code',
      code: c.code,
      redirect_uri: CALLBACK,
      code_verifier: c.verifier,
    });
    bad(
      await token(app, {
        grant_type: 'refresh_token',
        refresh_token: tokens.body.refresh_token ?? '',
      }),
    );
    await database.run(
      `UPDATE oauth2_authorization SET refresh_token_expires_at = now() - interval '1 second' WHERE refresh_token_value = ?`,
      [Hashing.sha256Hex(tokens.body.refresh_token ?? '')],
    );
    bad(
      await token(consentless, {
        grant_type: 'refresh_token',
        refresh_token: tokens.body.refresh_token ?? '',
      }),
    );
  });

  test('consent submissions are bound to the pending request and the signed-in user', async () => {
    const browser = await signedInBrowser();
    const { url } = authorizeUrl(app, { scope: 'openid offline_access' });
    const consentUrl = new URL(
      (await browser.send('GET', url)).headers.get('location') ?? '',
      'https://identity.test',
    );
    const state = consentUrl.searchParams.get('state') ?? '';
    const page = await browser.page(`${consentUrl.pathname}${consentUrl.search}`);
    expect(page).toMatchObject({ scopes: ['offline_access'] });
    const wrong = await browser.send('POST', '/oauth2/authorize', {
      form: { client_id: plain.clientId, state, scope: 'offline_access' },
    });
    expect(wrong.status).toBe(400);
    const missing = await browser.send('POST', '/oauth2/authorize', {
      form: { client_id: app.clientId, state: 'nope' },
    });
    expect(missing.status).toBe(400);
    const denied = await browser.send('POST', '/oauth2/authorize', {
      form: { client_id: app.clientId, state, scope: 'openid' },
    });
    const deniedUrl = new URL(denied.headers.get('location') ?? '');
    expect(deniedUrl.searchParams.get('error')).toBe('access_denied');
    expect(deniedUrl.searchParams.get('state')).toBe('client-state');
    const repository = useContainer().resolve<AuthorizationRepository>(AUTHORIZATIONS);
    expect(await repository.findByState(Hashing.sha256Hex(state))).toBeUndefined();

    const anonymous = new Browser(fetchApp);
    await anonymous.page('/login');
    const login = await anonymous.send('POST', '/oauth2/authorize', {
      form: { client_id: app.clientId, state },
    });
    expect(login.status).toBe(303);
    expect(login.headers.get('location')).toBe('/login');
  });

  test('UserInfo refuses users who are no longer active', async () => {
    const browser = await signedInBrowser();
    const request = authorizeUrl(plain, { scope: 'openid' });
    const code =
      new URL(
        (
          await browser.send(
            'GET',
            `/oauth2/authorize?${new URLSearchParams({ response_type: 'code', client_id: plain.clientId, redirect_uri: CALLBACK, scope: 'openid' })}`,
          )
        ).headers.get('location') ?? '',
      ).searchParams.get('code') ?? '';
    void request;
    const tokens = await token(plain, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: CALLBACK,
    });
    await useContainer()
      .resolve<DirectoryRepository>(DIRECTORY)
      .updateAccount(userId, { status: 'archived' });
    try {
      const response = await fetchApp(
        new Request('https://identity.test/userinfo', {
          headers: { authorization: `Bearer ${tokens.body.access_token}` },
        }),
      );
      expect(response.status).toBe(401);
    } finally {
      await useContainer()
        .resolve<DirectoryRepository>(DIRECTORY)
        .updateAccount(userId, { status: 'active' });
    }
  });

  test('prompt=login and max_age require a fresh sign-in; prompt=none never shows one', async () => {
    const browser = await signedInBrowser();
    const params = (extra: Record<string, string>) =>
      new URLSearchParams({
        response_type: 'code',
        client_id: plain.clientId,
        redirect_uri: CALLBACK,
        scope: 'openid',
        state: 'client-state',
        ...extra,
      });
    const authorize = (extra: Record<string, string>) =>
      browser.send('GET', `/oauth2/authorize?${params(extra)}`);
    const errorOf = (response: Response) =>
      new URL(response.headers.get('location') ?? '').searchParams.get('error');

    expect(codeFrom((await authorize({ max_age: '3600' })).headers.get('location'))).toBeTruthy();
    expect(errorOf(await authorize({ max_age: 'soon' }))).toBe('invalid_request');

    const forced = await authorize({ prompt: 'login' });
    expect(forced.status).toBe(302);
    expect(forced.headers.get('location')).toBe('/login');
    const again = await browser.signIn(login, PASSWORD);
    expect(again.headers.get('location')).toBe(`/oauth2/authorize?${params({})}`);
    expect(
      codeFrom(
        (await browser.send('GET', again.headers.get('location') ?? '')).headers.get('location'),
      ),
    ).toBeTruthy();

    await database.run(
      `UPDATE browser_sessions SET last_authenticated_at = now() - interval '2 hours' WHERE user_id = ?`,
      [userId],
    );
    expect(codeFrom((await authorize({ max_age: '86400' })).headers.get('location'))).toBeTruthy();
    expect((await authorize({ max_age: '60' })).headers.get('location')).toBe('/login');
    expect(errorOf(await authorize({ max_age: '60', prompt: 'none' }))).toBe('login_required');
    expect(errorOf(await authorize({ prompt: 'login none' }))).toBe('login_required');

    const anonymous = new Browser(fetchApp);
    await anonymous.page('/login');
    expect(
      errorOf(await anonymous.send('GET', `/oauth2/authorize?${params({ prompt: 'none' })}`)),
    ).toBe('login_required');
    // Signing in from a max_age=0 request is fresh, so the resumed request does not ask again.
    expect(
      (await anonymous.send('GET', `/oauth2/authorize?${params({ max_age: '0' })}`)).headers.get(
        'location',
      ),
    ).toBe('/login');
    const resumed = await anonymous.signIn(login, PASSWORD);
    expect(resumed.headers.get('location')).toBe(`/oauth2/authorize?${params({})}`);
    expect(
      codeFrom(
        (await anonymous.send('GET', resumed.headers.get('location') ?? '')).headers.get(
          'location',
        ),
      ),
    ).toBeTruthy();
  });

  test('archived users get no codes, no consent, and no tokens from codes or refresh', async () => {
    const directory = useContainer().resolve<DirectoryRepository>(DIRECTORY);
    const browser = await signedInBrowser();
    // Consent once (an earlier test may already have), then read the code from the callback.
    const approve = async (location: string) => {
      const consent = new URL(location, 'https://identity.test');
      if (consent.pathname !== '/oauth2/consent') return location;
      await browser.page(`${consent.pathname}${consent.search}`);
      const granted = await browser.send('POST', '/oauth2/authorize', {
        form: {
          client_id: app.clientId,
          state: consent.searchParams.get('state') ?? '',
          scope: (consent.searchParams.get('scope') ?? '').split(' '),
        },
      });
      return granted.headers.get('location') ?? '';
    };
    const { url, verifier } = authorizeUrl(app, { scope: 'openid offline_access' });
    const first = await token(app, {
      grant_type: 'authorization_code',
      code: codeFrom(await approve((await browser.send('GET', url)).headers.get('location') ?? '')),
      redirect_uri: CALLBACK,
      code_verifier: verifier,
    });
    expect(first.status).toBe(200);
    const pending = authorizeUrl(app, { scope: 'openid offline_access' });
    const pendingCode = codeFrom((await browser.send('GET', pending.url)).headers.get('location'));
    const unconsented = await registerClient({
      grantTypes: ['authorization_code'],
      redirectUris: [CALLBACK],
      scopes: ['openid', 'profile'],
      requireAuthorizationConsent: true,
    });
    const second = authorizeUrl(unconsented, { scope: 'openid profile' });
    const secondConsent = new URL(
      (await browser.send('GET', second.url)).headers.get('location') ?? '',
      'https://identity.test',
    );
    expect(secondConsent.pathname).toBe('/oauth2/consent');
    await browser.page(`${secondConsent.pathname}${secondConsent.search}`);

    const replays = async () =>
      (
        await database.query(
          `SELECT 1 FROM auth_audit_records WHERE action = 'oauth.refresh_reuse_detected'`,
        )
      ).length;
    const replaysBefore = await replays();
    await directory.updateAccount(userId, { status: 'archived' });
    try {
      const refused = await browser.send('GET', authorizeUrl(app).url);
      expect(new URL(refused.headers.get('location') ?? '').searchParams.get('error')).toBe(
        'access_denied',
      );
      const consent = await browser.send('POST', '/oauth2/authorize', {
        form: {
          client_id: unconsented.clientId,
          state: secondConsent.searchParams.get('state') ?? '',
          scope: 'profile',
        },
      });
      expect(consent.status).toBe(400);
      expect(
        await token(app, {
          grant_type: 'authorization_code',
          code: pendingCode,
          redirect_uri: CALLBACK,
          code_verifier: pending.verifier,
        }),
      ).toEqual({ status: 400, body: { error: 'invalid_grant' } });
      expect(
        await token(app, {
          grant_type: 'refresh_token',
          refresh_token: first.body.refresh_token ?? '',
        }),
      ).toEqual({ status: 400, body: { error: 'invalid_grant' } });
    } finally {
      await directory.updateAccount(userId, { status: 'active' });
    }
    // The refused refresh deleted the authorization, so the token stays dead after restore.
    expect(
      await token(app, {
        grant_type: 'refresh_token',
        refresh_token: first.body.refresh_token ?? '',
      }),
    ).toEqual({ status: 400, body: { error: 'invalid_grant' } });
    // A token refused for an inactive user is not a rotated-out token, so it is no replay.
    expect(await replays()).toBe(replaysBefore);
  });
});

test('a public client redirects to any loopback port and exchanges without a secret', async () => {
  const browser = await signedInBrowser();
  const native = await registerClient({
    methods: ['none'],
    grantTypes: ['authorization_code', 'refresh_token'],
    redirectUris: ['http://127.0.0.1/callback'],
    scopes: ['openid', 'profile'],
    requireProofKey: true,
  });
  const verifier = Hashing.token();
  const authorize = (redirect: string) =>
    `/oauth2/authorize?${new URLSearchParams({
      response_type: 'code',
      client_id: native.clientId,
      redirect_uri: redirect,
      scope: 'openid profile',
      state: 'cli-state',
      code_challenge: Hashing.pkceChallenge(verifier),
      code_challenge_method: 'S256',
    })}`;
  for (const bad of [
    'http://127.0.0.1:49152/other',
    'http://localhost:49152/callback',
    'https://127.0.0.1:49152/callback',
    'http://127.0.0.1:49152/callback?x=1',
    'not a url',
  ]) {
    const refused = await browser.send('GET', authorize(bad), { json: true });
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ message: 'The redirect URI is not valid.' });
  }
  const redirect = 'http://127.0.0.1:49152/callback';
  const location = (await browser.send('GET', authorize(redirect))).headers.get('location') ?? '';
  expect(location.startsWith(`${redirect}?`)).toBe(true);
  const code = new URL(location).searchParams.get('code') ?? '';
  const exchanged = await fetchApp(
    new Request('https://identity.test/oauth2/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: native.clientId,
        code,
        redirect_uri: redirect,
        code_verifier: verifier,
      }),
    }),
  );
  expect(exchanged.status).toBe(200);
  expect(((await exchanged.json()) as { refresh_token?: string }).refresh_token).toBeDefined();
});
