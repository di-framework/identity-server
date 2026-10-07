import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { TokenService } from '../../../../packages/core/src/authorization/application/token-service.ts';
import type { DirectoryRepository } from '../../../../packages/core/src/directory/domain/directory-repository.ts';
import {
  DIRECTORY,
  IDENTITY_SETTINGS,
  SIGNING_KEYS,
} from '../../../../packages/core/src/shared/domain/tokens.ts';
import { PasswordHasher } from '../../../../packages/core/src/shared/infrastructure/crypto/passwords.ts';
import type { SigningKeys } from '../../../../packages/core/src/shared/infrastructure/crypto/signing-keys.ts';
import type { IdentitySettings } from '../../../../packages/core/src/shared/infrastructure/identity-settings.ts';
import {
  registerClient,
  type TestClient,
} from '../../../../packages/core/tests/support/clients.ts';
import { useTestDatabase } from '../../../../packages/core/tests/support/database.ts';
import { routeRequest } from '../../src/serve.ts';

export interface RedTeamContext {
  server: ReturnType<typeof Bun.serve>;
  baseUrl: string;
  database: SqlDatabase;
  signingKeys: SigningKeys;
  tokenService: TokenService;
  settings: IdentitySettings;
  fixtures: {
    adminUser: { id: string; login: string; email: string; password: string };
    regularUser1: { id: string; login: string; email: string; password: string; orgSlug: string };
    regularUser2: { id: string; login: string; email: string; password: string; orgSlug: string };
    archivedUser: { id: string; login: string; email: string };
    orgAlpha: { id: string; slug: string; name: string };
    orgBeta: { id: string; slug: string; name: string };
    confidentialClient: TestClient & { redirectUris: string[] };
    publicPkceClient: TestClient & { redirectUris: string[] };
    backendClient: TestClient & { redirectUris: string[] };
    unprivilegedClient: TestClient & { redirectUris: string[] };
  };
  stop(): Promise<void>;
}

export async function setupRedTeamServer(): Promise<RedTeamContext> {
  const database = await useTestDatabase();
  const container = useContainer();
  const directory = container.resolve<DirectoryRepository>(DIRECTORY);
  const settings = container.resolve<IdentitySettings>(IDENTITY_SETTINGS);
  const signingKeys = container.resolve<SigningKeys>(SIGNING_KEYS);
  const tokenService = container.resolve(TokenService);
  const hasher = new PasswordHasher();

  // 1. Prepare assets directory
  const assetDir = await mkdtemp(join(tmpdir(), 'identity-redteam-assets-'));
  const assetsUrl = new URL(`${assetDir}/`, 'file:');
  await writeFile(new URL('main.js', assetsUrl), '/* redteam asset */\n');

  // 2. Provision Organizations
  const orgAlpha = {
    id: crypto.randomUUID(),
    slug: `org-alpha-${crypto.randomUUID().slice(0, 6)}`,
    name: 'Alpha Corp',
  };
  const orgBeta = {
    id: crypto.randomUUID(),
    slug: `org-beta-${crypto.randomUUID().slice(0, 6)}`,
    name: 'Beta LLC',
  };
  await directory.insertOrganization(orgAlpha);
  await directory.insertOrganization(orgBeta);

  // 3. Provision Users
  const adminUser = {
    id: crypto.randomUUID(),
    login: `admin-${crypto.randomUUID().slice(0, 6)}`,
    email: `admin-${crypto.randomUUID().slice(0, 6)}@test.corp`,
    password: 'P@ssword123!-Admin',
  };
  await directory.insertAccount({
    id: adminUser.id,
    login: adminUser.login,
    email: adminUser.email,
    displayName: 'RedTeam Admin',
    passwordHash: await hasher.hash(adminUser.password),
    emailVerified: true,
    systemRole: 'platform_admin',
    status: 'active',
  });

  const regularUser1 = {
    id: crypto.randomUUID(),
    login: `user1-${crypto.randomUUID().slice(0, 6)}`,
    email: `user1-${crypto.randomUUID().slice(0, 6)}@test.corp`,
    password: 'P@ssword123!-User1',
    orgSlug: orgAlpha.slug,
  };
  await directory.insertAccount({
    id: regularUser1.id,
    login: regularUser1.login,
    email: regularUser1.email,
    displayName: 'Regular User One',
    passwordHash: await hasher.hash(regularUser1.password),
    emailVerified: true,
    systemRole: 'user',
    status: 'active',
  });
  await directory.upsertMembership(orgAlpha.id, regularUser1.id, 'owner');

  const regularUser2 = {
    id: crypto.randomUUID(),
    login: `user2-${crypto.randomUUID().slice(0, 6)}`,
    email: `user2-${crypto.randomUUID().slice(0, 6)}@test.corp`,
    password: 'P@ssword123!-User2',
    orgSlug: orgBeta.slug,
  };
  await directory.insertAccount({
    id: regularUser2.id,
    login: regularUser2.login,
    email: regularUser2.email,
    displayName: 'Regular User Two',
    passwordHash: await hasher.hash(regularUser2.password),
    emailVerified: true,
    systemRole: 'user',
    status: 'active',
  });
  await directory.upsertMembership(orgBeta.id, regularUser2.id, 'member');

  const archivedUser = {
    id: crypto.randomUUID(),
    login: `archived-${crypto.randomUUID().slice(0, 6)}`,
    email: `archived-${crypto.randomUUID().slice(0, 6)}@test.corp`,
  };
  await directory.insertAccount({
    id: archivedUser.id,
    login: archivedUser.login,
    email: archivedUser.email,
    displayName: 'Archived User',
    passwordHash: await hasher.hash('ExpiredPassword123!'),
    emailVerified: true,
    systemRole: 'user',
    status: 'archived',
  });

  // 4. Provision OAuth Clients
  const clientSuffix = crypto.randomUUID().slice(0, 8);
  const confidentialUris = ['https://client.example/callback'];
  const confidentialClient = {
    ...(await registerClient({
      clientId: `redteam-conf-${clientSuffix}`,
      grantTypes: ['authorization_code', 'client_credentials', 'refresh_token'],
      redirectUris: confidentialUris,
      scopes: [
        'openid',
        'profile',
        'email',
        'offline_access',
        'admin:read',
        'admin:write',
        'directory:read',
      ],
      requireProofKey: false,
      requireAuthorizationConsent: false,
    })),
    redirectUris: confidentialUris,
  };

  const publicUris = ['https://spa.example/callback'];
  const publicPkceClient = {
    ...(await registerClient({
      clientId: `redteam-spa-${clientSuffix}`,
      grantTypes: ['authorization_code', 'refresh_token'],
      redirectUris: publicUris,
      scopes: ['openid', 'profile', 'email'],
      requireProofKey: true,
      requireAuthorizationConsent: false,
    })),
    redirectUris: publicUris,
  };

  const backendClient = {
    ...(await registerClient({
      clientId: `redteam-be-${clientSuffix}`,
      grantTypes: ['client_credentials'],
      redirectUris: [],
      scopes: ['admin:read', 'directory:read'],
      requireProofKey: false,
      requireAuthorizationConsent: false,
    })),
    redirectUris: [] as string[],
  };

  const unprivilegedClient = {
    ...(await registerClient({
      clientId: `redteam-low-${clientSuffix}`,
      grantTypes: ['client_credentials'],
      redirectUris: [],
      scopes: ['directory:read'],
      requireProofKey: false,
      requireAuthorizationConsent: false,
    })),
    redirectUris: [] as string[],
  };

  // 5. Start live server on ephemeral port (port 0)
  const server = Bun.serve({
    port: 0,
    fetch: (request) => routeRequest(request, assetsUrl),
  });

  const baseUrl = `http://127.0.0.1:${server.port}`;

  return {
    server,
    baseUrl,
    database,
    signingKeys,
    tokenService,
    settings,
    fixtures: {
      adminUser,
      regularUser1,
      regularUser2,
      archivedUser,
      orgAlpha,
      orgBeta,
      confidentialClient,
      publicPkceClient,
      backendClient,
      unprivilegedClient,
    },
    stop: async () => {
      server.stop(true);
    },
  };
}

export async function loginUserSession(
  baseUrl: string,
  username: string,
  password: string,
): Promise<string> {
  const getRes = await fetch(`${baseUrl}/login`, {
    headers: { accept: 'application/json' },
  });
  const initialCookies = getRes.headers.getSetCookie();
  const initialCookie =
    initialCookies.find((c) => c.startsWith('identity_session='))?.split(';')[0] ?? '';
  const { csrf } = (await getRes.json()) as { csrf: string };

  const postRes = await fetch(`${baseUrl}/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: initialCookie,
    },
    body: new URLSearchParams({
      username,
      password,
      _csrf: csrf,
    }),
    redirect: 'manual',
  });

  const postCookies = postRes.headers.getSetCookie();
  const sessionCookie =
    postCookies.find((c) => c.startsWith('identity_session='))?.split(';')[0] ?? initialCookie;
  return sessionCookie;
}

export async function issueAuthCode(
  ctx: RedTeamContext,
  options: {
    client: TestClient & { redirectUris: string[] };
    user: { login: string; password: string };
    redirectUri?: string;
    scope?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    state?: string;
  },
): Promise<{ code: string; redirectUri: string; location: string }> {
  const sessionCookie = await loginUserSession(
    ctx.baseUrl,
    options.user.login,
    options.user.password,
  );
  const redirectUri = options.redirectUri ?? options.client.redirectUris[0] ?? '';
  const authUrl = new URL(`${ctx.baseUrl}/oauth2/authorize`);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', options.client.clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', options.scope ?? 'openid profile');
  authUrl.searchParams.set('state', options.state ?? 'test-state-123');
  if (options.codeChallenge) {
    authUrl.searchParams.set('code_challenge', options.codeChallenge);
    authUrl.searchParams.set('code_challenge_method', options.codeChallengeMethod ?? 'S256');
  }

  const authRes = await fetch(authUrl.toString(), {
    headers: { cookie: sessionCookie },
    redirect: 'manual',
  });
  const location = authRes.headers.get('location') ?? '';
  const parsed = new URL(location, ctx.baseUrl);
  const code = parsed.searchParams.get('code') ?? '';
  return { code, redirectUri, location };
}
