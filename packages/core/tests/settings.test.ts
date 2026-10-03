import { expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import { IdentityModule } from '../src/composition.ts';
import { IDENTITY_SETTINGS, SIGNING_KEYS } from '../src/shared/domain/tokens.ts';
import type { SigningKeys } from '../src/shared/infrastructure/crypto/signing-keys.ts';
import { loadIdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import { withContainer } from './support/container-lock.ts';
import { databaseUrl, testDatabaseName } from './support/database.ts';

test('defaults match the auth server application.yml', () => {
  const settings = loadIdentitySettings({});
  expect(settings.server).toEqual({ host: '0.0.0.0', port: 4180 });
  expect(settings.issuer).toBe('http://localhost:4180');
  expect(settings.publicOrigin).toBe('http://localhost:4180');
  expect(settings.cookieSecure).toBe(true);
  expect(settings.database.poolMax).toBe(8);
  expect(settings.smtp).toEqual({
    host: '',
    port: 587,
    username: '',
    password: '',
    from: '',
    auth: true,
    starttls: true,
    ssl: false,
  });
  expect(settings.jwk.signingAlgorithm).toBe('RS256');
  expect(settings.identityLink).toEqual({ clientId: 'gsio-auth-client', providers: {} });
  expect(settings.notifications).toEqual({ fixedDelayMs: 5000, schedulerEnabled: true });
  expect(settings.clients.access.redirectUris).toEqual([]);
});

test('reads every auth-server environment name', () => {
  const settings = loadIdentitySettings({
    PORT: '9000',
    ISSUER_URL: 'https://auth.example/',
    AUTH_PUBLIC_ORIGIN: 'https://public.example/',
    SERVER_SERVLET_SESSION_COOKIE_SECURE: 'false',
    DATABASE_URL: 'postgres://u:p@db/x',
    SMTP_HOST: 'smtp.example',
    SMTP_PORT: '1025',
    SMTP_USERNAME: 'mailer',
    SMTP_PASSWORD: 'secret',
    SMTP_FROM: 'no-reply@example.com',
    SMTP_AUTH: 'false',
    SMTP_STARTTLS: 'false',
    SMTP_SSL_ENABLE: 'true',
    AUTH_ACTIVE_PRIVATE_JWK: '{"kid":"a"}',
    AUTH_PREVIOUS_PUBLIC_JWK_SET: '{"keys":[]}',
    AUTH_SIGNING_ALGORITHM: 'ML-DSA-65',
    AUTH_BOOTSTRAP_OWNER_EMAIL: 'owner@example.com',
    AUTH_BOOTSTRAP_OWNER_LOGIN: 'owner',
    AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME: 'Owner',
    AUTH_BOOTSTRAP_OWNER_PASSWORD: 'owner-password',
    AUTH_BOOTSTRAP_VIEWER_LOGIN: 'viewer',
    AUTH_BOOTSTRAP_ORGANIZATION_SLUG: 'acme',
    AUTH_BOOTSTRAP_ORGANIZATION_NAME: 'Acme',
    AUTH_ACCESS_CLIENT_ID: 'access',
    AUTH_ACCESS_CLIENT_SECRET: 'access-secret',
    AUTH_ACCESS_REDIRECT_URIS: 'https://a.example/cb, https://b.example/cb',
    AUTH_DIRECTORY_CLIENT_ID: 'directory',
    AUTH_DIRECTORY_CLIENT_SECRET: 'directory-secret',
    AUTH_PROVISIONER_CLIENT_ID: 'provisioner',
    AUTH_PROVISIONER_CLIENT_SECRET: 'provisioner-secret',
    AUTH_IDENTITY_LINK_CLIENT_ID: 'link-client',
    GSIO_IDENTITY_NOTIFICATION_DELAY_MS: '250',
    GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED: 'false',
  });
  expect(settings.server.port).toBe(9000);
  expect(settings.issuer).toBe('https://auth.example');
  expect(settings.publicOrigin).toBe('https://public.example');
  expect(settings.cookieSecure).toBe(false);
  expect(settings.database.url).toBe('postgres://u:p@db/x');
  expect(settings.smtp).toEqual({
    host: 'smtp.example',
    port: 1025,
    username: 'mailer',
    password: 'secret',
    from: 'no-reply@example.com',
    auth: false,
    starttls: false,
    ssl: true,
  });
  expect(settings.jwk).toEqual({
    activePrivate: '{"kid":"a"}',
    previousPublicSet: '{"keys":[]}',
    signingAlgorithm: 'ML-DSA-65',
  });
  expect(settings.bootstrap.owner).toEqual({
    email: 'owner@example.com',
    login: 'owner',
    displayName: 'Owner',
    password: 'owner-password',
  });
  expect(settings.bootstrap.viewer.login).toBe('viewer');
  expect(settings.bootstrap.organization).toEqual({ slug: 'acme', name: 'Acme' });
  expect(settings.clients).toEqual({
    access: {
      id: 'access',
      secret: 'access-secret',
      redirectUris: ['https://a.example/cb', 'https://b.example/cb'],
    },
    directory: { id: 'directory', secret: 'directory-secret' },
    provisioner: { id: 'provisioner', secret: 'provisioner-secret' },
  });
  expect(settings.identityLink.clientId).toBe('link-client');
  expect(settings.notifications).toEqual({ fixedDelayMs: 250, schedulerEnabled: false });
});

test('IDENTITY_ double-underscore keys override and providers parse from JSON or nesting', () => {
  const json = loadIdentitySettings({
    IDENTITY_SERVER__HOST: '127.0.0.1',
    IDENTITY_SERVER__PORT: '0',
    IDENTITY_DATABASE__POOL_MAX: '2',
    IDENTITY_IDENTITY_LINK__PROVIDERS: JSON.stringify({
      Acme: {
        issuer: 'https://idp.example',
        authorizationEndpoint: 'https://idp.example/authorize',
        tokenEndpoint: 'https://idp.example/token',
        jwksUri: 'https://idp.example/jwks',
        clientId: 'acme-client',
        clientSecret: 'acme-secret',
        scopes: ['openid', 7],
        freshAuthenticationParameter: 'prompt=login&max_age=0',
      },
      Bare: 'not an object',
    }),
  });
  expect(json.server).toEqual({ host: '127.0.0.1', port: 0 });
  expect(json.database.poolMax).toBe(2);
  expect(json.identityLink.providers.acme).toEqual({
    issuer: 'https://idp.example',
    authorizationEndpoint: 'https://idp.example/authorize',
    tokenEndpoint: 'https://idp.example/token',
    jwksUri: 'https://idp.example/jwks',
    clientId: 'acme-client',
    clientSecret: 'acme-secret',
    scopes: ['openid'],
    freshAuthenticationParameter: 'prompt=login&max_age=0',
  });
  expect(json.identityLink.providers.bare).toEqual({
    issuer: undefined,
    authorizationEndpoint: undefined,
    tokenEndpoint: undefined,
    jwksUri: undefined,
    clientId: undefined,
    clientSecret: undefined,
    scopes: undefined,
    freshAuthenticationParameter: undefined,
  });

  const nested = loadIdentitySettings({
    IDENTITY_IDENTITY_LINK__PROVIDERS__OKTA__ISSUER: 'https://okta.example',
    IDENTITY_IDENTITY_LINK__PROVIDERS__OKTA__SCOPES: 'openid, email',
  });
  expect(nested.identityLink.providers.okta?.issuer).toBe('https://okta.example');
  expect(nested.identityLink.providers.okta?.scopes).toEqual(['openid', 'email']);
  expect(
    loadIdentitySettings({ IDENTITY_IDENTITY_LINK__PROVIDERS: ' ' }).identityLink.providers,
  ).toEqual({});
});

test('rejects malformed numbers and provider documents', () => {
  expect(() => loadIdentitySettings({ PORT: 'eighty' })).toThrow('PORT must be an integer');
  expect(() => loadIdentitySettings({ IDENTITY_IDENTITY_LINK__PROVIDERS: '{' })).toThrow(
    'Identity link providers must be a JSON object',
  );
  expect(() => loadIdentitySettings({ IDENTITY_IDENTITY_LINK__PROVIDERS: '[]' })).toThrow(
    'Identity link providers must be a JSON object',
  );
});

test('the module registers, exposes, and connects from settings', async () => {
  await withContainer(async () => {
    const container = useContainer();
    expect(container.resolve<SigningKeys>(SIGNING_KEYS).kid).toBe('test-active');
    const original = IdentityModule.settings();
    try {
      const custom = loadIdentitySettings({ ISSUER_URL: 'https://custom.example' });
      IdentityModule.configure(custom);
      expect(IdentityModule.settings().issuer).toBe('https://custom.example');
      expect(container.resolve<object>(IDENTITY_SETTINGS)).toBe(custom);
    } finally {
      IdentityModule.configure(original);
    }
    const fromEnv = await IdentityModule.connectFromConfig({
      DATABASE_URL: databaseUrl('postgres'),
      IDENTITY_DATABASE__POOL_MAX: '1',
    });
    const viaSettings = await IdentityModule.connectFromConfig();
    try {
      expect(await fromEnv.first<{ one: number }>('SELECT 1 AS one')).toEqual({ one: 1 });
      expect(await viaSettings.first<{ one: number }>('SELECT 1 AS one')).toEqual({ one: 1 });
    } finally {
      await fromEnv.close?.();
      await viaSettings.close?.();
      const { useTestDatabase } = await import('./support/database.ts');
      const shared = await useTestDatabase();
      IdentityModule.connect(shared);
    }
    expect(testDatabaseName).toBe('identity_test');
  });
});

test('the notification worker starts only when the scheduler is enabled', async () => {
  await withContainer(async () => {
    const original = IdentityModule.settings();
    try {
      IdentityModule.configure(
        loadIdentitySettings({ GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED: 'false' }),
      );
      expect(IdentityModule.startNotificationWorker()).toBeUndefined();
      IdentityModule.configure(
        loadIdentitySettings({ GSIO_IDENTITY_NOTIFICATION_DELAY_MS: '60000' }),
      );
      const worker = IdentityModule.startNotificationWorker();
      expect(worker).toBeDefined();
      worker?.stop();
    } finally {
      IdentityModule.configure(original);
    }
  });
});
