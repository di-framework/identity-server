import { beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import type { RegisteredClientRepository } from '../src/authorization/domain/models.ts';
import {
  BootstrapError,
  BootstrapReconciler,
} from '../src/bootstrap/application/bootstrap-reconciler.ts';
import { Readiness } from '../src/bootstrap/application/readiness.ts';
import { IdentityModule } from '../src/composition.ts';
import type { DirectoryRepository } from '../src/directory/domain/directory-repository.ts';
import { DIRECTORY, REGISTERED_CLIENTS } from '../src/shared/domain/tokens.ts';
import { Hashing } from '../src/shared/infrastructure/crypto/hashing.ts';
import { PasswordHasher } from '../src/shared/infrastructure/crypto/passwords.ts';
import { loadIdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import type { PostgresGateway } from '../src/shared/infrastructure/postgres-gateway.ts';
import { withContainer } from './support/container-lock.ts';
import { useTestDatabase } from './support/database.ts';

let database: SqlDatabase;
const passwords = new PasswordHasher();

beforeAll(async () => {
  database = await useTestDatabase();
});

type Env = Record<
  | 'AUTH_BOOTSTRAP_OWNER_EMAIL'
  | 'AUTH_BOOTSTRAP_OWNER_LOGIN'
  | 'AUTH_BOOTSTRAP_ORGANIZATION_SLUG'
  | 'AUTH_BOOTSTRAP_VIEWER_LOGIN'
  | 'AUTH_ACCESS_CLIENT_ID'
  | 'AUTH_DIRECTORY_CLIENT_ID'
  | 'AUTH_PROVISIONER_CLIENT_ID',
  string
> &
  Record<string, string>;

function environment(overrides: Record<string, string> = {}): Env {
  const tag = Hashing.token(6)
    .toLowerCase()
    .replaceAll(/[^a-z0-9]/g, 'x');
  return {
    AUTH_BOOTSTRAP_OWNER_EMAIL: `owner-${tag}@example.com`,
    AUTH_BOOTSTRAP_OWNER_LOGIN: `owner-${tag}`,
    AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME: 'Bootstrap Owner',
    AUTH_BOOTSTRAP_OWNER_PASSWORD: 'owner-password-1',
    AUTH_BOOTSTRAP_ORGANIZATION_SLUG: `org-${tag}`,
    AUTH_BOOTSTRAP_ORGANIZATION_NAME: 'Bootstrap Org',
    AUTH_ACCESS_CLIENT_ID: `access-${tag}`,
    AUTH_ACCESS_CLIENT_SECRET: 'access-secret',
    AUTH_ACCESS_REDIRECT_URIS: 'https://access.example/callback',
    AUTH_DIRECTORY_CLIENT_ID: `directory-${tag}`,
    AUTH_DIRECTORY_CLIENT_SECRET: 'directory-secret',
    AUTH_PROVISIONER_CLIENT_ID: `provisioner-${tag}`,
    AUTH_PROVISIONER_CLIENT_SECRET: 'provisioner-secret',
    AUTH_BOOTSTRAP_VIEWER_LOGIN: '',
    ...overrides,
  };
}

function reconciler(env: Record<string, string>): BootstrapReconciler {
  return useContainer().construct(BootstrapReconciler, { 0: loadIdentitySettings(env) });
}

const directory = () => useContainer().resolve<DirectoryRepository>(DIRECTORY);
const clients = () => useContainer().resolve<RegisteredClientRepository>(REGISTERED_CLIENTS);

async function role(slug: string, userId: string): Promise<string | undefined> {
  return (await directory().findMembership(slug, userId))?.role;
}

describe('bootstrap reconciliation', () => {
  test('a fresh process can adopt an already applied bootstrap', () => {
    return withContainer(async () => {
      const service = reconciler(environment());
      expect(service.complete).toBe(false);
      service.markComplete();
      expect(service.complete).toBe(true);
    });
  });

  test('startup preparation fails closed without bootstrap configuration', async () => {
    await withContainer(async () => {
      await expect(IdentityModule.prepare()).rejects.toThrow(
        'Bootstrap owner configuration is required',
      );
    });
  });

  test('rejects incomplete configuration with the auth server messages', async () => {
    const cases: Array<[Record<string, string>, string]> = [
      [{ AUTH_BOOTSTRAP_OWNER_PASSWORD: '' }, 'Bootstrap owner configuration is required'],
      [{ AUTH_BOOTSTRAP_OWNER_EMAIL: '' }, 'Bootstrap owner configuration is required'],
      [
        { AUTH_BOOTSTRAP_ORGANIZATION_NAME: '' },
        'Bootstrap organization configuration is required',
      ],
      [{ AUTH_ACCESS_CLIENT_SECRET: '' }, 'Access Control client configuration is required'],
      [{ AUTH_DIRECTORY_CLIENT_ID: '' }, 'Directory client configuration is required'],
      [{ AUTH_PROVISIONER_CLIENT_SECRET: '' }, 'Provisioner client configuration is required'],
      [{ AUTH_ACCESS_REDIRECT_URIS: ' , ' }, 'Access Control redirect URIs are required'],
      [{ AUTH_ACCESS_REDIRECT_URIS: 'relative/path' }, 'Invalid Access Control redirect URI'],
      [
        { AUTH_ACCESS_REDIRECT_URIS: 'https://a.example/cb#x' },
        'Invalid Access Control redirect URI',
      ],
      [
        { AUTH_ACCESS_REDIRECT_URIS: 'https://a.example/cb#' },
        'Invalid Access Control redirect URI',
      ],
    ];
    for (const [overrides, message] of cases) {
      const instance = reconciler(environment(overrides));
      await expect(instance.reconcile()).rejects.toThrow(message);
      await expect(instance.reconcile()).rejects.toBeInstanceOf(BootstrapError);
      expect(instance.complete).toBe(false);
    }
  });

  test('creates the owner, organization, viewer, and three clients', async () => {
    const env = environment({
      AUTH_BOOTSTRAP_VIEWER_EMAIL: 'viewer-new@example.com',
      AUTH_BOOTSTRAP_VIEWER_LOGIN: `viewer-${Hashing.token(4)}`,
      AUTH_BOOTSTRAP_VIEWER_PASSWORD: 'viewer-password-1',
      AUTH_ACCESS_REDIRECT_URIS: 'https://access.example/callback, https://access.example/callback',
    });
    const instance = reconciler(env);
    await instance.reconcile();
    expect(instance.complete).toBe(true);

    const owner = await directory().findUserByEmailOrLogin(env.AUTH_BOOTSTRAP_OWNER_EMAIL, '');
    expect(owner).toMatchObject({
      login: env.AUTH_BOOTSTRAP_OWNER_LOGIN,
      displayName: 'Bootstrap Owner',
      emailVerified: true,
      status: 'active',
      systemRole: 'platform_admin',
    });
    expect(await passwords.verify('owner-password-1', owner?.passwordHash)).toBe(true);
    expect(await role(env.AUTH_BOOTSTRAP_ORGANIZATION_SLUG, owner?.id ?? '')).toBe('owner');

    const viewer = await directory().findUserByEmailOrLogin('', env.AUTH_BOOTSTRAP_VIEWER_LOGIN);
    expect(viewer).toMatchObject({
      displayName: env.AUTH_BOOTSTRAP_VIEWER_LOGIN,
      systemRole: 'user',
      status: 'active',
      emailVerified: true,
    });
    expect(await role(env.AUTH_BOOTSTRAP_ORGANIZATION_SLUG, viewer?.id ?? '')).toBe('member');

    const access = await clients().find(env.AUTH_ACCESS_CLIENT_ID);
    expect(access).toMatchObject({
      clientName: env.AUTH_ACCESS_CLIENT_ID,
      authenticationMethods: ['client_secret_basic', 'client_secret_post'],
      grantTypes: ['authorization_code', 'refresh_token'],
      redirectUris: ['https://access.example/callback'],
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      settings: { requireProofKey: true, requireAuthorizationConsent: true },
      organizationSlug: null,
      revokedAt: null,
    });
    expect(await passwords.verify('access-secret', access?.secretHash)).toBe(true);
    expect(await clients().find(env.AUTH_DIRECTORY_CLIENT_ID)).toMatchObject({
      authenticationMethods: ['client_secret_basic'],
      grantTypes: ['client_credentials'],
      scopes: ['directory:read'],
      settings: { requireProofKey: false, requireAuthorizationConsent: false },
    });
    expect((await clients().find(env.AUTH_PROVISIONER_CLIENT_ID))?.scopes).toEqual([
      'admin:read',
      'admin:write',
      'directory:read',
    ]);
    const audits = await database.query(`SELECT 1 FROM auth_audit_records WHERE target = ?`, [
      owner?.id,
    ]);
    expect(audits).toEqual([]);
  });

  test('re-runs keep existing rows and only repair what the auth server repairs', async () => {
    const env = environment();
    await reconciler(env).reconcile();
    const owner = await directory().findUserByEmailOrLogin(env.AUTH_BOOTSTRAP_OWNER_EMAIL, '');
    const ownerId = owner?.id ?? '';
    await database.run(
      `UPDATE users SET password_hash = NULL, system_role = 'user', status = 'archived' WHERE id = ?`,
      [ownerId],
    );
    await database.run(
      `UPDATE oauth2_registered_client SET authorization_grant_types = 'client_credentials,refresh_token'
       WHERE client_id = ?`,
      [env.AUTH_PROVISIONER_CLIENT_ID],
    );
    await database.run(`DELETE FROM oauth_client_lifecycle WHERE client_id = ?`, [
      env.AUTH_DIRECTORY_CLIENT_ID,
    ]);
    const viewerLogin = `viewer-${Hashing.token(4)}`;
    await directory().insertAccount({
      id: crypto.randomUUID(),
      login: viewerLogin,
      email: `${viewerLogin}@example.com`,
      displayName: 'Existing Viewer',
      passwordHash: await passwords.hash('kept-viewer-password'),
      emailVerified: false,
      systemRole: 'platform_admin',
      status: 'pending',
    });

    const second = {
      ...env,
      AUTH_BOOTSTRAP_OWNER_PASSWORD: 'second-owner-password',
      AUTH_BOOTSTRAP_ORGANIZATION_NAME: 'Renamed Org',
      AUTH_ACCESS_CLIENT_SECRET: 'rotated-access-secret',
      AUTH_ACCESS_REDIRECT_URIS: 'https://new.example/cb',
      AUTH_PROVISIONER_CLIENT_SECRET: 'rotated-provisioner-secret',
      AUTH_BOOTSTRAP_VIEWER_EMAIL: `${viewerLogin}@example.com`,
      AUTH_BOOTSTRAP_VIEWER_LOGIN: viewerLogin,
      AUTH_BOOTSTRAP_VIEWER_PASSWORD: 'ignored-viewer-password',
    };
    await reconciler(second).reconcile();
    const repaired = await directory().findUser(ownerId);
    expect(repaired).toMatchObject({ systemRole: 'platform_admin', status: 'active' });
    expect(await passwords.verify('second-owner-password', repaired?.passwordHash)).toBe(true);
    await reconciler({ ...second, AUTH_BOOTSTRAP_OWNER_PASSWORD: 'third-password' }).reconcile();
    const kept = await directory().findUser(ownerId);
    expect(kept?.passwordHash).toBe(repaired?.passwordHash ?? '');

    expect((await directory().findOrganization(env.AUTH_BOOTSTRAP_ORGANIZATION_SLUG))?.name).toBe(
      'Bootstrap Org',
    );
    const access = await clients().find(env.AUTH_ACCESS_CLIENT_ID);
    expect(access?.redirectUris).toEqual(['https://new.example/cb']);
    expect(await passwords.verify('rotated-access-secret', access?.secretHash)).toBe(true);
    const provisioner = await clients().find(env.AUTH_PROVISIONER_CLIENT_ID);
    expect(provisioner?.grantTypes).toEqual(['client_credentials', 'refresh_token']);
    expect(await passwords.verify('rotated-provisioner-secret', provisioner?.secretHash)).toBe(
      true,
    );
    expect((await clients().find(env.AUTH_DIRECTORY_CLIENT_ID))?.revokedAt).toBeNull();
    expect(
      await database.first(`SELECT 1 FROM oauth_client_lifecycle WHERE client_id = ?`, [
        env.AUTH_DIRECTORY_CLIENT_ID,
      ]),
    ).not.toBeNull();

    const viewer = await directory().findUserByEmailOrLogin('', viewerLogin);
    expect(viewer).toMatchObject({
      status: 'active',
      systemRole: 'platform_admin',
      emailVerified: false,
    });
    expect(await passwords.verify('kept-viewer-password', viewer?.passwordHash)).toBe(true);
    expect(await role(env.AUTH_BOOTSTRAP_ORGANIZATION_SLUG, viewer?.id ?? '')).toBe('member');
  });

  test('requires a viewer email once a viewer login and password are set, and rolls back', async () => {
    const env = environment({
      AUTH_BOOTSTRAP_VIEWER_LOGIN: 'viewer-without-email',
      AUTH_BOOTSTRAP_VIEWER_PASSWORD: 'viewer-password-1',
    });
    await expect(reconciler(env).reconcile()).rejects.toThrow(
      'Bootstrap viewer email is required when viewer login is set',
    );
    expect(
      await directory().findOrganization(env.AUTH_BOOTSTRAP_ORGANIZATION_SLUG),
    ).toBeUndefined();
    await reconciler({ ...env, AUTH_BOOTSTRAP_VIEWER_PASSWORD: '' }).reconcile();
    expect(await directory().findUserByEmailOrLogin('', 'viewer-without-email')).toBeUndefined();
  });
});

describe('readiness', () => {
  function readiness(
    env: Record<string, string>,
    gateway: Pick<PostgresGateway, 'one'>,
    complete: boolean,
  ): Readiness {
    return new Readiness(gateway as PostgresGateway, loadIdentitySettings(env), {
      complete,
    } as BootstrapReconciler);
  }

  const live = { one: async () => ({ ok: 1 }) } as unknown as Pick<PostgresGateway, 'one'>;
  const mail = { SMTP_HOST: 'smtp.example', SMTP_FROM: 'no-reply@example.com' };

  test('is ok only when every check passes, in the auth server key order', async () => {
    const ready = await readiness(mail, live, true).check();
    expect(ready).toEqual({
      database: true,
      signing_key: true,
      smtp: true,
      bootstrap: true,
      ok: true,
    });
    expect(Object.keys(ready)).toEqual(['database', 'signing_key', 'smtp', 'bootstrap', 'ok']);
    expect(await readiness({ SMTP_HOST: 'smtp.example' }, live, true).check()).toMatchObject({
      smtp: false,
      ok: false,
    });
    expect(await readiness(mail, live, false).check()).toMatchObject({
      bootstrap: false,
      ok: false,
    });
  });

  test('a failing or hanging database is not ready', async () => {
    const failing = { one: async () => Promise.reject(new Error('down')) };
    expect(await readiness(mail, failing as never, true).check()).toMatchObject({
      database: false,
      ok: false,
    });
    const hanging = { one: () => new Promise(() => {}) };
    expect(await readiness(mail, hanging as never, true).check(10)).toMatchObject({
      database: false,
    });
    await withContainer(async () => {
      const real = useContainer().resolve(Readiness);
      expect((await real.check()).database).toBe(true);
    });
  });
});
