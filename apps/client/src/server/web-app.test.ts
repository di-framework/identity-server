import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { DirectoryRepository } from '@di-framework/identity/src/directory/domain/directory-repository.ts';
import type { LinkRepository } from '@di-framework/identity/src/linking/domain/identity-link.ts';
import {
  DIRECTORY,
  IDENTITY_SETTINGS,
  LINKS,
} from '@di-framework/identity/src/shared/domain/tokens.ts';
import { PasswordHasher } from '@di-framework/identity/src/shared/infrastructure/crypto/passwords.ts';
import {
  type IdentitySettings,
  loadIdentitySettings,
} from '@di-framework/identity/src/shared/infrastructure/identity-settings.ts';
import { useIsolatedDatabase } from '@di-framework/identity/tests/support/database.ts';
import { FakeIdp } from '@di-framework/identity/tests/support/fake-idp.ts';
import {
  type RecordingMailSender,
  useRecordingMail,
} from '@di-framework/identity/tests/support/mail.ts';
import type { PageModel } from '../domain/page-model.ts';
import { takeEmbeddedPage } from '../ui/app.tsx';
import { handle, indexDocument, scriptJson } from './handler.ts';
import { cookie } from './web-app.ts';

let isolated: Awaited<ReturnType<typeof useIsolatedDatabase>>;
let mail: RecordingMailSender;
let idp: FakeIdp;
let original: IdentitySettings;
const directory = () => useContainer().resolve<DirectoryRepository>(DIRECTORY);
const ids = { admin: '', owner: '', member: '', inactive: '', acme: '', beta: '' };
const PASSWORD = 'correct-horse-battery';

/** A cookie jar over `handle`, as a browser would use the pages. */
class Browser {
  private jar = new Map<string, string>();
  csrf = '';

  async send(
    method: string,
    path: string,
    options: { form?: Record<string, string>; json?: boolean; csrf?: boolean } = {},
  ): Promise<Response> {
    const headers = new Headers();
    if (this.jar.size > 0) {
      headers.set('cookie', [...this.jar].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    if (options.json) headers.set('accept', 'application/json');
    let body: string | undefined;
    if (options.form || method === 'POST') {
      headers.set('content-type', 'application/x-www-form-urlencoded');
      const form = new URLSearchParams(options.form);
      if (options.csrf !== false) form.set('_csrf', this.csrf);
      body = form.toString();
    }
    const response = await handle(
      new Request(`https://identity.test${path}`, { method, headers, body }),
    );
    for (const header of response.headers.getSetCookie()) {
      const [pair = '', ...attributes] = header.split(';');
      const [name = '', value = ''] = pair.split('=');
      if (attributes.some((part) => part.trim() === 'Max-Age=0')) this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return response;
  }

  async page(path: string, status = 200): Promise<PageModel> {
    const response = await this.send('GET', path, { json: true });
    expect([path, response.status]).toEqual([path, status]);
    const model = (await response.json()) as PageModel;
    this.csrf = model.csrf;
    return model;
  }

  async post(path: string, form: Record<string, string> = {}): Promise<Response> {
    return this.send('POST', path, { form });
  }

  /** Embedded page model from an HTML response. */
  async embedded(response: Response): Promise<PageModel> {
    const html = await response.text();
    const json = /window\.__IDENTITY_PAGE__ = (.*);<\/script>/.exec(html)?.[1] ?? 'null';
    return JSON.parse(json) as PageModel;
  }

  cookie(name: string): string | undefined {
    return this.jar.get(name);
  }

  setCookie(name: string, value: string): void {
    this.jar.set(name, value);
  }
}

async function signedIn(login: string): Promise<Browser> {
  const browser = new Browser();
  await browser.page('/login');
  const response = await browser.post('/login', { username: login, password: PASSWORD });
  expect(response.status).toBe(303);
  await browser.page('/account/identity-links');
  return browser;
}

async function account(
  login: string,
  options: { role?: string; status?: string; password?: boolean } = {},
) {
  const id = crypto.randomUUID();
  await directory().insertAccount({
    id,
    login,
    email: `${login}@example.com`,
    displayName: `${login} name`,
    passwordHash: options.password === false ? null : await new PasswordHasher().hash(PASSWORD),
    emailVerified: true,
    systemRole: options.role ?? 'user',
    status: options.status ?? 'active',
  });
  return id;
}

beforeAll(async () => {
  isolated = await useIsolatedDatabase('identity_web_test');
  mail = useRecordingMail();
  idp = new FakeIdp();
  original = useContainer().resolve<IdentitySettings>(IDENTITY_SETTINGS);
  const settings = loadIdentitySettings({
    ISSUER_URL: 'https://identity.test',
    SERVER_SERVLET_SESSION_COOKIE_SECURE: 'false',
    AUTH_ACTIVE_PRIVATE_JWK: original.jwk.activePrivate,
  });
  useContainer().registerValue(IDENTITY_SETTINGS, {
    ...settings,
    identityLink: { clientId: 'x', providers: { acme: idp.settings() } },
  });
  ids.admin = await account('admin', { role: 'platform_admin' });
  ids.owner = await account('owner');
  ids.member = await account('member');
  ids.inactive = await account('inactive', { status: 'archived' });
  ids.acme = crypto.randomUUID();
  ids.beta = crypto.randomUUID();
  await directory().insertOrganization({ id: ids.acme, slug: 'acme', name: 'Acme' });
  await directory().insertOrganization({ id: ids.beta, slug: 'beta', name: 'Beta' });
  await directory().upsertMembership(ids.acme, ids.owner, 'owner');
  await directory().upsertMembership(ids.acme, ids.member, 'member');
});

afterAll(async () => {
  useContainer().registerValue(IDENTITY_SETTINGS, original);
  idp.stop();
  await isolated.release();
});

describe('shell and transport', () => {
  test('renders HTML with the page model embedded, JSON on request, and 405 otherwise', async () => {
    const browser = new Browser();
    const html = await browser.send('GET', '/login');
    expect(html.headers.get('content-type')).toContain('text/html');
    expect(html.headers.get('set-cookie')).toContain('identity_session=');
    expect(html.headers.get('set-cookie')).not.toContain('Secure');
    expect(await browser.embedded(html)).toMatchObject({ page: 'login', signedIn: false });
    expect(
      (await handle(new Request('https://identity.test/login', { method: 'PUT' }))).status,
    ).toBe(405);
    expect(scriptJson({ a: '</script><b>&\u2028\u2029' })).toBe(
      '{"a":"\\u003c/script\\u003e\\u003cb\\u003e\\u0026\\u2028\\u2029"}',
    );
    expect(indexDocument('file:///nowhere/src/server/handler.ts').pathname).toBe(
      '/nowhere/src/server/embedded/index.html',
    );
    expect(cookie('a=1; b; c=2', 'c')).toBe('2');
    expect(cookie(null, 'c')).toBeUndefined();
    window.__IDENTITY_PAGE__ = { page: 'login', csrf: 'x', signedIn: false, displayName: null };
    expect(takeEmbeddedPage()?.page).toBe('login');
    expect(takeEmbeddedPage()).toBeNull();
  });

  test('protected pages redirect to login, remember the page, and return there', async () => {
    const browser = new Browser();
    const html = await browser.send('GET', '/admin/users?q=x');
    expect(html.status).toBe(302);
    expect(html.headers.get('location')).toBe('/login');
    expect(await browser.page('/admin/users', 401)).toMatchObject({ page: 'unauthenticated' });
    await browser.send('GET', '/admin/users?q=owner');
    // The browser's own favicon request and JSON page-model fetches do not replace it.
    expect((await browser.send('GET', '/favicon.ico')).status).toBe(302);
    await browser.page('/admin/organizations', 401);
    await browser.page('/login');
    const login = await browser.post('/login', { username: 'ADMIN', password: PASSWORD });
    expect(login.headers.get('location')).toBe('/admin/users?q=owner');
    const anonymous = new Browser();
    await anonymous.page('/login');
    expect(
      (await anonymous.post('/account/password', { password: 'x' })).headers.get('location'),
    ).toBe('/login');
  });
});

describe('sign-in, passwords, and passwordless', () => {
  test('form login rotates the session and logout clears it', async () => {
    const browser = new Browser();
    await browser.page('/login');
    const before = browser.cookie('identity_session');
    expect(
      (await browser.post('/login', { username: 'admin', password: 'wrong' })).headers.get(
        'location',
      ),
    ).toBe('/login?error');
    expect(
      (await browser.post('/login', { username: 'inactive', password: PASSWORD })).headers.get(
        'location',
      ),
    ).toBe('/login?error');
    const ok = await browser.post('/login', { username: 'admin@example.com', password: PASSWORD });
    expect(ok.headers.get('location')).toBe('/');
    expect(browser.cookie('identity_session')).not.toBe(before);
    expect((await browser.send('GET', '/')).headers.get('location')).toBe(
      '/account/identity-links',
    );
    const signed = await browser.page('/account/identity-links');
    expect(signed).toMatchObject({ signedIn: true, displayName: 'admin name' });
    const forged = await browser.send('POST', '/admin/logout', { form: {}, csrf: false });
    expect(forged.status).toBe(403);
    expect(await browser.embedded(forged)).toMatchObject({ page: 'error', title: 'Forbidden' });
    const out = await browser.post('/admin/logout');
    expect(out.headers.get('location')).toBe('/login?logout=1');
    expect(browser.cookie('identity_session')).toBeUndefined();
    expect(await browser.page('/account/identity-links', 401)).toMatchObject({
      page: 'unauthenticated',
    });
  });

  test('passwordless mails, stages the token in a cookie, and signs in on confirm', async () => {
    const pendingId = await account('newcomer', { status: 'pending', password: false });
    const browser = new Browser();
    expect(await browser.page('/passwordless')).toMatchObject({
      page: 'passwordless',
      notice: false,
    });
    const sent = await browser.send('POST', '/passwordless', {
      form: { email: 'newcomer@example.com' },
      csrf: false,
    });
    expect(sent.status).toBe(200);
    expect(await browser.embedded(sent)).toMatchObject({ page: 'passwordless', notice: true });
    const token = mail.lastToken('newcomer@example.com') ?? '';
    expect(await browser.page('/passwordless/confirm')).toMatchObject({
      page: 'passwordless-confirm',
      unavailable: false,
    });
    expect(await browser.page('/passwordless/confirm?token=bad', 400)).toMatchObject({
      unavailable: true,
    });
    const staged = await browser.send('GET', `/passwordless/confirm?token=${token}`);
    expect(staged.status).toBe(303);
    expect(staged.headers.get('location')).toBe('/passwordless/confirm');
    expect(staged.headers.get('set-cookie')).toBe(
      `gsio_passwordless_challenge=${token}; Max-Age=900; Path=/passwordless/confirm; HttpOnly; SameSite=Strict`,
    );
    expect((await browser.page('/account/password', 401)).page).toBe('unauthenticated');
    const confirmed = await browser.send('POST', '/passwordless/confirm', { csrf: false });
    expect(confirmed.headers.get('location')).toBe('/account/password');
    expect(browser.cookie('gsio_passwordless_challenge')).toBeUndefined();
    expect((await directory().findUser(pendingId))?.status).toBe('active');
    expect(await browser.page('/account/password')).toMatchObject({
      page: 'password',
      error: null,
    });
    const short = await browser.post('/account/password', { password: 'short' });
    expect(short.status).toBe(400);
    expect(await browser.embedded(short)).toMatchObject({ page: 'password', error: 'short' });
    expect(
      (await browser.post('/account/password', { password: 'a-brand-new-password' })).headers.get(
        'location',
      ),
    ).toBe('/account/password?updated=1');
    browser.setCookie('gsio_passwordless_challenge', token);
    const replay = await browser.send('POST', '/passwordless/confirm', { csrf: false });
    expect(replay.headers.get('location')).toBe('/passwordless/confirm?error=invalid');
  });

  test('the consent page is built from the request and does not name the client', async () => {
    const browser = await signedIn('member');
    expect(
      await browser.page(
        '/oauth2/consent?client_id=cli_1&scope=openid+profile,email%20profile&state=abc',
      ),
    ).toMatchObject({
      page: 'consent',
      clientId: 'cli_1',
      state: 'abc',
      openid: true,
      scopes: ['profile', 'email'],
    });
    expect(await browser.page('/oauth2/consent?client_id=cli_1')).toMatchObject({
      openid: false,
      scopes: [],
      state: null,
    });
    expect(await browser.page('/oauth2/consent', 400)).toMatchObject({
      page: 'error',
      title: 'Bad Request',
    });
    expect(await browser.page('/nowhere', 404)).toMatchObject({ page: 'not-found' });
  });
});

describe('admin pages', () => {
  test('users: list, invite, detail, archive, restore, reset, and denial reasons', async () => {
    const admin = await signedIn('admin');
    const list = await admin.page('/admin/users?q=owner&status=all');
    expect(list).toMatchObject({ page: 'users', query: 'owner', status: 'all' });
    expect((list as { users: Array<{ login: string }> }).users.map((u) => u.login)).toEqual([
      'owner',
    ]);
    expect(await admin.page('/admin/users?status=archived')).toMatchObject({ status: 'archived' });
    expect(await admin.page('/admin/users')).toMatchObject({ status: 'all' });
    expect(await admin.page('/admin/users/invite')).toMatchObject({
      page: 'invite',
      organizations: [{ id: 'acme' }, { id: 'beta' }],
    });
    const blank = await admin.post('/admin/users/invite', { login: '', email: '' });
    expect(blank.status).toBe(400);
    expect(await admin.embedded(blank)).toMatchObject({ page: 'invite', error: 'required' });
    const duplicate = await admin.post('/admin/users/invite', {
      login: 'owner',
      email: 'x@y.z',
      displayName: '',
    });
    expect(duplicate.status).toBe(409);
    expect(await admin.embedded(duplicate)).toMatchObject({ error: 'conflict' });
    const invited = await admin.post('/admin/users/invite', {
      login: 'invitee',
      email: 'invitee@example.com',
      displayName: 'Invitee',
      orgSlug: 'acme',
      role: 'member',
    });
    const location = invited.headers.get('location') ?? '';
    expect(location).toMatch(/^\/admin\/users\/[0-9a-f-]+\?invited=1$/);
    const detail = await admin.page(location);
    expect(detail).toMatchObject({
      page: 'user',
      banner: 'invited',
      showArchive: true,
      showRestore: false,
      showPasswordReset: true,
      user: { login: 'invitee', memberships: [{ slug: 'acme', organizationId: 'acme' }] },
    });
    const id = location.split('/')[3]?.split('?')[0] ?? '';
    expect((await admin.post(`/admin/users/${id}/password-reset`)).headers.get('location')).toBe(
      `/admin/users/${id}?reset=1`,
    );
    expect(await admin.page(`/admin/users/${id}?reset=1`)).toMatchObject({
      banner: 'password-reset',
    });
    expect((await admin.post(`/admin/users/${id}/archive`)).headers.get('location')).toBe(
      `/admin/users/${id}?archived=1`,
    );
    expect(await admin.page(`/admin/users/${id}?archived=1`)).toMatchObject({
      banner: 'archived',
      showRestore: true,
      showArchive: false,
    });
    expect((await admin.post(`/admin/users/${id}/restore`)).headers.get('location')).toBe(
      `/admin/users/${id}?restored=1`,
    );
    const blocked = await admin.post(`/admin/users/${ids.admin}/archive`);
    const blockedLocation = blocked.headers.get('location') ?? '';
    expect(blockedLocation).toBe(
      `/admin/users/${ids.admin}?error=Cannot+archive+the+last+active+platform+administrator`,
    );
    expect(await admin.page(blockedLocation)).toMatchObject({
      banner: 'blocked',
      message: 'Cannot archive the last active platform administrator',
    });
    expect(await admin.page(`/admin/users/${crypto.randomUUID()}`, 404)).toMatchObject({
      page: 'error',
      title: 'User Not Found',
    });
    const missing = await admin.post(`/admin/users/${crypto.randomUUID()}/restore`);
    expect(missing.status).toBe(404);

    const member = await signedIn('member');
    expect(await member.page('/admin/users', 403)).toMatchObject({
      page: 'denied',
      reason: 'member',
    });
    const owner = await signedIn('owner');
    expect(await owner.page('/admin/organizations/create', 403)).toMatchObject({
      reason: 'platform',
    });
    await directory().updateAccount(ids.owner, { status: 'archived' });
    expect(await owner.page('/admin/users', 403)).toMatchObject({ reason: 'inactive' });
    await directory().updateAccount(ids.owner, { status: 'active' });
    expect(await admin.page('/admin/users/x/y', 404)).toMatchObject({ page: 'not-found' });
  });

  test('organizations: list, create, detail, settings, and archive', async () => {
    const admin = await signedIn('admin');
    expect(await admin.page('/admin/organizations')).toMatchObject({
      page: 'organizations',
      canCreate: true,
      status: 'all',
    });
    expect(await admin.page('/admin/organizations?status=all')).toMatchObject({ status: 'all' });
    expect(await admin.page('/admin/organizations/create')).toMatchObject({
      page: 'create-organization',
      error: null,
    });
    const bad = await admin.post('/admin/organizations/create', { slug: 'Bad Slug!', name: '' });
    expect(bad.status).toBe(400);
    expect(await admin.embedded(bad)).toMatchObject({ error: 'slug' });
    const dupe = await admin.post('/admin/organizations/create', { slug: 'acme', name: '' });
    expect(await admin.embedded(dupe)).toMatchObject({ error: 'duplicate-slug' });
    const created = await admin.post('/admin/organizations/create', {
      slug: 'gamma',
      name: 'Gamma',
    });
    const location = created.headers.get('location') ?? '';
    expect(location).toMatch(/\?created=1$/);
    expect(await admin.page(location)).toMatchObject({
      page: 'organization',
      banner: 'created',
      canEdit: true,
      canArchive: true,
      organization: { slug: 'gamma', status: 'active', memberCount: 0 },
    });
    const id = location.split('/')[3]?.split('?')[0] ?? '';
    expect(
      (await admin.post(`/admin/organizations/${id}/settings`, { name: 'Gamma Two' })).headers.get(
        'location',
      ),
    ).toBe(`/admin/organizations/${id}?updated=1`);
    expect(await admin.page(`/admin/organizations/${id}?updated=1`)).toMatchObject({
      banner: 'saved',
      organization: { name: 'Gamma Two' },
    });
    expect((await admin.post(`/admin/organizations/${id}/archive`)).headers.get('location')).toBe(
      `/admin/organizations/${id}?archived=1`,
    );
    expect(await admin.page(`/admin/organizations/${id}?archived=1`)).toMatchObject({
      banner: 'archived',
      organization: { status: 'archived' },
      canArchive: false,
    });
    expect(await admin.page(`/admin/organizations/${crypto.randomUUID()}`, 404)).toMatchObject({
      title: 'Organization Not Found',
    });
    const owner = await signedIn('owner');
    expect(await owner.page(`/admin/organizations/${ids.acme}`)).toMatchObject({
      canEdit: true,
      canArchive: false,
    });
  });

  test('memberships: list, add, role change, and remove with the last-owner block', async () => {
    const owner = await signedIn('owner');
    expect(await owner.page('/admin/memberships')).toMatchObject({
      page: 'memberships',
      organizationId: '',
      organizations: [{ id: 'acme' }],
    });
    const listed = await owner.page('/admin/memberships?orgSlug=acme');
    expect(
      (listed as { members: Array<{ login: string; organizationId: string }> }).members.map((m) => [
        m.login,
        m.organizationId,
      ]),
    ).toContainEqual(['owner', 'acme']);
    const added = await owner.post('/admin/memberships/add', {
      orgSlug: 'acme',
      userLoginOrEmail: 'admin',
      role: 'member',
    });
    expect(added.headers.get('location')).toBe('/admin/memberships?orgSlug=acme&added=1');
    expect(await owner.page('/admin/memberships?orgSlug=acme&added=1')).toMatchObject({
      banner: 'added',
    });
    const demote = await owner.post('/admin/memberships/role-change', {
      orgSlug: 'acme',
      userId: ids.owner,
      newRole: 'member',
    });
    const location = demote.headers.get('location') ?? '';
    expect(location).toBe('/admin/memberships?orgSlug=acme&error=Cannot+demote+last+owner');
    expect(await owner.page(location)).toMatchObject({
      banner: 'blocked',
      message: 'Cannot demote last owner',
    });
    expect(
      (
        await owner.post('/admin/memberships/role-change', {
          orgSlug: 'acme',
          userId: ids.admin,
          newRole: 'owner',
        })
      ).headers.get('location'),
    ).toContain('changed=1');
    expect(
      (
        await owner.post('/admin/memberships/remove', { orgSlug: 'acme', userId: ids.admin })
      ).headers.get('location'),
    ).toContain('removed=1');
  });

  test('oauth clients: register shows the secret once, then edit, rotate, and revoke', async () => {
    const owner = await signedIn('owner');
    expect(await owner.page('/admin/oauth-clients/register')).toMatchObject({
      page: 'register-client',
      organizations: [{ id: 'acme' }],
    });
    const foreign = await owner.post('/admin/oauth-clients/register', {
      orgSlug: 'missing',
      clientName: 'x',
    });
    expect(foreign.status).toBe(403);
    const admin = await signedIn('admin');
    await admin.page('/admin/oauth-clients/register');
    const invalid = await admin.post('/admin/oauth-clients/register', {
      orgSlug: 'missing',
      clientName: 'x',
    });
    expect(invalid.status).toBe(400);
    expect(await admin.embedded(invalid)).toMatchObject({ error: 'invalid-org' });
    const registered = await owner.post('/admin/oauth-clients/register', {
      orgSlug: 'acme',
      clientName: 'Portal',
      redirectUris: 'https://portal.example/cb',
      grantTypes: '',
      scopes: '',
    });
    const location = registered.headers.get('location') ?? '';
    expect(location).toMatch(/^\/admin\/oauth-clients\/cli_[0-9a-f]{16}\?newSecret=1$/);
    expect(location).not.toContain('secret=');
    const shown = await owner.page(location);
    expect(shown).toMatchObject({
      page: 'client',
      banner: 'registered',
      secret: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      canModify: true,
      client: {
        name: 'Portal',
        grantTypes: 'authorization_code, refresh_token',
        scopes: 'openid, profile, email',
      },
    });
    expect(await owner.page(location)).toMatchObject({ secret: null });
    const id = location.split('/')[3]?.split('?')[0] ?? '';
    expect(await owner.page('/admin/oauth-clients?orgSlug=acme&status=active')).toMatchObject({
      page: 'clients',
      clients: [{ id, organization: 'acme', name: 'Portal', status: 'active' }],
    });
    expect(await owner.page('/admin/oauth-clients')).toMatchObject({ status: 'all' });
    expect(
      (
        await owner.post(`/admin/oauth-clients/${id}/edit`, {
          clientName: 'Portal 2',
          redirectUris: '',
          grantTypes: 'client_credentials',
          scopes: 'openid',
        })
      ).headers.get('location'),
    ).toBe(`/admin/oauth-clients/${id}?updated=1`);
    // Owners cannot grant the scopes the admin and directory APIs accept.
    const escalated = await owner.post(`/admin/oauth-clients/${id}/edit`, {
      clientName: 'Portal 2',
      grantTypes: 'client_credentials',
      scopes: 'admin:read',
    });
    expect(escalated.status).toBe(400);
    expect(await owner.embedded(escalated)).toMatchObject({
      page: 'error',
      title: 'Scope Not Allowed',
    });
    const privileged = await owner.post('/admin/oauth-clients/register', {
      orgSlug: 'acme',
      clientName: 'Escalate',
      grantTypes: 'client_credentials',
      scopes: 'admin:write',
    });
    expect(privileged.status).toBe(400);
    expect(await owner.embedded(privileged)).toMatchObject({ error: 'scope-not-allowed' });
    expect(await owner.page(`/admin/oauth-clients/${id}?updated=1`)).toMatchObject({
      banner: 'metadata-updated',
      client: { name: 'Portal 2' },
    });
    const rotated = await owner.post(`/admin/oauth-clients/${id}/rotate-secret`);
    expect(rotated.headers.get('location')).toBe(`/admin/oauth-clients/${id}?rotatedSecret=1`);
    expect(await owner.page(`/admin/oauth-clients/${id}?rotatedSecret=1`)).toMatchObject({
      banner: 'secret-rotated',
      secret: expect.any(String),
    });
    await owner.post(`/admin/oauth-clients/${id}/rotate-secret`);
    const other = await owner.post('/admin/oauth-clients/register', {
      orgSlug: 'acme',
      clientName: 'Other',
    });
    expect(await owner.page(other.headers.get('location') ?? '')).toMatchObject({
      secret: expect.any(String),
    });
    expect((await owner.post(`/admin/oauth-clients/${id}/revoke`)).headers.get('location')).toBe(
      `/admin/oauth-clients/${id}?revoked=1`,
    );
    expect(await owner.page(`/admin/oauth-clients/${id}?revoked=1`)).toMatchObject({
      banner: 'revoked',
      canModify: false,
      client: { status: 'revoked' },
    });
    expect(
      (await owner.post(`/admin/oauth-clients/missing/edit`, { clientName: 'x' })).status,
    ).toBe(404);
  });

  test('audit list and detail', async () => {
    const admin = await signedIn('admin');
    const list = await admin.page('/admin/audit?action=admin.&actor=&target=&from=&to=');
    expect(list).toMatchObject({ page: 'audit', filters: { action: 'admin.' } });
    const records = (list as { records: Array<{ id: string }>; count: number }).records;
    expect(records.length).toBe((list as { count: number }).count);
    expect(await admin.page(`/admin/audit/${records[0]?.id}`)).toMatchObject({
      page: 'audit-record',
      record: { id: records[0]?.id },
    });
    expect(await admin.page(`/admin/audit/${crypto.randomUUID()}`, 404)).toMatchObject({
      title: 'Audit Record Not Found',
    });
    expect(await admin.page('/admin/audit')).toMatchObject({
      filters: { action: '', actor: '', target: '', from: '', to: '' },
    });
  });
});

describe('linked identities', () => {
  test('start, callback, confirm, cancel, and unlink through the account pages', async () => {
    const browser = await signedIn('member');
    expect(await browser.page('/account/identity-links')).toMatchObject({
      page: 'links',
      accountName: 'member name',
      links: [],
    });
    expect(await browser.page('/account/identity-links/start?provider=unknown', 400)).toMatchObject(
      {
        page: 'link-unavailable',
        message: 'Identity provider is not configured',
      },
    );
    const started = await browser.send('GET', '/account/identity-links/start?provider=acme');
    expect(started.status).toBe(303);
    const state = idp.rememberAuthorization(started.headers.get('location') ?? '');
    expect(
      await browser.page('/account/identity-links/callback?error=access_denied', 400),
    ).toMatchObject({
      message: 'External identity provider returned an error or incomplete authorization payload.',
    });
    const callback = await browser.send(
      'GET',
      `/account/identity-links/callback?state=${state}&code=abc`,
    );
    expect(callback.headers.get('location')).toBe('/account/identity-links/confirm');
    const confirm = await browser.page('/account/identity-links/confirm');
    expect(confirm).toMatchObject({
      page: 'link-confirm',
      account: { login: 'member', email: 'member@example.com' },
      external: { provider: 'acme', issuer: idp.issuer, providerEmail: 'linked@provider.example' },
    });
    expect(await browser.page('/account/identity-links/confirm?token=nope', 400)).toMatchObject({
      page: 'link-unavailable',
    });
    expect((await browser.post('/account/identity-links/confirm')).headers.get('location')).toBe(
      '/account/identity-links?linked=1',
    );
    const linked = await browser.page('/account/identity-links?linked=1');
    expect(linked).toMatchObject({
      banner: 'linked',
      links: [{ provider: 'acme', issuer: idp.issuer }],
    });
    const linkId = (linked as { links: Array<{ id: string }> }).links[0]?.id ?? '';
    expect((await browser.post('/account/identity-links/confirm')).status).toBe(400);

    idp.subject = `second-${crypto.randomUUID()}`;
    const second = idp.rememberAuthorization(
      (await browser.send('GET', '/account/identity-links/start?provider=acme')).headers.get(
        'location',
      ) ?? '',
    );
    await browser.send('GET', `/account/identity-links/callback?state=${second}&code=c`);
    expect((await browser.post('/account/identity-links/cancel')).headers.get('location')).toBe(
      '/account/identity-links?canceled=1',
    );
    expect(await browser.page('/account/identity-links/confirm', 400)).toMatchObject({
      page: 'link-unavailable',
    });

    expect(await browser.page('/account/identity-links/unlink/confirm', 400)).toMatchObject({
      page: 'link-unavailable',
    });
    const startUnlink = await browser.post('/account/identity-links/unlink/start', { id: linkId });
    expect(startUnlink.headers.get('location')).toBe('/account/identity-links/unlink/confirm');
    expect(await browser.page('/account/identity-links/unlink/confirm')).toMatchObject({
      page: 'unlink-confirm',
      provider: 'acme',
      issuer: idp.issuer,
    });
    expect(
      (await browser.post('/account/identity-links/unlink/confirm')).headers.get('location'),
    ).toBe('/account/identity-links?unlinked=1');
    expect((await browser.post('/account/identity-links/unlink/confirm')).status).toBe(400);
    const notMine = await browser.post('/account/identity-links/unlink/start', {
      id: crypto.randomUUID(),
    });
    expect(notMine.status).toBe(403);

    const leftover = await useContainer().resolve<LinkRepository>(LINKS).insert({
      id: crypto.randomUUID(),
      userId: ids.inactive,
      issuer: 'https://x.example',
      subject: 's',
      providerName: 'x',
      providerEmail: null,
    });
    const inactive = new Browser();
    await inactive.page('/login');
    await directory().updateAccount(ids.inactive, { status: 'active' });
    await inactive.post('/login', { username: 'inactive', password: PASSWORD });
    await inactive.page('/account/identity-links');
    await directory().updateAccount(ids.inactive, { status: 'pending' });
    expect(
      (await inactive.post('/account/identity-links/unlink/start', { id: leftover.id })).status,
    ).toBe(400);
    expect(await inactive.page('/account/identity-links/nothing', 404)).toMatchObject({
      page: 'not-found',
    });
  });
});
