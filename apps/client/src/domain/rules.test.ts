import { describe, expect, test } from 'bun:test';
import { formatTimestamp, t } from '../i18n/messages.ts';
import { clearCookie, readCookie, writeCookie } from '../server/cookies.ts';
import { handle } from '../server/handler.ts';
import { manualClock, systemClock } from './clock.ts';
import type { PageModel, Session, Store } from './model.ts';
import {
  createSession,
  createStore,
  currentUser,
  EXPIRED_EMAIL_TOKEN,
  SEED_NOW,
  SEED_PASSWORDS,
  VALID_EMAIL_TOKEN,
} from './model.ts';
import { hashPassword, passwordMatches } from './password.ts';
import { submit, view } from './service.ts';

function world(userId: string | null = null) {
  const clock = manualClock(SEED_NOW);
  const store = createStore(clock);
  const session = createSession(store, userId, userId ? SEED_NOW : null);
  return { clock, store, session };
}

function form(session: Session, fields: Record<string, string>) {
  return new URLSearchParams({ _csrf: session.csrf, ...fields });
}

function post(
  store: Store,
  session: Session,
  path: string,
  fields: Record<string, string> = {},
  emailToken?: string,
) {
  return submit(
    store,
    session,
    emailToken,
    new URL(`http://localhost${path}`),
    form(session, fields),
  );
}

function get(store: Store, session: Session, path: string, emailToken?: string) {
  return view(store, session, emailToken, new URL(`http://localhost${path}`));
}

function pageOf(outcome: { page?: PageModel }): PageModel {
  if (!outcome.page) throw new Error('missing page');
  return outcome.page;
}

function login(store: Store, session: Session, name: string, password: string) {
  const outcome = post(store, session, '/login', { identifier: name, password });
  if (!outcome.session?.userId) throw new Error(`login failed for ${name}`);
  return outcome.session;
}

describe('identity client rules', () => {
  test('covers clock, password, copy, and cookie helpers', () => {
    const clock = systemClock();
    expect(clock.now()).toBeGreaterThan(0);
    expect(clock.hex(4)).toHaveLength(4);
    const manual = manualClock(10);
    manual.set(20);
    expect(manual.now()).toBe(20);
    expect(manual.hex(4)).toBe('0001');
    expect(passwordMatches('nope', null)).toBe(false);
    expect(passwordMatches('nope', hashPassword('other'))).toBe(false);
    expect(t('signIn')).toBe('Sign in');
    expect(t('auditHeading', { count: 2 })).toBe('Audit (2)');
    expect(formatTimestamp('not-a-date')).toBe('not-a-date');
    expect(formatTimestamp('2026-01-15T12:00:00.000Z').length).toBeGreaterThan(0);
    expect(readCookie(null, 'a')).toBeUndefined();
    expect(readCookie('other=1; identity_session=abc%3D', 'identity_session')).toBe('abc=');
    expect(readCookie('a=1', 'missing')).toBeUndefined();
    expect(writeCookie('a', 'b')).toContain('HttpOnly');
    expect(writeCookie('a', 'b', 10)).toContain('Max-Age=10');
    expect(clearCookie('a')).toContain('Max-Age=0');
  });

  test('signs in active and pending accounts and hides login failures', () => {
    const { store, session } = world();
    expect(pageOf(get(store, session, '/login?logout=1')).page).toBe('login');
    expect(
      post(store, session, '/login', { identifier: 'iris', password: SEED_PASSWORDS.iris })
        .location,
    ).toBe('/login');
    expect(
      post(store, session, '/login', { identifier: 'archived', password: SEED_PASSWORDS.archived })
        .location,
    ).toBe('/login');
    expect(
      post(store, session, '/login', { identifier: 'ada', password: 'wrong-password' }).location,
    ).toBe('/login');
    expect(
      post(store, session, '/login', { identifier: 'missing', password: SEED_PASSWORDS.ada })
        .location,
    ).toBe('/login');
    const ada = login(store, session, 'ada@identity.example', SEED_PASSWORDS.ada);
    expect(ada.userId).toBe('u_ada');
  });

  test('sends one email link per purpose per minute and confirms it', () => {
    const { store, session, clock } = world();
    expect(
      post(store, session, '/passwordless', { email: 'nobody@identity.example' }).location,
    ).toBe('/passwordless?sent=1');
    expect(
      post(store, session, '/passwordless', { email: 'archived@identity.example' }).location,
    ).toBe('/passwordless?sent=1');
    expect(post(store, session, '/passwordless', { email: 'iris@identity.example' }).location).toBe(
      '/passwordless?sent=1',
    );
    const sent = post(store, session, '/passwordless', { email: 'pending@identity.example' });
    expect(sent.location).toBe('/passwordless?sent=1');
    expect(pageOf(get(store, session, '/passwordless?sent=1')).page).toBe('passwordless');
    const again = post(store, session, '/passwordless', { email: 'pending@identity.example' });
    expect(again.location).toBe('/passwordless?sent=1');
    expect(
      store.emails.filter((email) => email.purpose === 'sign-in' && email.userId === 'u_pending')
        .length,
    ).toBe(2);
    clock.set(SEED_NOW + 61_000);
    post(store, session, '/passwordless', { email: 'ADA@identity.example' });
    const bad = get(store, session, `/passwordless/confirm?token=${EXPIRED_EMAIL_TOKEN}`);
    expect(pageOf(bad).page).toBe('passwordless-confirm');
    expect(bad.emailCookie).toBeNull();
    const staged = get(store, session, `/passwordless/confirm?token=${VALID_EMAIL_TOKEN}`);
    expect(pageOf(staged).page).toBe('passwordless-confirm');
    expect(staged.emailCookie).toBe(VALID_EMAIL_TOKEN);
    expect(post(store, session, '/passwordless/confirm', {}, 'missing').location).toBe(
      '/passwordless/confirm',
    );
    const confirmed = post(store, session, '/passwordless/confirm', {}, VALID_EMAIL_TOKEN);
    expect(confirmed.location).toBe('/account/password');
    expect(confirmed.session?.userId).toBe('u_pending');
    expect(
      post(store, confirmed.session ?? session, '/passwordless/confirm', {}, VALID_EMAIL_TOKEN)
        .location,
    ).toBe('/passwordless/confirm');
  });

  test('sets a password of at least 12 characters without showing the updated flag', () => {
    const { store, session } = world('u_pending');
    expect(post(store, session, '/account/password', { password: 'short' }).location).toBe(
      '/account/password?error=short',
    );
    const shown = pageOf(get(store, session, '/account/password?updated=1&error=short'));
    expect(shown.page).toBe('password');
    if (shown.page === 'password') expect(shown.error).toBe('short');
    expect(post(store, session, '/account/password', { password: 'long-enough-pw' }).location).toBe(
      '/account/password?updated=1',
    );
    const saved = pageOf(get(store, session, '/account/password?updated=1'));
    if (saved.page === 'password') expect(saved.error).toBeNull();
    const next = createSession(store, null, null);
    expect(login(store, next, 'pending', 'long-enough-pw').userId).toBe('u_pending');
  });

  test('gates admin pages by role', () => {
    const anon = world();
    expect(get(anon.store, anon.session, '/admin/users').type).toBe('login-required');
    expect(get(anon.store, anon.session, '/account/identity-links').type).toBe('login-required');
    const iris = world('u_iris');
    expect(pageOf(get(iris.store, iris.session, '/admin/users')).page).toBe('denied');
    expect(pageOf(get(iris.store, iris.session, '/missing')).page).toBe('denied');
    const marco = world('u_marco');
    const denied = pageOf(get(marco.store, marco.session, '/admin/users'));
    expect(denied.page).toBe('denied');
    if (denied.page === 'denied') expect(denied.reason).toBe('member');
    const olivia = world('u_olivia');
    const users = pageOf(get(olivia.store, olivia.session, '/admin/users?q=marco&status=active'));
    if (users.page === 'users') {
      expect(users.users.map((user) => user.login)).toEqual(['marco']);
      expect(users.users.some((user) => user.login === 'ada')).toBe(false);
    }
    expect(pageOf(get(olivia.store, olivia.session, '/admin/organizations/create')).page).toBe(
      'denied',
    );
    const ada = world('u_ada');
    const everyone = pageOf(get(ada.store, ada.session, '/admin/users?status=all'));
    if (everyone.page === 'users') expect(everyone.users.length).toBeGreaterThan(5);
    expect(pageOf(get(ada.store, ada.session, '/admin/users/missing')).page).toBe('not-found');
    expect(get(ada.store, ada.session, '/nope').page?.page).toBe('not-found');
  });

  test('invites, archives, restores, and resets passwords', () => {
    const { store, session } = world('u_ada');
    expect(
      post(store, session, '/admin/users/invite', { login: '', email: '', role: 'member' })
        .location,
    ).toContain('error=required');
    expect(
      post(store, session, '/admin/users/invite', {
        login: 'new',
        email: 'new@identity.example',
        role: 'guest',
      }).location,
    ).toContain('error=required');
    expect(
      post(store, session, '/admin/users/invite', {
        login: 'ada',
        email: 'ada@identity.example',
        role: 'member',
      }).location,
    ).toContain('error=conflict');
    expect(
      post(store, session, '/admin/users/invite', {
        login: 'new',
        email: 'new@identity.example',
        role: 'member',
        organization: 'missing',
      }).location,
    ).toContain('error=invalid-org');
    const invited = post(store, session, '/admin/users/invite', {
      login: 'new',
      email: 'new@identity.example',
      displayName: '',
      role: 'owner',
      organization: 'o_acme',
    });
    expect(invited.location).toContain('banner=invited');
    const created = store.users.find((user) => user.login === 'new');
    expect(created?.status).toBe('pending');
    expect(created?.displayName).toBe('new');
    const detail = pageOf(get(store, session, `/admin/users/${created?.id}?banner=invited`));
    if (detail.page === 'user') {
      expect(detail.banner).toBe('invited');
      expect(detail.showArchive).toBe(true);
      expect(detail.user.memberships.length).toBe(1);
    }
    expect(post(store, session, `/admin/users/${created?.id}/archive`).location).toContain(
      'banner=archived',
    );
    expect(post(store, session, `/admin/users/${created?.id}/restore`).location).toContain(
      'banner=restored',
    );
    expect(post(store, session, `/admin/users/${created?.id}/password-reset`).location).toContain(
      'banner=password-reset',
    );
    expect(post(store, session, `/admin/users/${created?.id}/password-reset`).location).toContain(
      'banner=blocked',
    );
    const linkOnly = store.users.find((user) => user.id === 'u_linkonly');
    if (linkOnly) linkOnly.email = null;
    expect(post(store, session, '/admin/users/u_linkonly/password-reset').location).toBe(
      '/admin/users/u_linkonly',
    );
    expect(pageOf(get(store, session, '/admin/users/invite?error=conflict')).page).toBe('invite');
    expect(post(store, session, '/admin/users/u_sam/archive').location).toContain('banner=blocked');
    expect(post(store, session, '/admin/users/u_blake/archive').location).toContain(
      'banner=archived',
    );
    expect(post(store, session, '/admin/users/u_ada/archive').location).toContain('banner=blocked');
    expect(post(store, session, '/admin/users/u_archived/restore').location).toContain(
      'banner=restored',
    );
    expect(post(store, session, '/admin/users/u_ada/restore').location).toBe('/admin/users/u_ada');
    expect(post(store, session, '/admin/users/missing/archive').location).toBe('/admin/users');
    const archivedView = pageOf(get(store, session, '/admin/users/u_blake?banner=archived'));
    if (archivedView.page === 'user') expect(archivedView.showRestore).toBe(true);
    expect(post(store, session, '/admin/users/invite', { _csrf: 'nope' }).location).toBe(
      '/admin/users',
    );
  });

  test('manages organizations for platform admins and owners', () => {
    const { store, session } = world('u_ada');
    const list = pageOf(get(store, session, '/admin/organizations?status=archived'));
    if (list.page === 'organizations') {
      expect(list.canCreate).toBe(true);
      expect(list.organizations.map((organization) => organization.slug)).toEqual(['oldco']);
    }
    expect(
      post(store, session, '/admin/organizations/create', { slug: 'Bad', name: 'Bad' }).location,
    ).toContain('error=slug');
    expect(
      post(store, session, '/admin/organizations/create', { slug: 'acme', name: 'Acme' }).location,
    ).toContain('error=duplicate-slug');
    const created = post(store, session, '/admin/organizations/create', {
      slug: 'new-org',
      name: '',
    });
    expect(created.location).toContain('banner=created');
    const organization = store.organizations.find((item) => item.slug === 'new-org');
    expect(organization?.name).toBe('new-org');
    const detail = pageOf(
      get(store, session, `/admin/organizations/${organization?.id}?banner=created`),
    );
    if (detail.page === 'organization') {
      expect(detail.canArchive).toBe(true);
      expect(detail.organization.memberCount).toBe(0);
    }
    expect(
      post(store, session, `/admin/organizations/${organization?.id}/settings`, { name: '' })
        .location,
    ).toContain('banner=saved');
    expect(organization?.name).toBe('new-org');
    expect(
      post(store, session, `/admin/organizations/${organization?.id}/archive`).location,
    ).toContain('banner=archived');
    expect(post(store, session, `/admin/organizations/${organization?.id}/archive`).location).toBe(
      `/admin/organizations/${organization?.id}`,
    );
    const owner = world('u_olivia');
    const owned = pageOf(get(owner.store, owner.session, '/admin/organizations'));
    if (owned.page === 'organizations') {
      expect(owned.canCreate).toBe(false);
      expect(owned.organizations.map((item) => item.slug)).toEqual(['acme']);
    }
    expect(
      post(owner.store, owner.session, '/admin/organizations/o_acme/settings', { name: 'Acme Co' })
        .location,
    ).toContain('banner=saved');
    expect(post(owner.store, owner.session, '/admin/organizations/o_acme/archive').location).toBe(
      '/admin/organizations/o_acme',
    );
    expect(owner.store.organizations.find((item) => item.id === 'o_acme')?.status).toBe('active');
    expect(pageOf(get(owner.store, owner.session, '/admin/organizations/o_solo')).page).toBe(
      'not-found',
    );
    expect(post(store, session, '/admin/organizations/missing/settings').location).toBe(
      '/admin/organizations',
    );
  });

  test('adds, changes, and removes memberships without removing the last owner', () => {
    const { store, session } = world('u_olivia');
    const page = pageOf(get(store, session, '/admin/memberships'));
    if (page.page === 'memberships') expect(page.organizationId).toBe('o_acme');
    expect(
      post(store, session, '/admin/memberships/add', {
        organization: 'o_old',
        user: 'casey',
        role: 'member',
      }).location,
    ).toContain('error=invalid-org');
    expect(
      post(store, session, '/admin/memberships/add', {
        organization: 'o_acme',
        user: 'missing',
        role: 'member',
      }).location,
    ).toContain('error=user-not-found');
    expect(
      post(store, session, '/admin/memberships/add', {
        organization: 'o_acme',
        user: 'archived',
        role: 'member',
      }).location,
    ).toContain('error=archived-user');
    expect(
      post(store, session, '/admin/memberships/add', {
        organization: 'o_acme',
        user: 'marco',
        role: 'member',
      }).location,
    ).toContain('error=already-member');
    expect(
      post(store, session, '/admin/memberships/add', {
        organization: 'o_acme',
        user: 'casey',
        role: 'member',
      }).location,
    ).toContain('banner=added');
    expect(
      post(store, session, '/admin/memberships/role-change', {
        organization: 'o_acme',
        user: 'u_olivia',
        role: 'member',
      }).location,
    ).toContain('banner=blocked');
    expect(
      post(store, session, '/admin/memberships/remove', {
        organization: 'o_acme',
        user: 'u_olivia',
      }).location,
    ).toContain('banner=blocked');
    expect(
      post(store, session, '/admin/memberships/remove', { organization: 'o_acme', user: 'u_marco' })
        .location,
    ).toContain('banner=removed');
    expect(
      post(store, session, '/admin/memberships/role-change', {
        organization: 'missing',
        user: 'u_casey',
        role: 'member',
      }).location,
    ).toContain('error=invalid-org');
    expect(
      post(store, session, '/admin/memberships/remove', {
        organization: 'missing',
        user: 'u_casey',
      }).location,
    ).toContain('error=invalid-org');
    expect(
      post(store, session, '/admin/memberships/add', {
        organization: 'o_acme',
        user: 'ada',
        role: 'guest',
      }).location,
    ).toContain('error=invalid-org');
    expect(
      post(store, session, '/admin/memberships/role-change', {
        organization: 'o_acme',
        user: 'u_casey',
        role: 'owner',
      }).location,
    ).toContain('banner=role-changed');
    expect(
      post(store, session, '/admin/memberships/role-change', {
        organization: 'o_acme',
        user: 'u_olivia',
        role: 'member',
      }).location,
    ).toContain('banner=role-changed');
    const shown = pageOf(
      get(
        store,
        session,
        '/admin/memberships?organization=o_acme&banner=blocked&error=user-not-found',
      ),
    );
    if (shown.page === 'memberships') {
      expect(shown.banner).toBe('added');
      expect(shown.error).toBe('user-not-found');
    }
  });

  test('registers, edits, rotates, and revokes OAuth clients once', () => {
    const { store, session } = world('u_ada');
    expect(
      post(store, session, '/admin/oauth-clients/register', { name: '', organization: 'o_acme' })
        .location,
    ).toContain('error=name');
    expect(
      post(store, session, '/admin/oauth-clients/register', { name: 'Old', organization: 'o_old' })
        .location,
    ).toContain('error=invalid-org');
    const registered = post(store, session, '/admin/oauth-clients/register', {
      name: 'New',
      organization: 'o_north',
      redirectUris: '',
      grantTypes: '',
      scopes: '',
    });
    expect(registered.location).toContain('banner=registered');
    const client = store.clients.find((item) => item.name === 'New');
    expect(client?.id).toMatch(/^cli_[0-9a-f]{16}$/);
    expect(client?.grantTypes).toEqual(['authorization_code', 'refresh_token']);
    expect(client?.scopes).toEqual(['openid', 'profile', 'email']);
    const first = pageOf(
      get(store, session, `/admin/oauth-clients/${client?.id}?banner=registered`),
    );
    if (first.page === 'client') {
      expect(first.secret).toBeTruthy();
      expect(first.banner).toBe('registered');
      expect(first.canModify).toBe(true);
    }
    const second = pageOf(get(store, session, `/admin/oauth-clients/${client?.id}`));
    if (second.page === 'client') expect(second.secret).toBeNull();
    expect(
      post(store, session, `/admin/oauth-clients/${client?.id}/edit`, {
        name: '',
        redirectUris: 'https://new.example/cb',
        grantTypes: 'authorization_code',
        scopes: 'openid',
      }).location,
    ).toContain('banner=metadata-updated');
    expect(client?.name).toBe('New');
    expect(
      post(store, session, `/admin/oauth-clients/${client?.id}/rotate-secret`).location,
    ).toContain('banner=secret-rotated');
    const rotated = pageOf(
      get(store, session, `/admin/oauth-clients/${client?.id}?banner=secret-rotated`),
    );
    if (rotated.page === 'client') expect(rotated.secret).toBeTruthy();
    expect(post(store, session, `/admin/oauth-clients/${client?.id}/revoke`).location).toContain(
      'banner=revoked',
    );
    expect(client?.status).toBe('revoked');
    expect(
      post(store, session, `/admin/oauth-clients/${client?.id}/edit`, { name: 'Nope' }).location,
    ).toBe(`/admin/oauth-clients/${client?.id}`);
    expect(client?.name).toBe('New');
    const revoked = pageOf(
      get(store, session, `/admin/oauth-clients/${client?.id}?banner=revoked`),
    );
    if (revoked.page === 'client') expect(revoked.canModify).toBe(false);
    const owner = world('u_olivia');
    const visible = pageOf(get(owner.store, owner.session, '/admin/oauth-clients?status=active'));
    if (visible.page === 'clients')
      expect(visible.clients.every((item) => item.organization === 'Acme')).toBe(true);
    expect(pageOf(get(owner.store, owner.session, `/admin/oauth-clients/${client?.id}`)).page).toBe(
      'not-found',
    );
    expect(post(store, session, '/admin/oauth-clients/missing/revoke').location).toBe(
      '/admin/oauth-clients',
    );
    const empty = pageOf(
      get(store, session, '/admin/oauth-clients?organization=o_solo&status=revoked'),
    );
    if (empty.page === 'clients') expect(empty.clients).toEqual([]);
  });

  test('filters read-only audit records and hides records outside an owner scope', () => {
    const ada = world('u_ada');
    const all = pageOf(
      get(
        ada.store,
        ada.session,
        '/admin/audit?action=organization.create&actor=ada&from=2026-01-01T00:00:00.000Z&to=2026-01-10T00:00:00.000Z',
      ),
    );
    if (all.page === 'audit') expect(all.count).toBe(1);
    const badRange = pageOf(
      get(ada.store, ada.session, '/admin/audit?from=nope&to=nope&target=organization:solo'),
    );
    if (badRange.page === 'audit') expect(badRange.count).toBe(1);
    const record = pageOf(get(ada.store, ada.session, '/admin/audit/aud_solo'));
    if (record.page === 'audit-record') expect(record.record.stateAfter).toContain('solo');
    expect(pageOf(get(ada.store, ada.session, '/admin/audit/missing')).page).toBe('not-found');
    const owner = world('u_olivia');
    const scoped = pageOf(get(owner.store, owner.session, '/admin/audit'));
    if (scoped.page === 'audit') {
      expect(scoped.records.some((item) => item.id === 'aud_acme')).toBe(true);
      expect(scoped.records.some((item) => item.id === 'aud_solo')).toBe(false);
    }
    expect(pageOf(get(owner.store, owner.session, '/admin/audit/aud_solo')).page).toBe('not-found');
  });

  test('reviews OAuth consent and allows the request', () => {
    const { store, session } = world('u_marco');
    expect(pageOf(get(store, session, '/oauth2/consent?client_id=missing')).page).toBe('not-found');
    const consent = pageOf(
      get(
        store,
        session,
        '/oauth2/consent?client_id=cli_aaaaaaaaaaaaaaaa&scope=openid%20profile&redirect_uri=https://acme.example/callback',
      ),
    );
    if (consent.page === 'consent') {
      expect(consent.clientName).toBe('Acme web');
      expect(consent.scopes).toEqual(['profile']);
      expect(consent.redirectUri).toBe('https://acme.example/callback');
    }
    const allowed = post(store, session, '/oauth2/authorize', {
      client_id: 'cli_aaaaaaaaaaaaaaaa',
      redirect_uri: 'https://acme.example/callback',
    });
    expect(allowed.location).toBe('https://acme.example/callback');
    expect(post(store, session, '/oauth2/authorize', { client_id: 'missing' }).location).toBe(
      '/oauth2/consent',
    );
    const javascript = store.clients[0];
    if (javascript) javascript.redirectUris = ['not a url', 'javascript:alert(1)'];
    expect(
      post(store, session, '/oauth2/authorize', { client_id: 'cli_aaaaaaaaaaaaaaaa' }).location,
    ).toBe('/account/identity-links');
  });

  test('links and unlinks identities', () => {
    const { store, session, clock } = world('u_nora');
    expect(
      pageOf(get(store, session, '/account/identity-links/start?provider=&issuer=')).page,
    ).toBe('link-unavailable');
    expect(
      pageOf(
        get(
          store,
          session,
          '/account/identity-links/start?provider=google&issuer=javascript:alert(1)',
        ),
      ).page,
    ).toBe('link-unavailable');
    const started = get(
      store,
      session,
      '/account/identity-links/start?provider=google&issuer=https://idp.example/authorize&returnUrl=/account/identity-links',
    );
    expect(started.location).toContain('https://idp.example/authorize');
    expect(started.session?.pendingLink?.userId).toBe('u_nora');
    const state = started.session?.pendingLink?.token ?? '';
    expect(
      pageOf(
        get(store, session, '/account/identity-links/callback?error=access_denied&code=1&state=1'),
      ).page,
    ).toBe('link-unavailable');
    expect(post(store, session, '/account/identity-links/confirm').location).toBe(
      '/account/identity-links/confirm',
    );
    const restart = get(
      store,
      session,
      '/account/identity-links/start?provider=google&issuer=https://idp.example/authorize&returnUrl=/account/identity-links',
    );
    const nextState = restart.session?.pendingLink?.token ?? '';
    expect(
      get(store, session, `/account/identity-links/callback?code=abc&state=${nextState}`).type,
    ).toBe('redirect');
    const confirm = pageOf(get(store, session, '/account/identity-links/confirm'));
    if (confirm.page === 'link-confirm') {
      expect(confirm.account.login).toBe('nora');
      expect(confirm.external.provider).toBe('google');
    }
    expect(post(store, session, '/account/identity-links/confirm').location).toContain(
      'banner=linked',
    );
    expect(post(store, session, '/account/identity-links/cancel').location).toContain(
      'banner=canceled',
    );
    const links = pageOf(get(store, session, '/account/identity-links?banner=linked'));
    if (links.page === 'links') expect(links.accountName).toBe('Nora North');
    const other = world('u_ada');
    other.session.pendingLink = {
      provider: 'google',
      issuer: 'https://idp.example',
      subject: 'sub_other',
      subjectHint: '••••ther',
      providerEmail: 'user@google.example',
      token: 'token',
      expiresAt: SEED_NOW + 1000,
      userId: 'u_nora',
      returnUrl: '',
    };
    expect(pageOf(get(other.store, other.session, '/account/identity-links/confirm')).page).toBe(
      'link-unavailable',
    );
    clock.set(SEED_NOW + 16 * 60 * 1000);
    expect(
      post(store, session, '/account/identity-links/unlink/start', {
        issuer: 'https://accounts.google.example',
        subject: 'subject-nora-1',
      }).location,
    ).toContain('error=recent-auth');
    session.authenticatedAt = clock.now();
    expect(
      post(store, session, '/account/identity-links/unlink/start', {
        issuer: 'missing',
        subject: 'missing',
      }).location,
    ).toBe('/account/identity-links/unlink/confirm');
    expect(pageOf(get(store, session, '/account/identity-links/unlink/confirm')).page).toBe(
      'link-unavailable',
    );
    const pendingUser = world('u_pending');
    pendingUser.store.links.push({
      id: 'link_pending',
      userId: 'u_pending',
      provider: 'google',
      issuer: 'https://accounts.google.example',
      subject: 'subject-pending',
      subjectHint: '••••ding',
      providerEmail: 'pending@google.example',
      linkedAt: '2026-01-01T00:00:00.000Z',
    });
    expect(
      post(pendingUser.store, pendingUser.session, '/account/identity-links/unlink/start', {
        issuer: 'https://accounts.google.example',
        subject: 'subject-pending',
      }).location,
    ).toContain('error=inactive-unlink');
    const only = world('u_linkonly');
    expect(
      post(only.store, only.session, '/account/identity-links/unlink/start', {
        issuer: 'https://github.example/login',
        subject: 'subject-linkonly',
      }).location,
    ).toContain('error=last-method');
    const startedUnlink = post(store, session, '/account/identity-links/unlink/start', {
      issuer: 'https://accounts.google.example',
      subject: 'subject-nora-1',
    });
    expect(startedUnlink.location).toBe('/account/identity-links/unlink/confirm');
    const review = pageOf(get(store, session, '/account/identity-links/unlink/confirm'));
    if (review.page === 'unlink-confirm') expect(review.subjectHint).toContain('••••');
    session.unlinkConfirmation = session.unlinkConfirmation
      ? { ...session.unlinkConfirmation, expiresAt: clock.now() - 1 }
      : null;
    expect(post(store, session, '/account/identity-links/unlink/confirm').location).toBe(
      '/account/identity-links/unlink/confirm',
    );
    post(store, session, '/account/identity-links/unlink/start', {
      issuer: 'https://accounts.google.example',
      subject: 'subject-nora-1',
    });
    expect(post(store, session, '/account/identity-links/unlink/confirm').location).toContain(
      'banner=unlinked',
    );
    expect(store.links.some((link) => link.subject === 'subject-nora-1')).toBe(false);
    expect(state.length).toBeGreaterThan(0);
    const casey = world('u_casey');
    const empty = pageOf(get(casey.store, casey.session, '/account/identity-links'));
    if (empty.page === 'links') expect(empty.links).toEqual([]);
  });

  test('logs out with a POST and rejects a bad CSRF token', () => {
    const { store, session } = world('u_ada');
    const loggedOut = post(store, session, '/admin/logout');
    expect(loggedOut.location).toBe('/login?logout=1');
    expect(loggedOut.session).toBeNull();
    expect(store.sessions.some((item) => item.id === session.id)).toBe(false);
    expect(currentUser(store, session)?.login).toBe('ada');
    const again = world();
    const bad = submit(
      again.store,
      again.session,
      undefined,
      new URL('http://localhost/login'),
      new URLSearchParams({ _csrf: 'nope', identifier: 'ada', password: SEED_PASSWORDS.ada }),
    );
    expect(bad.location).toBe('/login');
    expect(bad.session?.userId).toBeNull();
    expect(post(again.store, again.session, '/nope').location).toBe('/login');
    const badForm = { _csrf: 'nope' };
    expect(
      post(again.store, again.session, '/admin/organizations/o_acme/settings', badForm).location,
    ).toBe('/admin/organizations');
    expect(
      post(again.store, again.session, '/admin/oauth-clients/register', badForm).location,
    ).toBe('/admin/oauth-clients');
    expect(post(again.store, again.session, '/admin/memberships/add', badForm).location).toBe(
      '/admin/memberships',
    );
    expect(
      post(again.store, again.session, '/account/identity-links/cancel', badForm).location,
    ).toBe('/account/identity-links');
    expect(post(again.store, again.session, '/account/password', badForm).location).toBe(
      '/account/password',
    );
    expect(post(again.store, again.session, '/passwordless', badForm).location).toBe(
      '/passwordless',
    );
    expect(post(again.store, again.session, '/oauth2/authorize', badForm).location).toBe(
      '/oauth2/consent',
    );
    expect(pageOf(get(again.store, again.session, '/passwordless/confirm')).page).toBe(
      'passwordless-confirm',
    );
    expect(pageOf(get(store, session, '/admin/organizations/create?error=slug')).page).toBe(
      'create-organization',
    );
    expect(pageOf(get(store, session, '/admin/oauth-clients/register?error=name')).page).toBe(
      'register-client',
    );
  });
});

describe('identity client HTTP', () => {
  test('serves HTML, JSON, cookies, and redirects', async () => {
    const { store } = world();
    const html = await handle(new Request('http://localhost/login'), store);
    expect(html.headers.get('content-type')).toContain('text/html');
    expect(html.headers.get('set-cookie')).toContain('identity_session');
    const cookie = html.headers.get('set-cookie') ?? '';
    const json = await handle(
      new Request('http://localhost/login', { headers: { accept: 'application/json', cookie } }),
      store,
    );
    const body = (await json.json()) as PageModel;
    expect(body.page).toBe('login');
    const signed = await handle(
      new Request('http://localhost/login', {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
        body: `_csrf=${encodeURIComponent(body.csrf)}&identifier=ada&password=${SEED_PASSWORDS.ada}`,
      }),
      store,
    );
    expect(signed.status).toBe(303);
    expect(signed.headers.get('location')).toBe('/account/identity-links');
    const signedCookie = signed.headers.get('set-cookie') ?? '';
    const account = await handle(
      new Request('http://localhost/account/identity-links', {
        headers: { accept: 'application/json', cookie: signedCookie },
      }),
      store,
    );
    const accountBody = (await account.json()) as PageModel;
    const loggedOut = await handle(
      new Request('http://localhost/admin/logout', {
        method: 'POST',
        headers: { cookie: signedCookie, 'content-type': 'application/x-www-form-urlencoded' },
        body: `_csrf=${encodeURIComponent(accountBody.csrf)}`,
      }),
      store,
    );
    expect(loggedOut.status).toBe(303);
    expect(loggedOut.headers.getSetCookie().join(';')).toContain('Max-Age=0');
    const admin = await handle(new Request('http://localhost/admin/users'), store);
    expect(admin.status).toBe(302);
    expect(admin.headers.get('location')).toBe('/login');
    const denied = await handle(
      new Request('http://localhost/admin/users', { headers: { accept: 'application/json' } }),
      store,
    );
    expect(denied.status).toBe(401);
    const method = await handle(new Request('http://localhost/login', { method: 'PUT' }), store);
    expect(method.status).toBe(405);
    const staged = await handle(
      new Request(`http://localhost/passwordless/confirm?token=${VALID_EMAIL_TOKEN}`, {
        headers: { accept: 'application/json', cookie },
      }),
      store,
    );
    expect(staged.headers.getSetCookie().join(';')).toContain('identity_email');
  });

  test('shows a client secret on the JSON page after the HTML shell loads', async () => {
    const { store, session } = world('u_ada');
    const registered = post(store, session, '/admin/oauth-clients/register', {
      name: 'Shell',
      organization: 'o_acme',
    });
    const location = registered.location ?? '';
    const cookie = `identity_session=${session.id}`;
    const html = await handle(
      new Request(`http://localhost${location}`, { headers: { cookie } }),
      store,
    );
    expect(html.headers.get('content-type')).toContain('text/html');
    const json = await handle(
      new Request(`http://localhost${location}`, {
        headers: { accept: 'application/json', cookie },
      }),
      store,
    );
    const body = (await json.json()) as PageModel;
    if (body.page === 'client') expect(body.secret).toBeTruthy();
    const again = await handle(
      new Request(`http://localhost${location}`, {
        headers: { accept: 'application/json', cookie },
      }),
      store,
    );
    const hidden = (await again.json()) as PageModel;
    if (hidden.page === 'client') expect(hidden.secret).toBeNull();
  });
});
