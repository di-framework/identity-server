import { describe, expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { routeRequest } from '../../../server/src/serve.ts';
import { systemClock } from '../domain/clock.ts';
import {
  createSession,
  createStore,
  type Outcome,
  type Session,
  type Store,
} from '../domain/model.ts';
import { view } from '../domain/service.ts';
import { handle } from '../server/handler.ts';
import { createIdentityClient } from './client.ts';
import { applyDirectory } from './directory.ts';

const userId = '11111111-1111-4111-8111-111111111111';
const archivedId = '22222222-2222-4222-8222-222222222222';

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}

function clientFor(respond: (request: Request) => Response) {
  return createIdentityClient({
    baseUrl: 'http://identity.test',
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      return respond(request);
    }) as typeof fetch,
  });
}

function fixtures(request: Request, fail = new Set<string>()): Response {
  const url = new URL(request.url);
  const key = `${request.method} ${url.pathname}`;
  if (fail.has(key)) return json({ error: 'down' }, 500);
  if (request.method === 'GET' && url.pathname === '/api/admin/users') {
    return json([
      {
        id: userId,
        login: 'ada',
        email: 'ada@identity.example',
        display_name: 'Ada Admin',
        email_verified: true,
        status: 'active',
      },
      {
        id: archivedId,
        login: 'old',
        email: 'old@identity.example',
        display_name: 'Old',
        status: 'archived',
      },
      { login: 'nameless' },
    ]);
  }
  if (request.method === 'GET' && url.pathname === `/api/admin/users/${userId}`) {
    return json({
      id: userId,
      login: 'ada',
      email: 'ada@identity.example',
      display_name: 'Ada Admin',
      email_verified: true,
      status: 'active',
    });
  }
  if (request.method === 'GET' && url.pathname === `/api/admin/users/${archivedId}`) {
    return json({
      id: archivedId,
      login: 'old',
      email: '',
      display_name: 'Old',
      status: 'archived',
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/users/missing') {
    return json({ error: 'missing' }, 404);
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/organizations') {
    return json([
      { id: 'org-1', slug: 'acme', name: 'Acme', created_at: '2026-01-01T00:00:00.000Z' },
      { name: 'no-slug' },
    ]);
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/organizations/acme') {
    return json({
      id: 'org-1',
      slug: 'acme',
      name: 'Acme',
      created_at: '2026-01-01T00:00:00.000Z',
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/organizations/missing') {
    return json({}, 404);
  }
  if (request.method === 'GET' && url.pathname === '/api/v1/organizations/acme/members') {
    return json({
      items: [
        {
          subject: userId,
          login: 'ada',
          email: 'ada@identity.example',
          organization_role: 'owner',
        },
        {
          subject: archivedId,
          login: 'old',
          email: 'old@identity.example',
          organization_role: 'guest',
        },
        { login: 'nameless' },
      ],
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/oauth-clients') {
    return json([
      {
        client_id: 'cli_1',
        organization_slug: 'acme',
        redirect_uris: ['https://acme.example/callback'],
        scopes: ['openid'],
        browser: true,
      },
      {
        client_id: 'cli_revoked',
        organization_slug: 'acme',
        revoked_at: '2026-01-02T00:00:00.000Z',
      },
      {},
    ]);
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/oauth-clients/cli_1') {
    return json({
      client_id: 'cli_1',
      organization_slug: 'acme',
      redirect_uris: ['https://acme.example/callback'],
      scopes: ['openid'],
      browser: true,
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/oauth-clients/cli_revoked') {
    return json({
      client_id: 'cli_revoked',
      organization_slug: 'acme',
      revoked_at: '2026-01-02T00:00:00.000Z',
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/oauth-clients/missing') {
    return json({}, 404);
  }
  if (request.method === 'GET' && url.pathname === '/api/admin/audit') {
    return json([
      {
        id: 'aud_1',
        action: 'admin.user_created',
        actor_client_id: 'ada',
        target: 'user:1',
        correlation_id: 'c1',
        before_metadata: '{}',
        after_metadata: '{"status":"pending"}',
        created_at: '2026-01-15T12:00:00.000Z',
      },
      {
        id: 'aud_actor',
        action: 'admin.user_created',
        actor_client_id: 'other',
        target: 'user:1',
        created_at: '2026-01-15T12:00:00.000Z',
      },
      {
        id: 'aud_target',
        action: 'admin.user_created',
        actor_client_id: 'ada',
        target: 'elsewhere',
        created_at: '2026-01-15T12:00:00.000Z',
      },
      {
        id: 'aud_early',
        action: 'admin.user_created',
        actor_client_id: 'ada',
        target: 'user:1',
        created_at: '2020-01-01T00:00:00.000Z',
      },
      {
        id: 'aud_other',
        action: 'other',
        actor_client_id: 'ada',
        target: 'user:1',
        created_at: '2026-01-15T12:00:00.000Z',
      },
      {
        id: 'aud_late',
        action: 'admin.user_created',
        actor_client_id: 'ada',
        target: 'user:1',
        created_at: '2027-01-01T00:00:00.000Z',
      },
      {},
    ]);
  }
  if (request.method === 'GET' && url.pathname === '/api/v1/account/identity-links') {
    return json([
      {
        id: 'link-1',
        providerName: 'google',
        issuer: 'https://accounts.google.example',
        subjectHint: 'hint',
        createdAt: '2026-01-02T00:00:00.000Z',
      },
      { providerName: 'skip' },
    ]);
  }
  if (request.method === 'POST' && url.pathname === '/api/admin/users') {
    return json({ id: userId, status: 'pending' }, 201);
  }
  if (request.method === 'POST' && url.pathname === '/api/admin/organizations') {
    return json({ id: 'org-1', slug: 'acme' }, 201);
  }
  if (request.method === 'POST' && url.pathname === '/api/admin/oauth-clients') {
    return json({ client_id: 'cli_1', client_secret: 'secret-once' }, 201);
  }
  if (
    request.method === 'POST' &&
    url.pathname === '/api/admin/oauth-clients/cli_1/rotate-secret'
  ) {
    return json({ client_id: 'cli_1', client_secret: 'rotated-secret' });
  }
  if (
    request.method === 'POST' &&
    url.pathname === '/api/v1/account/identity-links/unlink/prepare'
  ) {
    return json({ confirmation_token: 'a'.repeat(43) });
  }
  if (request.method === 'PUT' || request.method === 'PATCH' || request.method === 'DELETE') {
    return new Response(null, { status: 204 });
  }
  return json({ error: 'unmapped', key }, 500);
}

function world(user: string | null): { store: Store; session: Session } {
  const store = createStore(systemClock());
  const session = createSession(store, user, user ? store.clock.now() : null);
  return { store, session };
}

function form(session: Session, fields: Record<string, string> = {}): URLSearchParams {
  return new URLSearchParams({ _csrf: session.csrf, ...fields });
}

async function run(
  respond: (request: Request) => Response,
  session: Session,
  store: Store,
  method: string,
  path: string,
  fields?: Record<string, string>,
): Promise<Outcome> {
  const url = new URL(path, 'http://identity.test');
  const outcome =
    method === 'GET'
      ? view(store, session, undefined, url, true)
      : { type: 'page' as const, session };
  return applyDirectory(clientFor(respond), {
    method,
    url,
    store,
    session,
    form: form(session, fields),
    outcome,
    revealSecrets: true,
  });
}

describe('openapi directory client', () => {
  test('constructs a client without a custom fetch', () => {
    const client = createIdentityClient({ baseUrl: 'http://identity.test' });
    expect(client.GET).toBeTypeOf('function');
  });

  test('loads directory pages from the API and writes back through it', async () => {
    const { store, session } = world('u_ada');
    const respond = (request: Request) => fixtures(request);
    const users = await run(respond, session, store, 'GET', '/admin/users?q=ada&status=active');
    expect(users.page?.page).toBe('users');
    if (users.page?.page === 'users')
      expect(users.page.users.map((user) => user.login)).toEqual(['ada']);

    const archived = await run(respond, session, store, 'GET', '/admin/users?status=archived');
    if (archived.page?.page === 'users')
      expect(archived.page.users.map((user) => user.login)).toEqual(['old']);

    const organizations = await run(
      respond,
      session,
      store,
      'GET',
      '/admin/organizations?status=active',
    );
    if (organizations.page?.page === 'organizations') {
      expect(organizations.page.organizations[0]?.slug).toBe('acme');
      expect(organizations.page.organizations[0]?.activeMemberCount).toBe(2);
      expect(organizations.page.organizations[0]?.activeClientCount).toBe(1);
    }
    const hidden = await run(
      respond,
      session,
      store,
      'GET',
      '/admin/organizations?status=archived',
    );
    if (hidden.page?.page === 'organizations') expect(hidden.page.organizations).toEqual([]);

    const invite = await run(respond, session, store, 'GET', '/admin/users/invite');
    if (invite.page?.page === 'invite') expect(invite.page.organizations[0]?.id).toBe('acme');
    const register = await run(respond, session, store, 'GET', '/admin/oauth-clients/register');
    if (register.page?.page === 'register-client')
      expect(register.page.organizations[0]?.slug).toBe('acme');

    const members = await run(
      respond,
      session,
      store,
      'GET',
      '/admin/memberships?organization=acme',
    );
    if (members.page?.page === 'memberships') {
      expect(members.page.organizationId).toBe('acme');
      expect(members.page.members[0]?.role).toBe('owner');
      expect(members.page.members[1]?.role).toBe('member');
    }

    const clients = await run(
      respond,
      session,
      store,
      'GET',
      '/admin/oauth-clients?organization=acme&status=revoked',
    );
    if (clients.page?.page === 'clients')
      expect(clients.page.clients.map((item) => item.id)).toEqual(['cli_revoked']);

    const audit = await run(
      respond,
      session,
      store,
      'GET',
      '/admin/audit?action=admin.user_created&actor=ada&target=user:1&from=2026-01-01&to=2026-02-01',
    );
    if (audit.page?.page === 'audit')
      expect(audit.page.records.map((record) => record.id)).toEqual(['aud_1']);

    const links = await run(respond, session, store, 'GET', '/account/identity-links');
    if (links.page?.page === 'links')
      expect(links.page.links[0]?.issuer).toBe('https://accounts.google.example');

    const detail = await run(respond, session, store, 'GET', `/admin/users/${userId}`);
    if (detail.page?.page === 'user') {
      expect(detail.page.user.emailVerified).toBe(true);
      expect(detail.page.user.memberships[0]?.slug).toBe('acme');
      expect(detail.page.showArchive).toBe(true);
    }
    const old = await run(respond, session, store, 'GET', `/admin/users/${archivedId}`);
    if (old.page?.page === 'user') {
      expect(old.page.showRestore).toBe(true);
      expect(old.page.showPasswordReset).toBe(false);
    }
    const missingUser = await run(respond, session, store, 'GET', '/admin/users/missing');
    expect(missingUser.page?.page).toBe('not-found');

    const org = await run(respond, session, store, 'GET', '/admin/organizations/acme');
    if (org.page?.page === 'organization') expect(org.page.organization.memberCount).toBe(2);
    const missingOrg = await run(respond, session, store, 'GET', '/admin/organizations/missing');
    expect(missingOrg.page?.page).toBe('not-found');

    session.secretReveal = { clientId: 'cli_1', secret: 'secret-once' };
    const kept = await applyDirectory(clientFor(respond), {
      method: 'GET',
      url: new URL('http://identity.test/admin/oauth-clients/cli_1'),
      store,
      session,
      form: new URLSearchParams(),
      outcome: view(
        store,
        session,
        undefined,
        new URL('http://identity.test/admin/oauth-clients/cli_1'),
        false,
      ),
      revealSecrets: false,
    });
    if (kept.page?.page === 'client') expect(kept.page.secret).toBe('secret-once');
    expect(session.secretReveal?.secret).toBe('secret-once');
    const revealed = await run(respond, session, store, 'GET', '/admin/oauth-clients/cli_1');
    if (revealed.page?.page === 'client') expect(revealed.page.secret).toBe('secret-once');
    expect(session.secretReveal).toBeNull();

    const revoked = await run(respond, session, store, 'GET', '/admin/oauth-clients/cli_revoked');
    if (revoked.page?.page === 'client') expect(revoked.page.canModify).toBe(false);
    const missingClient = await run(respond, session, store, 'GET', '/admin/oauth-clients/missing');
    expect(missingClient.page?.page).toBe('not-found');

    const record = await run(respond, session, store, 'GET', '/admin/audit/aud_1');
    if (record.page?.page === 'audit-record') expect(record.page.record.correlationId).toBe('c1');
    const missingAudit = await run(respond, session, store, 'GET', '/admin/audit/missing');
    expect(missingAudit.page?.page).toBe('not-found');

    const invited = await run(respond, session, store, 'POST', '/admin/users/invite', {
      login: 'new',
      email: 'new@identity.example',
      displayName: 'New',
      organization: 'acme',
      role: 'member',
    });
    expect(invited.location).toBe(`/admin/users/${userId}?banner=invited`);

    const created = await run(respond, session, store, 'POST', '/admin/organizations/create', {
      slug: 'acme',
      name: 'Acme',
    });
    expect(created.location).toBe('/admin/organizations/acme?banner=created');

    const added = await run(respond, session, store, 'POST', '/admin/memberships/add', {
      organization: 'acme',
      user: 'ada@identity.example',
      role: 'owner',
    });
    expect(added.location).toContain('banner=added');

    const changed = await run(respond, session, store, 'POST', '/admin/memberships/role-change', {
      organization: 'acme',
      user: userId,
      role: 'member',
    });
    expect(changed.location).toContain('banner=role-changed');

    const removed = await run(respond, session, store, 'POST', '/admin/memberships/remove', {
      organization: 'acme',
      user: userId,
    });
    expect(removed.location).toContain('banner=removed');

    const registered = await run(respond, session, store, 'POST', '/admin/oauth-clients/register', {
      name: 'cli_1',
      organization: 'acme',
      redirectUris: 'https://acme.example/callback',
      scopes: 'openid, profile',
    });
    expect(registered.location).toContain('banner=registered');
    expect(session.secretReveal?.secret).toBe('secret-once');

    const saved = await run(respond, session, store, 'POST', '/admin/oauth-clients/cli_1/edit', {
      redirectUris: 'https://acme.example/callback',
      scopes: 'openid',
    });
    expect(saved.location).toContain('banner=metadata-updated');

    const rotated = await run(
      respond,
      session,
      store,
      'POST',
      '/admin/oauth-clients/cli_1/rotate-secret',
    );
    expect(rotated.location).toContain('banner=secret-rotated');
    expect(session.secretReveal?.secret).toBe('rotated-secret');

    const gone = await run(respond, session, store, 'POST', '/admin/oauth-clients/cli_1/revoke');
    expect(gone.location).toContain('banner=revoked');

    const archivedUser = await run(
      respond,
      session,
      store,
      'POST',
      `/admin/users/${userId}/archive`,
    );
    expect(archivedUser.location).toContain('banner=archived');

    const savedOrg = await run(
      respond,
      session,
      store,
      'POST',
      '/admin/organizations/acme/settings',
      {
        name: 'Acme Inc',
      },
    );
    expect(savedOrg.location).toContain('banner=saved');

    const archivedOrg = await run(
      respond,
      session,
      store,
      'POST',
      '/admin/organizations/acme/archive',
    );
    expect(archivedOrg.location).toBe('/admin/organizations');

    const prepared = await run(
      respond,
      session,
      store,
      'POST',
      '/account/identity-links/unlink/start',
      {
        issuer: 'https://accounts.google.example',
        subject: 'subject-1',
      },
    );
    expect(prepared.location).toBe('/account/identity-links/unlink/confirm');
    const confirm = await run(
      respond,
      session,
      store,
      'GET',
      '/account/identity-links/unlink/confirm',
    );
    if (confirm.page?.page === 'unlink-confirm') expect(confirm.page.provider).toBe('google');
    const confirmed = await run(
      respond,
      session,
      store,
      'POST',
      '/account/identity-links/unlink/confirm',
    );
    expect(confirmed.location).toContain('banner=unlinked');
  });

  test('keeps the in-memory page when the API fails and rejects bad writes', async () => {
    const { store, session } = world('u_ada');
    const down = new Set([
      'GET /api/admin/users',
      'GET /api/admin/organizations',
      'GET /api/admin/oauth-clients',
      'GET /api/admin/audit',
      'GET /api/v1/account/identity-links',
    ]);
    const failed = (request: Request) => fixtures(request, down);
    const users = await run(failed, session, store, 'GET', '/admin/users');
    expect(users.page?.page).toBe('users');
    if (users.page?.page === 'users')
      expect(users.page.users.some((user) => user.login === 'ada')).toBe(true);

    const organizations = await run(failed, session, store, 'GET', '/admin/organizations');
    expect(organizations.page?.page).toBe('organizations');
    const invite = await run(failed, session, store, 'GET', '/admin/users/invite');
    expect(invite.page?.page).toBe('invite');
    const members = await run(failed, session, store, 'GET', '/admin/memberships');
    expect(members.page?.page).toBe('memberships');
    const clients = await run(failed, session, store, 'GET', '/admin/oauth-clients');
    expect(clients.page?.page).toBe('clients');
    const audit = await run(
      failed,
      session,
      store,
      'GET',
      '/admin/audit?from=not-a-date&to=also-bad',
    );
    expect(audit.page?.page).toBe('audit');
    const links = await run(failed, session, store, 'GET', '/account/identity-links');
    expect(links.page?.page).toBe('links');

    const denied = await run(failed, session, store, 'GET', '/login');
    expect(denied.page?.page).toBe('login');

    const required = await run(fixtures, session, store, 'POST', '/admin/users/invite', {
      role: 'member',
    });
    expect(required.location).toContain('error=required');
    const badRole = await run(fixtures, session, store, 'POST', '/admin/users/invite', {
      login: 'new',
      email: 'new@identity.example',
      organization: 'acme',
      role: 'nope',
    });
    expect(badRole.location).toContain('error=required');

    const conflict = (request: Request) =>
      request.method === 'POST' && new URL(request.url).pathname === '/api/admin/users'
        ? json({}, 400)
        : fixtures(request);
    const rejected = await run(conflict, session, store, 'POST', '/admin/users/invite', {
      login: 'new',
      email: 'new@identity.example',
    });
    expect(rejected.location).toContain('error=conflict');

    const invalidOrg = (request: Request) =>
      request.method === 'PUT' ? json({}, 404) : fixtures(request);
    const notJoined = await run(invalidOrg, session, store, 'POST', '/admin/users/invite', {
      login: 'new',
      email: 'new@identity.example',
      organization: 'acme',
      role: 'owner',
    });
    expect(notJoined.location).toContain('error=invalid-org');

    const blocked = (request: Request) => {
      const path = new URL(request.url).pathname;
      if (request.method === 'DELETE' && path.endsWith(`/${userId}`)) return json({}, 409);
      if (request.method === 'DELETE') return json({}, 500);
      return fixtures(request);
    };
    const userBlocked = await run(
      blocked,
      session,
      store,
      'POST',
      `/admin/users/${userId}/archive`,
    );
    expect(userBlocked.location).toContain('banner=blocked');
    const userMissing = await run(blocked, session, store, 'POST', '/admin/users/missing/archive');
    expect(userMissing.location).toBe('/admin/users');

    const slug = await run(fixtures, session, store, 'POST', '/admin/organizations/create', {
      slug: '',
    });
    expect(slug.location).toContain('error=slug');
    const duplicate = (request: Request) =>
      request.method === 'POST' && new URL(request.url).pathname === '/api/admin/organizations'
        ? json({}, 409)
        : fixtures(request);
    const taken = await run(duplicate, session, store, 'POST', '/admin/organizations/create', {
      slug: 'acme',
      name: 'Acme',
    });
    expect(taken.location).toContain('error=duplicate-slug');
    const unnamed = (request: Request) =>
      request.method === 'POST' && new URL(request.url).pathname === '/api/admin/organizations'
        ? json({}, 400)
        : fixtures(request);
    const badOrg = await run(unnamed, session, store, 'POST', '/admin/organizations/create', {
      slug: 'acme',
    });
    expect(badOrg.location).toContain('error=slug');

    const unsaved = (request: Request) =>
      request.method === 'PATCH' ? json({}, 400) : fixtures(request);
    const settings = await run(
      unsaved,
      session,
      store,
      'POST',
      '/admin/organizations/acme/settings',
      {
        name: 'Acme',
      },
    );
    expect(settings.location).toBe('/admin/organizations/acme');
    const occupied = (request: Request) =>
      request.method === 'DELETE' &&
      new URL(request.url).pathname === '/api/admin/organizations/acme'
        ? json({}, 409)
        : fixtures(request);
    const stillThere = await run(
      occupied,
      session,
      store,
      'POST',
      '/admin/organizations/acme/archive',
    );
    expect(stillThere.location).toContain('banner=blocked');

    const noUser = await run(fixtures, session, store, 'POST', '/admin/memberships/add', {
      organization: 'acme',
      role: 'member',
    });
    expect(noUser.location).toContain('error=user-not-found');
    const unknown = await run(fixtures, session, store, 'POST', '/admin/memberships/add', {
      organization: 'acme',
      user: 'nobody',
      role: 'member',
    });
    expect(unknown.location).toContain('error=user-not-found');
    const archivedMember = await run(fixtures, session, store, 'POST', '/admin/memberships/add', {
      organization: 'acme',
      user: 'old',
      role: 'member',
    });
    expect(archivedMember.location).toContain('error=archived-user');
    const badMembership = (request: Request) =>
      request.method === 'PUT' ? json({}, 404) : fixtures(request);
    const notAdded = await run(badMembership, session, store, 'POST', '/admin/memberships/add', {
      organization: 'acme',
      user: 'ada',
      role: 'member',
    });
    expect(notAdded.location).toContain('error=invalid-org');
    const badChange = await run(
      fixtures,
      session,
      store,
      'POST',
      '/admin/memberships/role-change',
      {
        organization: 'acme',
        user: userId,
        role: 'nope',
      },
    );
    expect(badChange.location).toContain('error=user-not-found');
    const changeBlocked = (request: Request) =>
      request.method === 'PUT' ? json({}, 409) : fixtures(request);
    const blockedChange = await run(
      changeBlocked,
      session,
      store,
      'POST',
      '/admin/memberships/role-change',
      {
        organization: 'acme',
        user: userId,
        role: 'owner',
      },
    );
    expect(blockedChange.location).toContain('banner=blocked');
    const changeMissing = (request: Request) =>
      request.method === 'PUT' ? json({}, 404) : fixtures(request);
    const missingChange = await run(
      changeMissing,
      session,
      store,
      'POST',
      '/admin/memberships/role-change',
      {
        organization: 'acme',
        user: userId,
        role: 'owner',
      },
    );
    expect(missingChange.location).toContain('error=user-not-found');
    const removeMissing = (request: Request) =>
      request.method === 'DELETE' ? json({}, 404) : fixtures(request);
    const notRemoved = await run(
      removeMissing,
      session,
      store,
      'POST',
      '/admin/memberships/remove',
      {
        organization: 'acme',
        user: userId,
      },
    );
    expect(notRemoved.location).toContain('error=user-not-found');

    const nameless = await run(fixtures, session, store, 'POST', '/admin/oauth-clients/register', {
      organization: 'acme',
    });
    expect(nameless.location).toContain('error=name');
    const unregistered = (request: Request) =>
      request.method === 'POST' && new URL(request.url).pathname === '/api/admin/oauth-clients'
        ? json({}, 409)
        : fixtures(request);
    const notRegistered = await run(
      unregistered,
      session,
      store,
      'POST',
      '/admin/oauth-clients/register',
      {
        name: 'cli_1',
        organization: 'acme',
      },
    );
    expect(notRegistered.location).toContain('error=invalid-org');
    const unsavedClient = (request: Request) =>
      request.method === 'PUT' ? json({}, 400) : fixtures(request);
    const notEdited = await run(
      unsavedClient,
      session,
      store,
      'POST',
      '/admin/oauth-clients/cli_1/edit',
      {
        scopes: 'openid',
      },
    );
    expect(notEdited.location).toBe('/admin/oauth-clients/cli_1');
    const notRotated = (request: Request) =>
      request.url.includes('rotate-secret') ? json({}, 409) : fixtures(request);
    const stayed = await run(
      notRotated,
      session,
      store,
      'POST',
      '/admin/oauth-clients/cli_1/rotate-secret',
    );
    expect(stayed.location).toBe('/admin/oauth-clients/cli_1');
    const notRevoked = (request: Request) =>
      request.method === 'DELETE' ? json({}, 404) : fixtures(request);
    const stillClient = await run(
      notRevoked,
      session,
      store,
      'POST',
      '/admin/oauth-clients/cli_1/revoke',
    );
    expect(stillClient.location).toBe('/admin/oauth-clients/cli_1');

    const noToken = (request: Request) =>
      request.url.includes('unlink/prepare')
        ? json({ confirmation_token: 1 }, 200)
        : fixtures(request);
    const notPrepared = await run(
      noToken,
      session,
      store,
      'POST',
      '/account/identity-links/unlink/start',
      {
        issuer: 'https://accounts.google.example',
        subject: 'subject-1',
      },
    );
    expect(notPrepared.location).toContain('error=last-method');
    const early = await run(
      fixtures,
      session,
      store,
      'POST',
      '/account/identity-links/unlink/confirm',
    );
    expect(early.location).toBe('/account/identity-links');

    const { store: memberStore, session: member } = world('u_marco');
    const memberPage = await run(fixtures, member, memberStore, 'GET', '/admin/users');
    expect(memberPage.page?.page).toBe('denied');
    const ignored = await run(fixtures, member, memberStore, 'POST', '/admin/users/invite', {
      login: 'new',
      email: 'new@identity.example',
    });
    expect(ignored.type).toBe('page');
    const { store: quietStore, session: quiet } = world(null);
    const anonymous = await run(fixtures, quiet, quietStore, 'GET', '/admin/users');
    expect(anonymous.page?.page).toBe('unauthenticated');
    const wrong = await applyDirectory(clientFor(fixtures), {
      method: 'POST',
      url: new URL('http://identity.test/admin/users/invite'),
      store,
      session,
      form: new URLSearchParams({ _csrf: 'nope' }),
      outcome: { type: 'page', session },
      revealSecrets: false,
    });
    expect(wrong).toEqual({ type: 'page', session });

    const other = await run(fixtures, session, store, 'POST', '/admin/logout');
    expect(other.type).toBe('page');
    const account = await run(fixtures, session, store, 'POST', '/account/identity-links/cancel');
    expect(account.type).toBe('page');

    const emptyMembers = (request: Request) =>
      request.url.includes('/members') ? json({ items: [] }) : fixtures(request);
    const nobody = await run(emptyMembers, session, store, 'GET', '/admin/memberships');
    if (nobody.page?.page === 'memberships') expect(nobody.page.members).toEqual([]);

    const prepared = await run(
      fixtures,
      session,
      store,
      'POST',
      '/account/identity-links/unlink/start',
      {
        issuer: 'https://accounts.google.example',
        subject: 'subject-1',
      },
    );
    expect(prepared.location).toContain('confirm');
    const unlinkFailed = (request: Request) =>
      request.method === 'DELETE' && request.url.includes('identity-links')
        ? json({}, 409)
        : fixtures(request);
    const failedUnlink = await run(
      unlinkFailed,
      session,
      store,
      'POST',
      '/account/identity-links/unlink/confirm',
    );
    expect(failedUnlink.location).toContain('error=last-method');
  });

  test('the identity server reads the user list through the generated client', async () => {
    const { store, session } = world('u_ada');
    const directory = await mkdtemp(join(tmpdir(), 'identity-assets-'));
    const assets = new URL(`${directory}/`, 'file:');
    await writeFile(new URL('main.js', assets), 'console.log(1)\n');
    const page = await routeRequest(
      new Request('https://identity.test/admin/users', {
        headers: { accept: 'application/json', cookie: `identity_session=${session.id}` },
      }),
      store,
      assets,
    );
    const body = (await page.json()) as { page?: string; users?: Array<{ login: string }> };
    expect(body.page).toBe('users');
    expect(Array.isArray(body.users)).toBe(true);

    const posted = await handle(
      new Request('http://identity.test/admin/users/invite', {
        method: 'POST',
        headers: {
          cookie: `identity_session=${session.id}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          _csrf: session.csrf,
          login: 'brand-new',
          email: 'brand-new@identity.example',
          displayName: 'Brand New',
          role: 'member',
        }),
      }),
      store,
      clientFor((request) =>
        request.method === 'POST'
          ? json({ id: userId, status: 'pending' }, 201)
          : fixtures(request),
      ),
    );
    expect(posted.status).toBe(303);
    expect(posted.headers.get('location')).toBe(`/admin/users/${userId}?banner=invited`);
  });
});
