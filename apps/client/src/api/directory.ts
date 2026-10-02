import {
  actorFields,
  bannerFrom,
  currentUser,
  isOwner,
  isPlatformAdmin,
  type MembershipRole,
  type Outcome,
  type PageModel,
  type Session,
  type Store,
} from '../domain/model.ts';
import type { IdentityClient } from './client.ts';

const USER_BANNERS = ['invited', 'archived', 'restored', 'password-reset', 'blocked'] as const;
const ORG_BANNERS = ['created', 'saved', 'archived'] as const;
const CLIENT_BANNERS = ['registered', 'secret-rotated', 'metadata-updated', 'revoked'] as const;

interface PendingUnlink {
  token: string;
  userId: string;
  provider: string;
  subjectHint: string;
}

const pendingUnlink = new WeakMap<Session, PendingUnlink>();

export async function applyDirectory(
  client: IdentityClient,
  input: {
    method: string;
    url: URL;
    store: Store;
    session: Session;
    form: URLSearchParams;
    outcome: Outcome;
    revealSecrets: boolean;
  },
): Promise<Outcome> {
  const person = currentUser(input.store, input.session);
  if (person?.status !== 'active') return input.outcome;
  if (input.method === 'POST') {
    if (input.form.get('_csrf') !== input.session.csrf) return input.outcome;
    if (input.url.pathname.startsWith('/account/identity-links')) {
      return (await postAccount(client, input, person.id)) ?? input.outcome;
    }
    if (!isPlatformAdmin(person) && !isOwner(input.store, person)) return input.outcome;
    return (await postDirectory(client, input)) ?? input.outcome;
  }
  if (
    !input.url.pathname.startsWith('/account/') &&
    !isPlatformAdmin(person) &&
    !isOwner(input.store, person)
  ) {
    return input.outcome;
  }
  return getDirectory(client, input);
}

async function postDirectory(
  client: IdentityClient,
  input: {
    url: URL;
    store: Store;
    session: Session;
    form: URLSearchParams;
    outcome: Outcome;
  },
): Promise<Outcome | undefined> {
  const path = input.url.pathname;
  const form = input.form;
  if (form.get('_csrf') !== input.session.csrf) return undefined;
  if (path === '/admin/users/invite') return invite(client, input);
  if (path === '/admin/organizations/create') return createOrganization(client, input);
  if (path === '/admin/memberships/add') return addMember(client, input);
  if (path === '/admin/memberships/role-change') return changeMember(client, input);
  if (path === '/admin/memberships/remove') return removeMember(client, input);
  if (path === '/admin/oauth-clients/register') return registerClient(client, input);

  const userAction = /^\/admin\/users\/([^/]+)\/archive$/.exec(path);
  if (userAction?.[1]) return archiveUser(client, input, decode(userAction[1]));
  const orgAction = /^\/admin\/organizations\/([^/]+)\/(settings|archive)$/.exec(path);
  if (orgAction?.[1] && orgAction[2]) {
    return orgAction[2] === 'settings'
      ? saveOrganization(client, input, decode(orgAction[1]))
      : archiveOrganization(client, input, decode(orgAction[1]));
  }
  const clientAction = /^\/admin\/oauth-clients\/([^/]+)\/(edit|rotate-secret|revoke)$/.exec(path);
  if (clientAction?.[1] && clientAction[2]) {
    const id = decode(clientAction[1]);
    if (clientAction[2] === 'edit') return saveClient(client, input, id);
    if (clientAction[2] === 'rotate-secret') return rotateClient(client, input, id);
    return revokeClient(client, input, id);
  }
  return undefined;
}

async function getDirectory(
  client: IdentityClient,
  input: {
    url: URL;
    store: Store;
    session: Session;
    outcome: Outcome;
    revealSecrets: boolean;
  },
): Promise<Outcome> {
  const path = input.url.pathname;
  const page = input.outcome.page;
  if (!page || page.page === 'denied' || page.page === 'unauthenticated') return input.outcome;
  if (page.page === 'users') {
    const users = await usersOf(client);
    if (!users) return input.outcome;
    const query = page.query.trim().toLowerCase();
    return show(input, {
      ...page,
      users: users.filter((user) => {
        if (page.status !== 'all' && user.status !== page.status) return false;
        if (!query) return true;
        return (
          user.login.toLowerCase().includes(query) ||
          user.displayName.toLowerCase().includes(query) ||
          user.email.toLowerCase().includes(query)
        );
      }),
    });
  }
  if (page.page === 'organizations') {
    const organizations = await organizationsOf(client);
    if (!organizations) return input.outcome;
    return show(input, {
      ...page,
      organizations: organizations.filter(
        (organization) => page.status === 'all' || organization.status === page.status,
      ),
    });
  }
  if (page.page === 'invite' || page.page === 'register-client') {
    const organizations = await orgChoices(client);
    if (!organizations) return input.outcome;
    return show(input, { ...page, organizations });
  }
  if (page.page === 'memberships') {
    const organizations = await orgChoices(client);
    if (!organizations) return input.outcome;
    const requested = input.url.searchParams.get('organization') ?? '';
    const organizationId = organizations.some((organization) => organization.id === requested)
      ? requested
      : (organizations[0]?.id ?? '');
    const members = organizationId ? ((await membersOf(client, organizationId)) ?? []) : [];
    return show(input, { ...page, organizations, organizationId, members });
  }
  if (page.page === 'clients') {
    const organizations = await orgChoices(client);
    const clients = await clientsOf(client);
    if (!organizations || !clients) return input.outcome;
    const organizationId = page.organizationId;
    return show(input, {
      ...page,
      organizations,
      clients: clients.filter((item) => {
        if (organizationId && item.organization !== organizationId) return false;
        return page.status === 'all' || item.status === page.status;
      }),
    });
  }
  if (page.page === 'audit') {
    const records = await auditOf(client);
    if (!records) return input.outcome;
    const filters = page.filters;
    const from = Date.parse(filters.from);
    const to = Date.parse(filters.to);
    const filtered = records.filter((record) => {
      if (filters.action && record.action.toLowerCase() !== filters.action.toLowerCase()) {
        return false;
      }
      if (filters.actor && record.actor.toLowerCase() !== filters.actor.toLowerCase()) {
        return false;
      }
      if (filters.target && record.target.toLowerCase() !== filters.target.toLowerCase()) {
        return false;
      }
      if (!Number.isNaN(from) && Date.parse(record.timestamp) < from) return false;
      if (!Number.isNaN(to) && Date.parse(record.timestamp) > to) return false;
      return true;
    });
    return show(input, { ...page, records: filtered, count: filtered.length });
  }
  if (page.page === 'links') {
    const links = await linksForSession(client, input.store, input.session);
    if (!links) return input.outcome;
    return show(input, { ...page, links });
  }

  const userId = match(path, /^\/admin\/users\/([^/]+)$/);
  if (userId && (page.page === 'user' || page.page === 'not-found')) {
    const user = await userOf(client, userId);
    if (!user) return input.outcome;
    return show(input, {
      page: 'user',
      user,
      banner: bannerFrom(input.url, USER_BANNERS),
      showArchive: user.status !== 'archived',
      showRestore: user.status === 'archived',
      showPasswordReset: user.email !== '',
    });
  }
  const slug = match(path, /^\/admin\/organizations\/([^/]+)$/);
  if (slug && (page.page === 'organization' || page.page === 'not-found')) {
    const organization = await organizationOf(client, slug);
    if (!organization) return input.outcome;
    return show(input, {
      page: 'organization',
      organization,
      banner: bannerFrom(input.url, ORG_BANNERS),
      canEdit: true,
      canArchive: organization.status === 'active',
    });
  }
  const clientId = match(path, /^\/admin\/oauth-clients\/([^/]+)$/);
  if (clientId && (page.page === 'client' || page.page === 'not-found')) {
    const record = await clientOf(client, clientId, input.session, input.revealSecrets);
    if (!record) return input.outcome;
    return show(input, {
      page: 'client',
      client: record.client,
      banner: bannerFrom(input.url, CLIENT_BANNERS),
      secret: record.secret,
      canModify: record.client.status !== 'revoked',
    });
  }
  const auditId = match(path, /^\/admin\/audit\/([^/]+)$/);
  if (auditId && (page.page === 'audit-record' || page.page === 'not-found')) {
    const records = await auditOf(client);
    const record = records?.find((item) => item.id === auditId);
    if (!record) return input.outcome;
    return show(input, { page: 'audit-record', record });
  }
  if (path === '/account/identity-links/unlink/confirm') {
    const pending = pendingUnlink.get(input.session);
    if (!pending) return input.outcome;
    return show(input, {
      page: 'unlink-confirm',
      provider: pending.provider,
      issuer: input.session.unlinkConfirmation?.issuer ?? '',
      subjectHint: pending.subjectHint,
    });
  }
  return input.outcome;
}

async function postAccount(
  client: IdentityClient,
  input: { url: URL; store: Store; session: Session; form: URLSearchParams },
  actorId: string,
): Promise<Outcome | undefined> {
  if (input.url.pathname === '/account/identity-links/unlink/start') {
    return prepareUnlink(client, input, actorId);
  }
  if (input.url.pathname === '/account/identity-links/unlink/confirm') {
    return confirmUnlink(client, input);
  }
  return undefined;
}

async function invite(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
): Promise<Outcome> {
  const login = text(input.form, 'login');
  const email = text(input.form, 'email');
  const role = text(input.form, 'role');
  const organization = text(input.form, 'organization');
  if (!login || !email) return redirect(input.session, '/admin/users/invite?error=required');
  if (organization && role !== 'member' && role !== 'owner') {
    return redirect(input.session, '/admin/users/invite?error=required');
  }
  const created = await client.POST('/api/admin/users', {
    params: { header: idempotency() },
    body: { login, email, displayName: text(input.form, 'displayName') || login },
  });
  if (created.response.status === 400 || !created.data?.id) {
    return redirect(input.session, '/admin/users/invite?error=conflict');
  }
  if (organization) {
    const membership = await client.PUT('/api/admin/organizations/{slug}/members/{userId}', {
      params: {
        path: { slug: organization, userId: created.data.id },
        header: idempotency(),
      },
      body: { userId: created.data.id, role },
    });
    if (!membership.response.ok) {
      return redirect(input.session, '/admin/users/invite?error=invalid-org');
    }
  }
  return redirect(input.session, `/admin/users/${created.data.id}?banner=invited`);
}

async function archiveUser(
  client: IdentityClient,
  input: { session: Session },
  userId: string,
): Promise<Outcome> {
  const result = await client.DELETE('/api/admin/users/{userId}', {
    params: { path: { userId }, header: idempotency() },
  });
  const banner = result.response.status === 409 ? 'blocked' : 'archived';
  if (!result.response.ok && result.response.status !== 409) {
    return redirect(input.session, '/admin/users');
  }
  return redirect(input.session, `/admin/users/${userId}?banner=${banner}`);
}

async function createOrganization(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
): Promise<Outcome> {
  const slug = text(input.form, 'slug');
  const name = text(input.form, 'name') || slug;
  if (!slug || !name) return redirect(input.session, '/admin/organizations/create?error=slug');
  const created = await client.POST('/api/admin/organizations', {
    params: { header: idempotency() },
    body: { slug, name },
  });
  if (created.response.status === 409) {
    return redirect(input.session, '/admin/organizations/create?error=duplicate-slug');
  }
  if (!created.response.ok || !created.data?.slug) {
    return redirect(input.session, '/admin/organizations/create?error=slug');
  }
  return redirect(input.session, `/admin/organizations/${created.data.slug}?banner=created`);
}

async function saveOrganization(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
  slug: string,
): Promise<Outcome> {
  const name = text(input.form, 'name');
  const saved = await client.PATCH('/api/admin/organizations/{slug}', {
    params: { path: { slug }, header: idempotency() },
    body: { name },
  });
  if (!saved.response.ok) return redirect(input.session, `/admin/organizations/${slug}`);
  return redirect(input.session, `/admin/organizations/${slug}?banner=saved`);
}

async function archiveOrganization(
  client: IdentityClient,
  input: { session: Session },
  slug: string,
): Promise<Outcome> {
  const result = await client.DELETE('/api/admin/organizations/{slug}', {
    params: { path: { slug }, header: idempotency() },
  });
  if (result.response.status === 409) {
    return redirect(input.session, `/admin/organizations/${slug}?banner=blocked`);
  }
  if (!result.response.ok) return redirect(input.session, '/admin/organizations');
  return redirect(input.session, '/admin/organizations');
}

async function addMember(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
): Promise<Outcome> {
  const organization = text(input.form, 'organization');
  const identifier = text(input.form, 'user');
  const role = text(input.form, 'role');
  const back = `/admin/memberships?organization=${encodeURIComponent(organization)}`;
  if (!organization || !identifier || (role !== 'member' && role !== 'owner')) {
    return redirect(input.session, `${back}&error=user-not-found`);
  }
  const users = await usersOf(client);
  const user = users?.find((item) => item.login === identifier || item.email === identifier);
  if (!user) return redirect(input.session, `${back}&error=user-not-found`);
  if (user.status === 'archived') return redirect(input.session, `${back}&error=archived-user`);
  const saved = await client.PUT('/api/admin/organizations/{slug}/members/{userId}', {
    params: { path: { slug: organization, userId: user.id }, header: idempotency() },
    body: { userId: user.id, role },
  });
  if (!saved.response.ok) return redirect(input.session, `${back}&error=invalid-org`);
  return redirect(input.session, `${back}&banner=added`);
}

async function changeMember(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
): Promise<Outcome> {
  const organization = text(input.form, 'organization');
  const userId = text(input.form, 'user');
  const role = text(input.form, 'role');
  const back = `/admin/memberships?organization=${encodeURIComponent(organization)}`;
  if (role !== 'member' && role !== 'owner') {
    return redirect(input.session, `${back}&error=user-not-found`);
  }
  const saved = await client.PUT('/api/admin/organizations/{slug}/members/{userId}', {
    params: { path: { slug: organization, userId }, header: idempotency() },
    body: { userId, role },
  });
  if (saved.response.status === 409) return redirect(input.session, `${back}&banner=blocked`);
  if (!saved.response.ok) return redirect(input.session, `${back}&error=user-not-found`);
  return redirect(input.session, `${back}&banner=role-changed`);
}

async function removeMember(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
): Promise<Outcome> {
  const organization = text(input.form, 'organization');
  const userId = text(input.form, 'user');
  const back = `/admin/memberships?organization=${encodeURIComponent(organization)}`;
  const removed = await client.DELETE('/api/admin/organizations/{slug}/members/{userId}', {
    params: { path: { slug: organization, userId }, header: idempotency() },
  });
  if (!removed.response.ok) return redirect(input.session, `${back}&error=user-not-found`);
  return redirect(input.session, `${back}&banner=removed`);
}

async function registerClient(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
): Promise<Outcome> {
  const name = text(input.form, 'name');
  const organization = text(input.form, 'organization');
  if (!name || !organization) {
    return redirect(input.session, '/admin/oauth-clients/register?error=name');
  }
  const redirectUris = split(text(input.form, 'redirectUris'));
  const created = await client.POST('/api/admin/oauth-clients', {
    params: { header: idempotency() },
    body: {
      clientId: name,
      organizationSlug: organization,
      redirectUris,
      scopes: split(text(input.form, 'scopes')),
      browser: redirectUris.length > 0,
    },
  });
  if (!created.response.ok || !created.data?.client_id) {
    return redirect(input.session, '/admin/oauth-clients/register?error=invalid-org');
  }
  if (created.data.client_secret) {
    input.session.secretReveal = {
      clientId: created.data.client_id,
      secret: created.data.client_secret,
    };
  }
  return redirect(
    input.session,
    `/admin/oauth-clients/${created.data.client_id}?banner=registered`,
  );
}

async function saveClient(
  client: IdentityClient,
  input: { session: Session; form: URLSearchParams },
  clientId: string,
): Promise<Outcome> {
  const current = await client.GET('/api/admin/oauth-clients/{clientId}', {
    params: { path: { clientId } },
  });
  const redirectUris = split(text(input.form, 'redirectUris'));
  const saved = await client.PUT('/api/admin/oauth-clients/{clientId}', {
    params: { path: { clientId }, header: idempotency() },
    body: {
      organizationSlug: current.data?.organization_slug,
      redirectUris,
      scopes: split(text(input.form, 'scopes')),
      browser: current.data?.browser ?? redirectUris.length > 0,
    },
  });
  if (!saved.response.ok) return redirect(input.session, `/admin/oauth-clients/${clientId}`);
  return redirect(input.session, `/admin/oauth-clients/${clientId}?banner=metadata-updated`);
}

async function rotateClient(
  client: IdentityClient,
  input: { session: Session },
  clientId: string,
): Promise<Outcome> {
  const rotated = await client.POST('/api/admin/oauth-clients/{clientId}/rotate-secret', {
    params: { path: { clientId }, header: idempotency() },
    body: { version: crypto.randomUUID() },
  });
  if (!rotated.response.ok || !rotated.data?.client_secret) {
    return redirect(input.session, `/admin/oauth-clients/${clientId}`);
  }
  input.session.secretReveal = { clientId, secret: rotated.data.client_secret };
  return redirect(input.session, `/admin/oauth-clients/${clientId}?banner=secret-rotated`);
}

async function revokeClient(
  client: IdentityClient,
  input: { session: Session },
  clientId: string,
): Promise<Outcome> {
  const revoked = await client.DELETE('/api/admin/oauth-clients/{clientId}', {
    params: { path: { clientId }, header: idempotency() },
  });
  if (!revoked.response.ok) return redirect(input.session, `/admin/oauth-clients/${clientId}`);
  return redirect(input.session, `/admin/oauth-clients/${clientId}?banner=revoked`);
}

async function prepareUnlink(
  client: IdentityClient,
  input: { store: Store; session: Session; form: URLSearchParams },
  actorId: string,
): Promise<Outcome> {
  const issuer = text(input.form, 'issuer');
  const subject = text(input.form, 'subject');
  const userId = (await apiUserId(client, input.store, input.session)) ?? actorId;
  const prepared = await client.POST('/api/v1/account/identity-links/unlink/prepare', {
    params: { query: { issuer, subject } },
    headers: { 'x-user-id': userId, 'x-session-id': input.session.id },
  });
  const token = readToken(prepared.data);
  if (!prepared.response.ok || !token) {
    return redirect(input.session, '/account/identity-links?error=last-method');
  }
  const links = await linksOf(client, userId);
  const link = links?.find((item) => item.issuer === issuer);
  input.session.unlinkConfirmation = {
    issuer,
    subject,
    expiresAt: input.store.clock.now() + 300_000,
    sessionId: input.session.id,
  };
  pendingUnlink.set(input.session, {
    token,
    userId,
    provider: link?.provider ?? '',
    subjectHint: link?.subjectHint ?? '',
  });
  return redirect(input.session, '/account/identity-links/unlink/confirm');
}

async function confirmUnlink(
  client: IdentityClient,
  input: { session: Session },
): Promise<Outcome> {
  const pending = pendingUnlink.get(input.session);
  const confirmation = input.session.unlinkConfirmation;
  if (!pending || !confirmation) {
    return redirect(input.session, '/account/identity-links');
  }
  const removed = await client.DELETE('/api/v1/account/identity-links', {
    params: {
      query: {
        issuer: confirmation.issuer,
        subject: confirmation.subject,
        confirmationToken: pending.token,
      },
    },
    headers: { 'x-user-id': pending.userId, 'x-session-id': input.session.id },
  });
  pendingUnlink.delete(input.session);
  input.session.unlinkConfirmation = null;
  if (!removed.response.ok)
    return redirect(input.session, '/account/identity-links?error=last-method');
  return redirect(input.session, '/account/identity-links?banner=unlinked');
}

async function usersOf(client: IdentityClient) {
  const result = await client.GET('/api/admin/users');
  if (!result.response.ok || !result.data) return undefined;
  return result.data.flatMap((user) => {
    if (!user.id || !user.login) return [];
    return [
      {
        id: user.id,
        login: user.login,
        displayName: user.display_name ?? user.login,
        email: user.email ?? '',
        status: user.status ?? '',
        systemRole: '',
      },
    ];
  });
}

async function userOf(client: IdentityClient, userId: string) {
  const result = await client.GET('/api/admin/users/{userId}', { params: { path: { userId } } });
  if (!result.response.ok || !result.data?.id || !result.data.login) return undefined;
  const user = result.data;
  const id = user.id;
  const login = user.login;
  const organizations = (await organizationsOf(client)) ?? [];
  const memberships = [];
  for (const organization of organizations) {
    const members = (await membersOf(client, organization.slug)) ?? [];
    for (const member of members) {
      if (member.userId !== id) continue;
      memberships.push({
        organizationId: organization.slug,
        slug: organization.slug,
        name: organization.name,
        role: member.role,
      });
    }
  }
  return {
    id,
    login,
    displayName: user.display_name ?? login,
    email: user.email ?? '',
    status: user.status ?? '',
    systemRole: '',
    emailVerified: user.email_verified === true,
    memberships,
  };
}

async function organizationsOf(client: IdentityClient) {
  const result = await client.GET('/api/admin/organizations');
  const clients = await clientsOf(client);
  if (!result.response.ok || !result.data || !clients) return undefined;
  const rows = [];
  for (const organization of result.data) {
    const slug = organization.slug ?? '';
    if (!slug) continue;
    const members = (await membersOf(client, slug)) ?? [];
    rows.push({
      id: slug,
      slug,
      name: organization.name ?? slug,
      status: 'active',
      activeMemberCount: members.length,
      activeClientCount: clients.filter(
        (item) => item.organization === slug && item.status === 'active',
      ).length,
    });
  }
  return rows;
}

async function organizationOf(client: IdentityClient, slug: string) {
  const result = await client.GET('/api/admin/organizations/{slug}', {
    params: { path: { slug } },
  });
  if (!result.response.ok || !result.data?.slug) return undefined;
  const members = (await membersOf(client, result.data.slug)) ?? [];
  const clients = (await clientsOf(client)) ?? [];
  return {
    id: result.data.slug,
    slug: result.data.slug,
    name: result.data.name ?? result.data.slug,
    status: 'active',
    activeMemberCount: members.length,
    activeClientCount: clients.filter(
      (item) => item.organization === result.data?.slug && item.status === 'active',
    ).length,
    createdAt: result.data.created_at ?? '',
    memberCount: members.length,
  };
}

async function orgChoices(client: IdentityClient) {
  const organizations = await organizationsOf(client);
  return organizations?.map((organization) => ({
    id: organization.id,
    slug: organization.slug,
    name: organization.name,
  }));
}

async function membersOf(client: IdentityClient, slug: string) {
  const result = await client.GET('/api/v1/organizations/{slug}/members', {
    params: { path: { slug } },
  });
  if (!result.response.ok || !result.data?.items) return undefined;
  return result.data.items.flatMap((member) => {
    if (!member.subject || !member.login) return [];
    const role: MembershipRole = member.organization_role === 'owner' ? 'owner' : 'member';
    return [
      {
        organizationId: slug,
        userId: member.subject,
        login: member.login,
        email: member.email ?? '',
        role,
      },
    ];
  });
}

async function clientsOf(client: IdentityClient) {
  const result = await client.GET('/api/admin/oauth-clients');
  if (!result.response.ok || !result.data) return undefined;
  return result.data.flatMap((item) => {
    if (!item.client_id) return [];
    return [
      {
        id: item.client_id,
        organization: item.organization_slug ?? '',
        name: item.client_id,
        status: item.revoked_at ? 'revoked' : 'active',
      },
    ];
  });
}

async function clientOf(
  client: IdentityClient,
  clientId: string,
  session: Session,
  revealSecrets: boolean,
) {
  const result = await client.GET('/api/admin/oauth-clients/{clientId}', {
    params: { path: { clientId } },
  });
  if (!result.response.ok || !result.data?.client_id) return undefined;
  const item = result.data;
  const id = item.client_id;
  let secret: string | null = null;
  const reveal = session.secretReveal;
  if (reveal && reveal.clientId === id) {
    secret = reveal.secret;
    if (revealSecrets) session.secretReveal = null;
  }
  return {
    secret,
    client: {
      id,
      organizationId: item.organization_slug ?? '',
      organization: item.organization_slug ?? '',
      name: id,
      status: item.revoked_at ? 'revoked' : 'active',
      redirectUris: (item.redirect_uris ?? []).join(', '),
      grantTypes: '',
      scopes: (item.scopes ?? []).join(', '),
    },
  };
}

async function auditOf(client: IdentityClient) {
  const result = await client.GET('/api/admin/audit');
  if (!result.response.ok || !result.data) return undefined;
  return result.data.flatMap((record) => {
    if (!record.id) return [];
    return [
      {
        id: record.id,
        timestamp: record.created_at ?? '',
        action: record.action ?? '',
        actor: record.actor_client_id ?? '',
        target: record.target ?? '',
        correlationId: record.correlation_id ?? '',
        stateBefore: record.before_metadata ?? '',
        stateAfter: record.after_metadata ?? '',
      },
    ];
  });
}

async function linksForSession(client: IdentityClient, store: Store, session: Session) {
  const userId = await apiUserId(client, store, session);
  if (!userId) return undefined;
  return linksOf(client, userId);
}

async function linksOf(client: IdentityClient, userId: string) {
  const result = await client.GET('/api/v1/account/identity-links', {
    headers: { 'x-user-id': userId },
  });
  if (!result.response.ok || !result.data) return undefined;
  return result.data.flatMap((link) => {
    if (!link.issuer) return [];
    return [
      {
        issuer: link.issuer,
        subject: link.id ?? '',
        subjectHint: link.subjectHint ?? '',
        provider: link.providerName ?? '',
        linkedAt: link.createdAt ?? '',
      },
    ];
  });
}

async function apiUserId(client: IdentityClient, store: Store, session: Session) {
  const person = currentUser(store, session);
  if (!person) return undefined;
  const users = await usersOf(client);
  return users?.find((user) => user.login === person.login || user.email === person.email)?.id;
}

function show(input: { store: Store; session: Session; outcome: Outcome }, page: object): Outcome {
  const fields = actorFields(input.store, input.session);
  return {
    type: 'page',
    session: input.outcome.session,
    status: input.outcome.status,
    page: { ...fields, ...page } as PageModel,
  };
}

function redirect(session: Session, location: string): Outcome {
  return { type: 'redirect', location, session };
}

function text(form: URLSearchParams, name: string): string {
  return (form.get(name) ?? '').trim();
}

function split(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function decode(value: string): string {
  return decodeURIComponent(value);
}

function match(path: string, pattern: RegExp): string | undefined {
  const found = pattern.exec(path);
  return found?.[1] ? decode(found[1]) : undefined;
}

function idempotency(): { 'Idempotency-Key': string } {
  return { 'Idempotency-Key': crypto.randomUUID() };
}

function readToken(data: unknown): string | undefined {
  if (!data || typeof data !== 'object' || !('confirmation_token' in data)) return undefined;
  const token = data.confirmation_token;
  return typeof token === 'string' ? token : undefined;
}
