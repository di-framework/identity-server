import {
  AUTH_WINDOW_MS,
  activeClientCount,
  activeMemberCount,
  actorFields,
  adminAccess,
  archiveBlocked,
  bannerFrom,
  canManageOrganization,
  createSession,
  currentUser,
  eligibleForEmail,
  emailByToken,
  errorFrom,
  findUserByIdentifier,
  isPlatformAdmin,
  LINK_TTL_MS,
  type MembershipRole,
  manageableOrganizations,
  type Outcome,
  organizationById,
  ownersOf,
  type PageModel,
  recordAudit,
  type Session,
  SLUG_PATTERN,
  type Store,
  safeProviderUrl,
  sendEmail,
  signInMethodCount,
  splitList,
  UNLINK_TTL_MS,
  type User,
  visibleUsers,
} from './model.ts';
import { hashPassword, MIN_PASSWORD_LENGTH, passwordMatches } from './password.ts';

const USER_BANNERS = ['invited', 'archived', 'restored', 'password-reset', 'blocked'] as const;
const ORG_BANNERS = ['created', 'saved', 'archived'] as const;
const MEMBER_BANNERS = ['added', 'role-changed', 'removed', 'blocked'] as const;
const CLIENT_BANNERS = ['registered', 'secret-rotated', 'metadata-updated', 'revoked'] as const;
const LINK_BANNERS = ['linked', 'unlinked', 'canceled'] as const;
const MEMBER_ERRORS = ['invalid-org', 'user-not-found', 'archived-user', 'already-member'] as const;
const LINK_ERRORS = ['recent-auth', 'last-method', 'inactive-unlink'] as const;
const DEFAULT_GRANTS = ['authorization_code', 'refresh_token'];
const DEFAULT_SCOPES = ['openid', 'profile', 'email'];

export function view(
  store: Store,
  session: Session,
  emailToken: string | undefined,
  url: URL,
  revealSecrets = true,
): Outcome {
  const path = url.pathname;
  if (path === '/login') return show(store, session, { page: 'login' });
  if (path === '/passwordless') {
    return show(store, session, {
      page: 'passwordless',
      notice: url.searchParams.get('sent') === '1',
    });
  }
  if (path === '/passwordless/confirm') return confirmEmail(store, session, emailToken, url);
  if (path === '/account/password') return passwordPage(store, session, url);
  if (path === '/oauth2/consent') return consentPage(store, session, url);
  if (path === '/admin/users') return userList(store, session, url);
  if (path === '/admin/users/invite') return invitePage(store, session, url);
  if (path === '/admin/organizations') return organizationList(store, session, url);
  if (path === '/admin/organizations/create') return createOrganizationPage(store, session, url);
  if (path === '/admin/memberships') return membershipPage(store, session, url);
  if (path === '/admin/oauth-clients') return clientList(store, session, url);
  if (path === '/admin/oauth-clients/register') return registerPage(store, session, url);
  if (path === '/admin/audit') return auditList(store, session, url);
  if (path === '/account/identity-links') return linkList(store, session, url);
  if (path === '/account/identity-links/start') return startLink(store, session, url);
  if (path === '/account/identity-links/callback') return linkCallback(store, session, url);
  if (path === '/account/identity-links/confirm') return linkConfirm(store, session);
  if (path === '/account/identity-links/unlink/confirm') return unlinkConfirm(store, session);

  const userMatch = /^\/admin\/users\/([^/]+)$/.exec(path);
  if (userMatch?.[1]) return userDetail(store, session, url, userMatch[1]);
  const orgMatch = /^\/admin\/organizations\/([^/]+)$/.exec(path);
  if (orgMatch?.[1]) return organizationDetail(store, session, url, orgMatch[1]);
  const clientMatch = /^\/admin\/oauth-clients\/([^/]+)$/.exec(path);
  if (clientMatch?.[1]) return clientDetail(store, session, url, clientMatch[1], revealSecrets);
  const auditMatch = /^\/admin\/audit\/([^/]+)$/.exec(path);
  if (auditMatch?.[1]) return auditDetail(store, session, auditMatch[1]);
  return missing(store, session);
}

export function submit(
  store: Store,
  session: Session,
  emailToken: string | undefined,
  url: URL,
  form: URLSearchParams,
): Outcome {
  const path = url.pathname;
  if (!csrfOk(session, form)) return go(session, fallback(path));
  if (path === '/login') return signIn(store, session, form);
  if (path === '/passwordless') return requestEmail(store, session, form);
  if (path === '/passwordless/confirm') return consumeEmail(store, session, emailToken);
  if (path === '/account/password') return savePassword(store, session, form);
  if (path === '/oauth2/authorize') return allowConsent(store, session, form);
  if (path === '/admin/logout') return logOut(store, session);
  if (path === '/admin/users/invite') return inviteUser(store, session, form);
  if (path === '/admin/organizations/create') return createOrganization(store, session, form);
  if (path === '/admin/memberships/add') return addMember(store, session, form);
  if (path === '/admin/memberships/role-change') return changeRole(store, session, form);
  if (path === '/admin/memberships/remove') return removeMember(store, session, form);
  if (path === '/admin/oauth-clients/register') return registerClient(store, session, form);
  if (path === '/account/identity-links/confirm') return confirmLink(store, session);
  if (path === '/account/identity-links/cancel') return cancelLink(store, session);
  if (path === '/account/identity-links/unlink/start') return startUnlink(store, session, form);
  if (path === '/account/identity-links/unlink/confirm') return confirmUnlink(store, session);

  const userAction = /^\/admin\/users\/([^/]+)\/(archive|restore|password-reset)$/.exec(path);
  if (userAction?.[1] && userAction[2])
    return userActionSubmit(store, session, userAction[1], userAction[2]);
  const orgAction = /^\/admin\/organizations\/([^/]+)\/(settings|archive)$/.exec(path);
  if (orgAction?.[1] && orgAction[2])
    return organizationAction(store, session, form, orgAction[1], orgAction[2]);
  const clientAction = /^\/admin\/oauth-clients\/([^/]+)\/(edit|rotate-secret|revoke)$/.exec(path);
  if (clientAction?.[1] && clientAction[2]) {
    return clientActionSubmit(store, session, form, clientAction[1], clientAction[2]);
  }
  return go(session, '/login');
}

function confirmEmail(
  store: Store,
  session: Session,
  emailToken: string | undefined,
  url: URL,
): Outcome {
  const token = url.searchParams.get('token') ?? emailToken;
  const valid = usableEmailToken(store, token);
  if (!valid)
    return show(store, session, { page: 'passwordless-confirm', unavailable: true }, 200, null);
  return show(store, session, { page: 'passwordless-confirm', unavailable: false }, 200, token);
}

function passwordPage(store: Store, session: Session, url: URL): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const error = url.searchParams.get('error') === 'short' ? 'short' : null;
  return show(store, session, { page: 'password', error });
}

function consentPage(store: Store, session: Session, url: URL): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const clientId = url.searchParams.get('client_id') ?? '';
  const client = store.clients.find((item) => item.id === clientId && item.status === 'active');
  if (!client) return missing(store, session);
  const requested = (url.searchParams.get('scope') ?? client.scopes.join(' '))
    .split(/[\s,]+/)
    .filter(Boolean);
  const scopes = requested.filter((scope) => scope !== 'openid' && client.scopes.includes(scope));
  const redirectUri = url.searchParams.get('redirect_uri') ?? '';
  return show(store, session, {
    page: 'consent',
    clientName: client.name,
    clientId: client.id,
    scopes,
    redirectUri: client.redirectUris.includes(redirectUri) ? redirectUri : '',
  });
}

function userList(store: Store, session: Session, url: URL): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const query = url.searchParams.get('q') ?? '';
  const status = url.searchParams.get('status') ?? 'all';
  const needle = query.trim().toLowerCase();
  const users = visibleUsers(store, person)
    .filter((item) => status === 'all' || item.status === status)
    .filter((item) => {
      if (!needle) return true;
      return (
        item.login.toLowerCase().includes(needle) ||
        item.displayName.toLowerCase().includes(needle) ||
        (item.email ?? '').toLowerCase().includes(needle)
      );
    })
    .sort((left, right) => left.login.localeCompare(right.login))
    .map((item) => ({
      id: item.id,
      login: item.login,
      displayName: item.displayName,
      email: item.email ?? '',
      status: item.status,
      systemRole: item.systemRole,
    }));
  return show(store, session, { page: 'users', users, query, status });
}

function invitePage(store: Store, session: Session, url: URL): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  return show(store, session, {
    page: 'invite',
    organizations: orgChoices(store, person, true),
    error: errorFrom(url, ['conflict', 'required', 'invalid-org']),
  });
}

function userDetail(store: Store, session: Session, url: URL, id: string): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const target = visibleUsers(store, person).find((item) => item.id === id);
  if (!target) return missing(store, session);
  return show(store, session, {
    page: 'user',
    user: {
      id: target.id,
      login: target.login,
      displayName: target.displayName,
      email: target.email ?? '',
      status: target.status,
      systemRole: target.systemRole,
      emailVerified: target.emailVerified,
      memberships: store.memberships
        .filter((membership) => membership.userId === target.id)
        .map((membership) => {
          const organization = organizationById(store, membership.organizationId);
          return {
            organizationId: membership.organizationId,
            slug: organization?.slug ?? '',
            name: organization?.name ?? '',
            role: membership.role,
          };
        }),
    },
    banner: bannerFrom(url, USER_BANNERS),
    showArchive: target.status !== 'archived',
    showRestore: target.status === 'archived',
    showPasswordReset: target.email !== null,
  });
}

function organizationList(store: Store, session: Session, url: URL): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const status = url.searchParams.get('status') ?? 'all';
  const organizations = manageableOrganizations(store, person, false)
    .filter((organization) => status === 'all' || organization.status === status)
    .sort((left, right) => left.slug.localeCompare(right.slug))
    .map((organization) => orgRow(store, organization));
  return show(store, session, {
    page: 'organizations',
    organizations,
    status,
    canCreate: isPlatformAdmin(person),
  });
}

function createOrganizationPage(store: Store, session: Session, url: URL): Outcome {
  const person = requirePlatform(store, session);
  if (isOutcome(person)) return person;
  return show(store, session, {
    page: 'create-organization',
    error: errorFrom(url, ['slug', 'duplicate-slug']),
  });
}

function organizationDetail(store: Store, session: Session, url: URL, id: string): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const organization = manageableOrganizations(store, person, false).find((item) => item.id === id);
  if (!organization) return missing(store, session);
  const row = orgRow(store, organization);
  return show(store, session, {
    page: 'organization',
    organization: {
      ...row,
      createdAt: organization.createdAt,
      memberCount: store.memberships.filter(
        (membership) => membership.organizationId === organization.id,
      ).length,
    },
    banner: bannerFrom(url, ORG_BANNERS),
    canEdit: canManageOrganization(store, person, organization.id),
    canArchive: isPlatformAdmin(person) && organization.status === 'active',
  });
}

function membershipPage(store: Store, session: Session, url: URL): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const organizations = orgChoices(store, person, true);
  const requested = url.searchParams.get('organization') ?? '';
  const organizationId = organizations.some((organization) => organization.id === requested)
    ? requested
    : (organizations[0]?.id ?? '');
  const members = store.memberships
    .filter((membership) => membership.organizationId === organizationId)
    .flatMap((membership) => {
      const member = store.users.find((item) => item.id === membership.userId);
      if (!member) return [];
      return [
        {
          organizationId,
          userId: member.id,
          login: member.login,
          email: member.email ?? '',
          role: membership.role,
        },
      ];
    })
    .sort((left, right) => left.login.localeCompare(right.login));
  return show(store, session, {
    page: 'memberships',
    organizations,
    organizationId,
    members,
    banner: bannerFrom(url, MEMBER_BANNERS),
    error: errorFrom(url, MEMBER_ERRORS),
  });
}

function clientList(store: Store, session: Session, url: URL): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const organizations = orgChoices(store, person, false);
  const requested = url.searchParams.get('organization') ?? '';
  const organizationId = organizations.some((organization) => organization.id === requested)
    ? requested
    : '';
  const status = url.searchParams.get('status') ?? 'all';
  const allowed = new Set(organizations.map((organization) => organization.id));
  const clients = store.clients
    .filter((client) => allowed.has(client.organizationId))
    .filter((client) => !organizationId || client.organizationId === organizationId)
    .filter((client) => status === 'all' || client.status === status)
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((client) => ({
      id: client.id,
      organization: organizationById(store, client.organizationId)?.name ?? '',
      name: client.name,
      status: client.status,
    }));
  return show(store, session, { page: 'clients', organizations, organizationId, status, clients });
}

function registerPage(store: Store, session: Session, url: URL): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  return show(store, session, {
    page: 'register-client',
    organizations: orgChoices(store, person, true),
    error: errorFrom(url, ['invalid-org', 'name']),
  });
}

function clientDetail(
  store: Store,
  session: Session,
  url: URL,
  id: string,
  revealSecrets: boolean,
): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const allowed = new Set(
    manageableOrganizations(store, person, false).map((organization) => organization.id),
  );
  const client = store.clients.find((item) => item.id === id && allowed.has(item.organizationId));
  if (!client) return missing(store, session);
  const stored = session.secretReveal?.clientId === client.id ? session.secretReveal.secret : null;
  const secret = revealSecrets ? stored : null;
  if (revealSecrets && stored) session.secretReveal = null;
  return show(store, session, {
    page: 'client',
    client: {
      id: client.id,
      organizationId: client.organizationId,
      organization: organizationById(store, client.organizationId)?.name ?? '',
      name: client.name,
      status: client.status,
      redirectUris: client.redirectUris.join(', '),
      grantTypes: client.grantTypes.join(', '),
      scopes: client.scopes.join(', '),
    },
    banner: bannerFrom(url, CLIENT_BANNERS),
    secret,
    canModify: client.status !== 'revoked',
  });
}

function auditList(store: Store, session: Session, url: URL): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const filters = {
    action: url.searchParams.get('action') ?? '',
    actor: url.searchParams.get('actor') ?? '',
    target: url.searchParams.get('target') ?? '',
    from: url.searchParams.get('from') ?? '',
    to: url.searchParams.get('to') ?? '',
  };
  const from = Date.parse(filters.from);
  const to = Date.parse(filters.to);
  const records = visibleAudits(store, person)
    .filter(
      (record) => !filters.action || record.action.toLowerCase() === filters.action.toLowerCase(),
    )
    .filter(
      (record) => !filters.actor || record.actor.toLowerCase() === filters.actor.toLowerCase(),
    )
    .filter(
      (record) => !filters.target || record.target.toLowerCase() === filters.target.toLowerCase(),
    )
    .filter((record) => Number.isNaN(from) || Date.parse(record.timestamp) >= from)
    .filter((record) => Number.isNaN(to) || Date.parse(record.timestamp) <= to)
    .sort((left, right) => right.timestamp.localeCompare(left.timestamp))
    .map((record) => ({
      id: record.id,
      timestamp: record.timestamp,
      action: record.action,
      actor: record.actor,
      target: record.target,
    }));
  return show(store, session, { page: 'audit', count: records.length, records, filters });
}

function auditDetail(store: Store, session: Session, id: string): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const record = visibleAudits(store, person).find((item) => item.id === id);
  if (!record) return missing(store, session);
  return show(store, session, {
    page: 'audit-record',
    record: {
      id: record.id,
      timestamp: record.timestamp,
      action: record.action,
      actor: record.actor,
      target: record.target,
      correlationId: record.correlationId,
      stateBefore: record.stateBefore,
      stateAfter: record.stateAfter,
    },
  });
}

function linkList(store: Store, session: Session, url: URL): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  return show(store, session, {
    page: 'links',
    accountName: person.displayName,
    links: store.links
      .filter((item) => item.userId === person.id)
      .map((item) => ({
        issuer: item.issuer,
        subject: item.subject,
        subjectHint: item.subjectHint,
        provider: item.provider,
        linkedAt: item.linkedAt,
      })),
    banner: bannerFrom(url, LINK_BANNERS),
    error: errorFrom(url, LINK_ERRORS),
  });
}

function startLink(store: Store, session: Session, url: URL): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const provider = url.searchParams.get('provider') ?? '';
  const issuer = url.searchParams.get('issuer') ?? '';
  const returnUrl = url.searchParams.get('returnUrl') ?? '';
  const token = store.clock.hex(16);
  const subject = `sub_${store.clock.hex(8)}`;
  const safeProvider = provider.toLowerCase().replace(/[^a-z0-9-]/g, '') || 'provider';
  const location = safeProviderUrl(issuer, provider, token, returnUrl);
  if (!location || provider.trim() === '')
    return show(store, session, { page: 'link-unavailable' });
  session.pendingLink = {
    provider,
    issuer,
    subject,
    subjectHint: `••••${subject.slice(-4)}`,
    providerEmail: `user@${safeProvider}.example`,
    token,
    expiresAt: store.clock.now() + LINK_TTL_MS,
    userId: person.id,
    returnUrl,
  };
  return go(session, location);
}

function linkCallback(store: Store, session: Session, url: URL): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const pending = session.pendingLink;
  const error = url.searchParams.get('error');
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const valid =
    !error &&
    Boolean(code) &&
    Boolean(state) &&
    pending !== null &&
    pending?.token === state &&
    pending.userId === person.id &&
    pending.expiresAt > store.clock.now();
  if (!valid) {
    session.pendingLink = null;
    return show(store, session, { page: 'link-unavailable' });
  }
  return go(session, '/account/identity-links/confirm');
}

function linkConfirm(store: Store, session: Session): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const pending = session.pendingLink;
  if (!pending || pending.userId !== person.id || pending.expiresAt <= store.clock.now()) {
    return show(store, session, { page: 'link-unavailable' });
  }
  return show(store, session, {
    page: 'link-confirm',
    account: { displayName: person.displayName, login: person.login, email: person.email ?? '' },
    external: {
      provider: pending.provider,
      issuer: pending.issuer,
      subjectHint: pending.subjectHint,
      providerEmail: pending.providerEmail,
    },
  });
}

function unlinkConfirm(store: Store, session: Session): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const confirmation = session.unlinkConfirmation;
  const identity = store.links.find(
    (item) =>
      item.userId === person.id &&
      item.issuer === confirmation?.issuer &&
      item.subject === confirmation.subject,
  );
  if (
    !confirmation ||
    confirmation.sessionId !== session.id ||
    confirmation.expiresAt <= store.clock.now() ||
    !identity
  ) {
    return show(store, session, { page: 'link-unavailable' });
  }
  return show(store, session, {
    page: 'unlink-confirm',
    provider: identity.provider,
    issuer: identity.issuer,
    subjectHint: identity.subjectHint,
  });
}

function signIn(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = findUserByIdentifier(store, text(form, 'identifier'));
  const password = form.get('password') ?? '';
  if (
    !person ||
    person.status === 'inactive' ||
    person.status === 'archived' ||
    !passwordMatches(password, person.passwordHash)
  ) {
    return go(session, '/login');
  }
  dropSession(store, session);
  const next = createSession(store, person.id, store.clock.now());
  return go(next, '/account/identity-links');
}

function requestEmail(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = findUserByIdentifier(store, text(form, 'email'));
  if (eligibleForEmail(person)) sendEmail(store, person, 'sign-in');
  return go(session, '/passwordless?sent=1');
}

function consumeEmail(store: Store, session: Session, emailToken: string | undefined): Outcome {
  const email = usableEmailToken(store, emailToken);
  if (!email) return go(session, '/passwordless/confirm', null);
  const person = store.users.find((item) => item.id === email.userId);
  if (!eligibleForEmail(person)) return go(session, '/passwordless/confirm', null);
  store.emails = store.emails.filter((item) => item.token !== email.token);
  dropSession(store, session);
  const next = createSession(store, person.id, store.clock.now());
  return go(next, '/account/password', null);
}

function savePassword(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const password = form.get('password') ?? '';
  if (password.length < MIN_PASSWORD_LENGTH) return go(session, '/account/password?error=short');
  person.passwordHash = hashPassword(password);
  recordAudit(
    store,
    person.login,
    'user.password',
    `user:${person.id}`,
    null,
    person.id,
    '{}',
    '{"password":true}',
  );
  return go(session, '/account/password?updated=1');
}

function allowConsent(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const client = store.clients.find(
    (item) => item.id === text(form, 'client_id') && item.status === 'active',
  );
  if (!client) return go(session, '/oauth2/consent');
  return go(session, clientRedirect(client.redirectUris, text(form, 'redirect_uri')));
}

function logOut(store: Store, session: Session): Outcome {
  dropSession(store, session);
  return go(null, '/login?logout=1', null);
}

function inviteUser(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const login = text(form, 'login');
  const email = text(form, 'email');
  const role = text(form, 'role');
  if (!login || !email) return go(session, '/admin/users/invite?error=required');
  if (role !== 'member' && role !== 'owner')
    return go(session, '/admin/users/invite?error=required');
  if (taken(store, login, email)) return go(session, '/admin/users/invite?error=conflict');
  const organizationId = text(form, 'organization');
  if (organizationId) {
    const organization = organizationById(store, organizationId);
    if (
      organization?.status !== 'active' ||
      !canManageOrganization(store, person, organization?.id ?? '')
    ) {
      return go(session, '/admin/users/invite?error=invalid-org');
    }
  }
  const created: User = {
    id: `usr_${store.clock.hex(8)}`,
    login,
    displayName: text(form, 'displayName') || login,
    email,
    emailVerified: false,
    status: 'pending',
    systemRole: 'none',
    passwordHash: null,
  };
  store.users.push(created);
  if (organizationId) store.memberships.push({ organizationId, userId: created.id, role });
  sendEmail(store, created, 'invite');
  recordAudit(
    store,
    person.login,
    'user.invite',
    `user:${created.id}`,
    organizationId || null,
    created.id,
    '{}',
    JSON.stringify({ login, email, status: 'pending', role: organizationId ? role : null }),
  );
  return go(session, `/admin/users/${created.id}?banner=invited`);
}

function userActionSubmit(store: Store, session: Session, id: string, action: string): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const target = visibleUsers(store, person).find((item) => item.id === id);
  if (!target) return go(session, '/admin/users');
  const back = `/admin/users/${target.id}`;
  if (action === 'archive') {
    if (target.status === 'archived') return go(session, back);
    if (archiveBlocked(store, target)) return go(session, `${back}?banner=blocked`);
    const before = target.status;
    target.status = 'archived';
    recordAudit(
      store,
      person.login,
      'user.archive',
      `user:${target.id}`,
      null,
      target.id,
      JSON.stringify({ status: before }),
      JSON.stringify({ status: 'archived' }),
    );
    return go(session, `${back}?banner=archived`);
  }
  if (action === 'restore') {
    if (target.status !== 'archived') return go(session, back);
    target.status = 'active';
    recordAudit(
      store,
      person.login,
      'user.restore',
      `user:${target.id}`,
      null,
      target.id,
      '{"status":"archived"}',
      '{"status":"active"}',
    );
    return go(session, `${back}?banner=restored`);
  }
  if (!target.email) return go(session, back);
  const sent = sendEmail(store, target, 'password-reset');
  if (!sent) return go(session, `${back}?banner=blocked`);
  recordAudit(
    store,
    person.login,
    'user.password-reset',
    `user:${target.id}`,
    null,
    target.id,
    '{}',
    '{"email":true}',
  );
  return go(session, `${back}?banner=password-reset`);
}

function createOrganization(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requirePlatform(store, session);
  if (isOutcome(person)) return person;
  const slug = text(form, 'slug');
  if (!SLUG_PATTERN.test(slug)) return go(session, '/admin/organizations/create?error=slug');
  if (store.organizations.some((organization) => organization.slug === slug)) {
    return go(session, '/admin/organizations/create?error=duplicate-slug');
  }
  const name = text(form, 'name') || slug;
  const organization = {
    id: `org_${store.clock.hex(8)}`,
    slug,
    name,
    status: 'active' as const,
    createdAt: new Date(store.clock.now()).toISOString(),
  };
  store.organizations.push(organization);
  recordAudit(
    store,
    person.login,
    'organization.create',
    `organization:${slug}`,
    organization.id,
    null,
    '{}',
    JSON.stringify({ slug, name }),
  );
  return go(session, `/admin/organizations/${organization.id}?banner=created`);
}

function organizationAction(
  store: Store,
  session: Session,
  form: URLSearchParams,
  id: string,
  action: string,
): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const organization = manageableOrganizations(store, person, false).find((item) => item.id === id);
  if (!organization) return go(session, '/admin/organizations');
  const back = `/admin/organizations/${organization.id}`;
  if (action === 'settings') {
    if (!canManageOrganization(store, person, organization.id)) return go(session, back);
    const before = organization.name;
    organization.name = text(form, 'name') || organization.slug;
    recordAudit(
      store,
      person.login,
      'organization.settings',
      `organization:${organization.slug}`,
      organization.id,
      null,
      JSON.stringify({ name: before }),
      JSON.stringify({ name: organization.name }),
    );
    return go(session, `${back}?banner=saved`);
  }
  if (!isPlatformAdmin(person) || organization.status !== 'active') return go(session, back);
  organization.status = 'archived';
  recordAudit(
    store,
    person.login,
    'organization.archive',
    `organization:${organization.slug}`,
    organization.id,
    null,
    '{"status":"active"}',
    '{"status":"archived"}',
  );
  return go(session, `${back}?banner=archived`);
}

function addMember(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const organizationId = text(form, 'organization');
  const role = membershipRole(text(form, 'role'));
  const back = `/admin/memberships?organization=${encodeURIComponent(organizationId)}`;
  const organization = organizationById(store, organizationId);
  if (
    organization?.status !== 'active' ||
    !canManageOrganization(store, person, organization?.id ?? '') ||
    !role
  ) {
    return go(session, `${back}&error=invalid-org`);
  }
  const target = findUserByIdentifier(store, text(form, 'user'));
  if (!target) return go(session, `${back}&error=user-not-found`);
  if (target.status === 'archived') return go(session, `${back}&error=archived-user`);
  if (
    store.memberships.some(
      (membership) =>
        membership.organizationId === organization.id && membership.userId === target.id,
    )
  ) {
    return go(session, `${back}&error=already-member`);
  }
  store.memberships.push({ organizationId: organization.id, userId: target.id, role });
  recordAudit(
    store,
    person.login,
    'membership.add',
    `membership:${organization.slug}:${target.login}`,
    organization.id,
    target.id,
    '{}',
    JSON.stringify({ role }),
  );
  return go(session, `${back}&banner=added`);
}

function changeRole(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const organizationId = text(form, 'organization');
  const userId = text(form, 'user');
  const role = membershipRole(text(form, 'role'));
  const back = `/admin/memberships?organization=${encodeURIComponent(organizationId)}`;
  const organization = organizationById(store, organizationId);
  const membership = store.memberships.find(
    (item) => item.organizationId === organizationId && item.userId === userId,
  );
  if (
    !organization ||
    !membership ||
    !role ||
    !canManageOrganization(store, person, organization.id)
  ) {
    return go(session, `${back}&error=invalid-org`);
  }
  if (
    role === 'member' &&
    ownersOf(store, organization.id).length === 1 &&
    membership.role === 'owner'
  ) {
    return go(session, `${back}&banner=blocked`);
  }
  const before = membership.role;
  membership.role = role;
  recordAudit(
    store,
    person.login,
    'membership.role',
    `membership:${organization.slug}:${userId}`,
    organization.id,
    userId,
    JSON.stringify({ role: before }),
    JSON.stringify({ role }),
  );
  return go(session, `${back}&banner=role-changed`);
}

function removeMember(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const organizationId = text(form, 'organization');
  const userId = text(form, 'user');
  const back = `/admin/memberships?organization=${encodeURIComponent(organizationId)}`;
  const organization = organizationById(store, organizationId);
  const membership = store.memberships.find(
    (item) => item.organizationId === organizationId && item.userId === userId,
  );
  if (!organization || !membership || !canManageOrganization(store, person, organization.id)) {
    return go(session, `${back}&error=invalid-org`);
  }
  if (membership.role === 'owner' && ownersOf(store, organization.id).length === 1) {
    return go(session, `${back}&banner=blocked`);
  }
  store.memberships = store.memberships.filter((item) => item !== membership);
  recordAudit(
    store,
    person.login,
    'membership.remove',
    `membership:${organization.slug}:${userId}`,
    organization.id,
    userId,
    JSON.stringify({ role: membership.role }),
    '{}',
  );
  return go(session, `${back}&banner=removed`);
}

function registerClient(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const name = text(form, 'name');
  if (!name) return go(session, '/admin/oauth-clients/register?error=name');
  const organization = organizationById(store, text(form, 'organization'));
  if (
    organization?.status !== 'active' ||
    !canManageOrganization(store, person, organization?.id ?? '')
  ) {
    return go(session, '/admin/oauth-clients/register?error=invalid-org');
  }
  const client = {
    id: `cli_${store.clock.hex(16)}`,
    organizationId: organization.id,
    name,
    status: 'active' as const,
    redirectUris: splitList(text(form, 'redirectUris'), []),
    grantTypes: splitList(text(form, 'grantTypes'), DEFAULT_GRANTS),
    scopes: splitList(text(form, 'scopes'), DEFAULT_SCOPES),
  };
  store.clients.push(client);
  const secret = store.clock.hex(32);
  session.secretReveal = { clientId: client.id, secret };
  recordAudit(
    store,
    person.login,
    'client.register',
    `client:${client.id}`,
    organization.id,
    null,
    '{}',
    JSON.stringify({ name }),
  );
  return go(session, `/admin/oauth-clients/${client.id}?banner=registered`);
}

function clientActionSubmit(
  store: Store,
  session: Session,
  form: URLSearchParams,
  id: string,
  action: string,
): Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  const allowed = new Set(
    manageableOrganizations(store, person, false).map((organization) => organization.id),
  );
  const client = store.clients.find((item) => item.id === id && allowed.has(item.organizationId));
  if (!client) return go(session, '/admin/oauth-clients');
  const back = `/admin/oauth-clients/${client.id}`;
  if (client.status === 'revoked') return go(session, back);
  if (action === 'edit') {
    const before = {
      name: client.name,
      redirectUris: client.redirectUris,
      grantTypes: client.grantTypes,
      scopes: client.scopes,
    };
    client.name = text(form, 'name') || client.name;
    client.redirectUris = splitList(text(form, 'redirectUris'), client.redirectUris);
    client.grantTypes = splitList(text(form, 'grantTypes'), client.grantTypes);
    client.scopes = splitList(text(form, 'scopes'), client.scopes);
    recordAudit(
      store,
      person.login,
      'client.edit',
      `client:${client.id}`,
      client.organizationId,
      null,
      JSON.stringify(before),
      JSON.stringify({ name: client.name }),
    );
    return go(session, `${back}?banner=metadata-updated`);
  }
  if (action === 'rotate-secret') {
    session.secretReveal = { clientId: client.id, secret: store.clock.hex(32) };
    recordAudit(
      store,
      person.login,
      'client.rotate-secret',
      `client:${client.id}`,
      client.organizationId,
      null,
      '{}',
      '{"secret":true}',
    );
    return go(session, `${back}?banner=secret-rotated`);
  }
  client.status = 'revoked';
  session.secretReveal = null;
  recordAudit(
    store,
    person.login,
    'client.revoke',
    `client:${client.id}`,
    client.organizationId,
    null,
    '{"status":"active"}',
    '{"status":"revoked"}',
  );
  return go(session, `${back}?banner=revoked`);
}

function confirmLink(store: Store, session: Session): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const pending = session.pendingLink;
  if (!pending || pending.userId !== person.id || pending.expiresAt <= store.clock.now()) {
    session.pendingLink = null;
    return go(session, '/account/identity-links/confirm');
  }
  store.links.push({
    id: `link_${store.clock.hex(8)}`,
    userId: person.id,
    provider: pending.provider,
    issuer: pending.issuer,
    subject: pending.subject,
    subjectHint: pending.subjectHint,
    providerEmail: pending.providerEmail,
    linkedAt: new Date(store.clock.now()).toISOString(),
  });
  session.pendingLink = null;
  recordAudit(
    store,
    person.login,
    'link.confirm',
    `link:${pending.issuer}`,
    null,
    person.id,
    '{}',
    JSON.stringify({ issuer: pending.issuer }),
  );
  return go(session, '/account/identity-links?banner=linked');
}

function cancelLink(store: Store, session: Session): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  session.pendingLink = null;
  return go(session, '/account/identity-links?banner=canceled');
}

function startUnlink(store: Store, session: Session, form: URLSearchParams): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const issuer = text(form, 'issuer');
  const subject = text(form, 'subject');
  const identity = store.links.find(
    (item) => item.userId === person.id && item.issuer === issuer && item.subject === subject,
  );
  if (!identity) return go(session, '/account/identity-links/unlink/confirm');
  if (person.status !== 'active')
    return go(session, '/account/identity-links?error=inactive-unlink');
  if (
    session.authenticatedAt === null ||
    store.clock.now() - session.authenticatedAt > AUTH_WINDOW_MS
  ) {
    return go(session, '/account/identity-links?error=recent-auth');
  }
  if (signInMethodCount(store, person) <= 1)
    return go(session, '/account/identity-links?error=last-method');
  session.unlinkConfirmation = {
    issuer,
    subject,
    expiresAt: store.clock.now() + UNLINK_TTL_MS,
    sessionId: session.id,
  };
  return go(session, '/account/identity-links/unlink/confirm');
}

function confirmUnlink(store: Store, session: Session): Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const confirmation = session.unlinkConfirmation;
  const identity = store.links.find(
    (item) =>
      item.userId === person.id &&
      item.issuer === confirmation?.issuer &&
      item.subject === confirmation.subject,
  );
  if (
    !confirmation ||
    confirmation.sessionId !== session.id ||
    confirmation.expiresAt <= store.clock.now() ||
    !identity ||
    person.status !== 'active' ||
    session.authenticatedAt === null ||
    store.clock.now() - session.authenticatedAt > AUTH_WINDOW_MS ||
    signInMethodCount(store, person) <= 1
  ) {
    session.unlinkConfirmation = null;
    return go(session, '/account/identity-links/unlink/confirm');
  }
  store.links = store.links.filter((item) => item !== identity);
  session.unlinkConfirmation = null;
  recordAudit(
    store,
    person.login,
    'link.unlink',
    `link:${identity.issuer}`,
    null,
    person.id,
    JSON.stringify({ issuer: identity.issuer }),
    '{"tokens":"revoked"}',
  );
  return go(session, '/account/identity-links?banner=unlinked');
}

function visibleAudits(store: Store, person: User) {
  if (isPlatformAdmin(person)) return store.audits;
  const owned = new Set(
    manageableOrganizations(store, person, false).map((organization) => organization.id),
  );
  const users = new Set(visibleUsers(store, person).map((item) => item.id));
  return store.audits.filter(
    (record) =>
      (record.organizationId !== null && owned.has(record.organizationId)) ||
      (record.targetUserId !== null && users.has(record.targetUserId)) ||
      record.actor === person.login,
  );
}

function orgChoices(store: Store, person: User, activeOnly: boolean) {
  return manageableOrganizations(store, person, activeOnly)
    .sort((left, right) => left.slug.localeCompare(right.slug))
    .map((organization) => ({
      id: organization.id,
      slug: organization.slug,
      name: organization.name,
    }));
}

function orgRow(
  store: Store,
  organization: { id: string; slug: string; name: string; status: string },
) {
  return {
    id: organization.id,
    slug: organization.slug,
    name: organization.name,
    status: organization.status,
    activeMemberCount: activeMemberCount(store, organization.id),
    activeClientCount: activeClientCount(store, organization.id),
  };
}

function clientRedirect(redirectUris: string[], requested: string): string {
  const allowed = redirectUris.filter((uri) => {
    try {
      const target = new URL(uri);
      return target.protocol === 'https:' || target.protocol === 'http:';
    } catch {
      return false;
    }
  });
  if (requested && allowed.includes(requested)) return requested;
  return allowed[0] ?? '/account/identity-links';
}

function usableEmailToken(store: Store, token: string | undefined) {
  const email = emailByToken(store, token);
  if (!email || email.expiresAt <= store.clock.now()) return undefined;
  const person = store.users.find((item) => item.id === email.userId);
  if (!eligibleForEmail(person)) return undefined;
  return email;
}

function taken(store: Store, login: string, email: string): boolean {
  const lower = email.toLowerCase();
  return store.users.some(
    (item) => item.login === login || (item.email !== null && item.email.toLowerCase() === lower),
  );
}

function membershipRole(value: string): MembershipRole | null {
  if (value === 'member' || value === 'owner') return value;
  return null;
}

function requireAccount(store: Store, session: Session): User | Outcome {
  const person = currentUser(store, session);
  if (!person) return { type: 'login-required', session, page: unauthenticated(session) };
  if (person.status === 'inactive' || person.status === 'archived') {
    return show(store, session, { page: 'denied', reason: 'inactive' }, 403);
  }
  return person;
}

function requireStaff(store: Store, session: Session): User | Outcome {
  const person = requireAccount(store, session);
  if (isOutcome(person)) return person;
  const access = adminAccess(store, person);
  if (access === 'admin' || access === 'owner') return person;
  return show(store, session, { page: 'denied', reason: 'member' }, 403);
}

function requirePlatform(store: Store, session: Session): User | Outcome {
  const person = requireStaff(store, session);
  if (isOutcome(person)) return person;
  if (!isPlatformAdmin(person))
    return show(store, session, { page: 'denied', reason: 'platform' }, 403);
  return person;
}

function missing(store: Store, session: Session): Outcome {
  const person = currentUser(store, session);
  if (!person) return { type: 'login-required', session, page: unauthenticated(session) };
  if (person.status === 'inactive' || person.status === 'archived') {
    return show(store, session, { page: 'denied', reason: 'inactive' }, 403);
  }
  return show(store, session, { page: 'not-found' }, 404);
}

function unauthenticated(session: Session): PageModel {
  return { page: 'unauthenticated', csrf: session.csrf, signedIn: false, displayName: null };
}

function show(
  store: Store,
  session: Session,
  partial: Record<string, unknown>,
  status = 200,
  emailCookie?: string | null,
): Outcome {
  return {
    type: 'page',
    page: { ...actorFields(store, session), ...partial } as PageModel,
    status,
    session,
    emailCookie,
  };
}

function go(session: Session | null, location: string, emailCookie?: string | null): Outcome {
  return { type: 'redirect', location, session, emailCookie };
}

function isOutcome(value: User | Outcome): value is Outcome {
  return 'type' in value;
}

function csrfOk(session: Session, form: URLSearchParams): boolean {
  return form.get('_csrf') === session.csrf;
}

function text(form: URLSearchParams, name: string): string {
  return (form.get(name) ?? '').trim();
}

function dropSession(store: Store, session: Session): void {
  store.sessions = store.sessions.filter((item) => item.id !== session.id);
}

function fallback(path: string): string {
  if (path.startsWith('/admin/users/')) return '/admin/users';
  if (path.startsWith('/admin/organizations/')) return '/admin/organizations';
  if (path.startsWith('/admin/oauth-clients/')) return '/admin/oauth-clients';
  if (path.startsWith('/admin/memberships')) return '/admin/memberships';
  if (path.startsWith('/account/identity-links')) return '/account/identity-links';
  if (path.startsWith('/account/password')) return '/account/password';
  if (path.startsWith('/passwordless')) return '/passwordless';
  if (path.startsWith('/oauth2/')) return '/oauth2/consent';
  return '/login';
}
