import type { Clock } from './clock.ts';
import { hashPassword } from './password.ts';

export const SEED_NOW = Date.parse('2026-01-15T12:00:00.000Z');
export const EMAIL_TTL_MS = 15 * 60 * 1000;
export const EMAIL_INTERVAL_MS = 60 * 1000;
export const AUTH_WINDOW_MS = 15 * 60 * 1000;
export const UNLINK_TTL_MS = 5 * 60 * 1000;
export const LINK_TTL_MS = 15 * 60 * 1000;
export const SLUG_PATTERN = /^[a-z0-9-]+$/;
export const VALID_EMAIL_TOKEN = 'valid-email-token';
export const EXPIRED_EMAIL_TOKEN = 'expired-email-token';

export const SEED_PASSWORDS = {
  ada: 'platform-admin-pass',
  blake: 'second-admin-pass',
  olivia: 'org-owner-pass-1',
  marco: 'org-member-pass1',
  iris: 'inactive-user-pw',
  sam: 'sole-owner-pass1',
  nora: 'north-owner-pass',
  casey: 'north-member-pass',
  archived: 'archived-user-pw',
} as const;

export type UserStatus = 'active' | 'pending' | 'archived' | 'inactive';
export type SystemRole = 'platform_admin' | 'none';
export type OrgStatus = 'active' | 'archived';
export type MembershipRole = 'member' | 'owner';
export type ClientStatus = 'active' | 'revoked';
export type EmailPurpose = 'sign-in' | 'invite' | 'password-reset';

export interface User {
  id: string;
  login: string;
  displayName: string;
  email: string | null;
  emailVerified: boolean;
  status: UserStatus;
  systemRole: SystemRole;
  passwordHash: string | null;
}

export interface Organization {
  id: string;
  slug: string;
  name: string;
  status: OrgStatus;
  createdAt: string;
}

export interface Membership {
  organizationId: string;
  userId: string;
  role: MembershipRole;
}

export interface OAuthClient {
  id: string;
  organizationId: string;
  name: string;
  status: ClientStatus;
  redirectUris: string[];
  grantTypes: string[];
  scopes: string[];
}

export interface AuditRecord {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  target: string;
  correlationId: string;
  organizationId: string | null;
  targetUserId: string | null;
  stateBefore: string;
  stateAfter: string;
}

export interface IdentityLink {
  id: string;
  userId: string;
  provider: string;
  issuer: string;
  subject: string;
  subjectHint: string;
  providerEmail: string;
  linkedAt: string;
}

export interface EmailRecord {
  userId: string;
  purpose: EmailPurpose;
  sentAt: number;
  token: string;
  expiresAt: number;
}

export interface PendingLink {
  provider: string;
  issuer: string;
  subject: string;
  subjectHint: string;
  providerEmail: string;
  token: string;
  expiresAt: number;
  userId: string;
  returnUrl: string;
}

export interface UnlinkConfirmation {
  issuer: string;
  subject: string;
  expiresAt: number;
  sessionId: string;
}

export interface SecretReveal {
  clientId: string;
  secret: string;
}

export interface Session {
  id: string;
  csrf: string;
  userId: string | null;
  authenticatedAt: number | null;
  secretReveal: SecretReveal | null;
  pendingLink: PendingLink | null;
  unlinkConfirmation: UnlinkConfirmation | null;
}

export interface Store {
  clock: Clock;
  users: User[];
  organizations: Organization[];
  memberships: Membership[];
  clients: OAuthClient[];
  audits: AuditRecord[];
  links: IdentityLink[];
  emails: EmailRecord[];
  sessions: Session[];
}

export type BannerName =
  | 'invited'
  | 'archived'
  | 'restored'
  | 'password-reset'
  | 'blocked'
  | 'created'
  | 'saved'
  | 'added'
  | 'role-changed'
  | 'removed'
  | 'registered'
  | 'secret-rotated'
  | 'metadata-updated'
  | 'revoked'
  | 'linked'
  | 'unlinked'
  | 'canceled';

export type FormErrorName =
  | 'conflict'
  | 'slug'
  | 'duplicate-slug'
  | 'required'
  | 'short'
  | 'invalid-org'
  | 'user-not-found'
  | 'archived-user'
  | 'already-member'
  | 'recent-auth'
  | 'last-method'
  | 'inactive-unlink'
  | 'name';

export type DeniedReason = 'inactive' | 'member' | 'platform';

export interface ActorFields {
  csrf: string;
  signedIn: boolean;
  displayName: string | null;
}

export interface OrgChoice {
  id: string;
  slug: string;
  name: string;
}

export interface UserRow {
  id: string;
  login: string;
  displayName: string;
  email: string;
  status: string;
  systemRole: string;
}

export interface UserDetail extends UserRow {
  emailVerified: boolean;
  memberships: Array<{ organizationId: string; slug: string; name: string; role: string }>;
}

export interface OrgRow {
  id: string;
  slug: string;
  name: string;
  status: string;
  activeMemberCount: number;
  activeClientCount: number;
}

export interface OrgDetail extends OrgRow {
  createdAt: string;
  memberCount: number;
}

export interface MemberRow {
  organizationId: string;
  userId: string;
  login: string;
  email: string;
  role: MembershipRole;
}

export interface ClientRow {
  id: string;
  organization: string;
  name: string;
  status: string;
}

export interface ClientDetail {
  id: string;
  organizationId: string;
  organization: string;
  name: string;
  status: string;
  redirectUris: string;
  grantTypes: string;
  scopes: string;
}

export interface AuditRow {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  target: string;
}

export interface AuditDetail extends AuditRow {
  correlationId: string;
  stateBefore: string;
  stateAfter: string;
}

export interface LinkRow {
  issuer: string;
  subject: string;
  subjectHint: string;
  provider: string;
  linkedAt: string;
}

export interface AccountSummary {
  displayName: string;
  login: string;
  email: string;
}

export interface ExternalIdentity {
  provider: string;
  issuer: string;
  subjectHint: string;
  providerEmail: string;
}

export type PageModel = ActorFields &
  (
    | { page: 'login' }
    | { page: 'passwordless'; notice: boolean }
    | { page: 'passwordless-confirm'; unavailable: boolean }
    | { page: 'password'; error: 'short' | null }
    | {
        page: 'consent';
        clientName: string;
        scopes: string[];
        clientId: string;
        redirectUri: string;
      }
    | { page: 'unauthenticated' }
    | { page: 'denied'; reason: DeniedReason }
    | { page: 'not-found' }
    | { page: 'link-unavailable' }
    | { page: 'users'; users: UserRow[]; query: string; status: string }
    | { page: 'invite'; organizations: OrgChoice[]; error: FormErrorName | null }
    | {
        page: 'user';
        user: UserDetail;
        banner: BannerName | null;
        showArchive: boolean;
        showRestore: boolean;
        showPasswordReset: boolean;
      }
    | { page: 'organizations'; organizations: OrgRow[]; status: string; canCreate: boolean }
    | { page: 'create-organization'; error: FormErrorName | null }
    | {
        page: 'organization';
        organization: OrgDetail;
        banner: BannerName | null;
        canEdit: boolean;
        canArchive: boolean;
      }
    | {
        page: 'memberships';
        organizations: OrgChoice[];
        organizationId: string;
        members: MemberRow[];
        banner: BannerName | null;
        error: FormErrorName | null;
      }
    | {
        page: 'clients';
        organizations: OrgChoice[];
        organizationId: string;
        status: string;
        clients: ClientRow[];
      }
    | { page: 'register-client'; organizations: OrgChoice[]; error: FormErrorName | null }
    | {
        page: 'client';
        client: ClientDetail;
        banner: BannerName | null;
        secret: string | null;
        canModify: boolean;
      }
    | {
        page: 'audit';
        count: number;
        records: AuditRow[];
        filters: { action: string; actor: string; target: string; from: string; to: string };
      }
    | { page: 'audit-record'; record: AuditDetail }
    | {
        page: 'links';
        accountName: string;
        links: LinkRow[];
        banner: BannerName | null;
        error: FormErrorName | null;
      }
    | { page: 'link-confirm'; account: AccountSummary; external: ExternalIdentity }
    | { page: 'unlink-confirm'; provider: string; issuer: string; subjectHint: string }
  );

export interface Outcome {
  type: 'page' | 'redirect' | 'login-required';
  page?: PageModel;
  location?: string;
  status?: number;
  session: Session | null;
  emailCookie?: string | null;
}

function user(
  id: string,
  login: string,
  displayName: string,
  email: string | null,
  emailVerified: boolean,
  status: UserStatus,
  systemRole: SystemRole,
  password: string | null,
): User {
  return {
    id,
    login,
    displayName,
    email,
    emailVerified,
    status,
    systemRole,
    passwordHash: password ? hashPassword(password) : null,
  };
}

export function createStore(clock: Clock): Store {
  const now = clock.now();
  return {
    clock,
    users: [
      user(
        'u_ada',
        'ada',
        'Ada Admin',
        'ada@identity.example',
        true,
        'active',
        'platform_admin',
        SEED_PASSWORDS.ada,
      ),
      user(
        'u_blake',
        'blake',
        'Blake Admin',
        'blake@identity.example',
        true,
        'active',
        'platform_admin',
        SEED_PASSWORDS.blake,
      ),
      user(
        'u_olivia',
        'olivia',
        'Olivia Owner',
        'olivia@acme.example',
        true,
        'active',
        'none',
        SEED_PASSWORDS.olivia,
      ),
      user(
        'u_marco',
        'marco',
        'Marco Member',
        'marco@acme.example',
        true,
        'active',
        'none',
        SEED_PASSWORDS.marco,
      ),
      user(
        'u_iris',
        'iris',
        'Iris Inactive',
        'iris@identity.example',
        true,
        'inactive',
        'none',
        SEED_PASSWORDS.iris,
      ),
      user(
        'u_pending',
        'pending',
        'Pending User',
        'pending@identity.example',
        false,
        'pending',
        'none',
        null,
      ),
      user(
        'u_archived',
        'archived',
        'Archived User',
        'archived@identity.example',
        true,
        'archived',
        'none',
        SEED_PASSWORDS.archived,
      ),
      user(
        'u_sam',
        'sam',
        'Sam Sole',
        'sam@solo.example',
        true,
        'active',
        'none',
        SEED_PASSWORDS.sam,
      ),
      user(
        'u_nora',
        'nora',
        'Nora North',
        'nora@north.example',
        true,
        'active',
        'none',
        SEED_PASSWORDS.nora,
      ),
      user(
        'u_casey',
        'casey',
        'Casey North',
        'casey@north.example',
        true,
        'active',
        'none',
        SEED_PASSWORDS.casey,
      ),
      user(
        'u_linkonly',
        'linkonly',
        'Link Only',
        'linkonly@identity.example',
        false,
        'active',
        'none',
        null,
      ),
    ],
    organizations: [
      {
        id: 'o_acme',
        slug: 'acme',
        name: 'Acme',
        status: 'active',
        createdAt: '2026-01-01T00:00:00.000Z',
      },
      {
        id: 'o_solo',
        slug: 'solo',
        name: 'Solo',
        status: 'active',
        createdAt: '2026-01-02T00:00:00.000Z',
      },
      {
        id: 'o_north',
        slug: 'north',
        name: 'North',
        status: 'active',
        createdAt: '2026-01-03T00:00:00.000Z',
      },
      {
        id: 'o_old',
        slug: 'oldco',
        name: 'Old Co',
        status: 'archived',
        createdAt: '2025-12-01T00:00:00.000Z',
      },
    ],
    memberships: [
      { organizationId: 'o_acme', userId: 'u_olivia', role: 'owner' },
      { organizationId: 'o_acme', userId: 'u_marco', role: 'member' },
      { organizationId: 'o_acme', userId: 'u_pending', role: 'member' },
      { organizationId: 'o_acme', userId: 'u_archived', role: 'member' },
      { organizationId: 'o_acme', userId: 'u_iris', role: 'member' },
      { organizationId: 'o_solo', userId: 'u_sam', role: 'owner' },
      { organizationId: 'o_north', userId: 'u_nora', role: 'owner' },
      { organizationId: 'o_north', userId: 'u_casey', role: 'member' },
      { organizationId: 'o_old', userId: 'u_marco', role: 'member' },
    ],
    clients: [
      {
        id: 'cli_aaaaaaaaaaaaaaaa',
        organizationId: 'o_acme',
        name: 'Acme web',
        status: 'active',
        redirectUris: ['https://acme.example/callback'],
        grantTypes: ['authorization_code', 'refresh_token'],
        scopes: ['openid', 'profile', 'email'],
      },
      {
        id: 'cli_bbbbbbbbbbbbbbbb',
        organizationId: 'o_acme',
        name: 'Acme old',
        status: 'revoked',
        redirectUris: ['https://acme.example/old'],
        grantTypes: ['authorization_code'],
        scopes: ['openid'],
      },
    ],
    audits: [
      {
        id: 'aud_acme',
        timestamp: '2026-01-10T00:00:00.000Z',
        action: 'organization.create',
        actor: 'ada',
        target: 'organization:acme',
        correlationId: 'cor_acme',
        organizationId: 'o_acme',
        targetUserId: null,
        stateBefore: '{}',
        stateAfter: '{"slug":"acme"}',
      },
      {
        id: 'aud_solo',
        timestamp: '2026-01-11T00:00:00.000Z',
        action: 'organization.create',
        actor: 'ada',
        target: 'organization:solo',
        correlationId: 'cor_solo',
        organizationId: 'o_solo',
        targetUserId: null,
        stateBefore: '{}',
        stateAfter: '{"slug":"solo"}',
      },
      {
        id: 'aud_invite',
        timestamp: '2026-01-12T00:00:00.000Z',
        action: 'user.invite',
        actor: 'olivia',
        target: 'user:u_pending',
        correlationId: 'cor_invite',
        organizationId: 'o_acme',
        targetUserId: 'u_pending',
        stateBefore: '{}',
        stateAfter: '{"login":"pending"}',
      },
    ],
    links: [
      link(
        'link_only',
        'u_linkonly',
        'github',
        'https://github.example/login',
        'subject-linkonly',
        'linkonly@github.example',
        '2026-01-01T00:00:00.000Z',
      ),
      link(
        'link_nora_1',
        'u_nora',
        'google',
        'https://accounts.google.example',
        'subject-nora-1',
        'nora@google.example',
        '2026-01-02T00:00:00.000Z',
      ),
      link(
        'link_nora_2',
        'u_nora',
        'github',
        'https://github.example/login',
        'subject-nora-2',
        'nora@github.example',
        '2026-01-03T00:00:00.000Z',
      ),
      link(
        'link_ada',
        'u_ada',
        'google',
        'https://accounts.google.example',
        'subject-ada',
        'ada@google.example',
        '2026-01-04T00:00:00.000Z',
      ),
    ],
    emails: [
      {
        userId: 'u_pending',
        purpose: 'sign-in',
        sentAt: now - EMAIL_INTERVAL_MS - 1,
        token: VALID_EMAIL_TOKEN,
        expiresAt: now + EMAIL_TTL_MS,
      },
      {
        userId: 'u_ada',
        purpose: 'sign-in',
        sentAt: now - 3_600_000,
        token: EXPIRED_EMAIL_TOKEN,
        expiresAt: now - 60_000,
      },
    ],
    sessions: [],
  };
}

function link(
  id: string,
  userId: string,
  provider: string,
  issuer: string,
  subject: string,
  providerEmail: string,
  linkedAt: string,
): IdentityLink {
  return {
    id,
    userId,
    provider,
    issuer,
    subject,
    subjectHint: `••••${subject.slice(-4)}`,
    providerEmail,
    linkedAt,
  };
}

export function createSession(
  store: Store,
  userId: string | null,
  authenticatedAt: number | null,
): Session {
  const session: Session = {
    id: `ses_${store.clock.hex(16)}`,
    csrf: `csrf_${store.clock.hex(16)}`,
    userId,
    authenticatedAt,
    secretReveal: null,
    pendingLink: null,
    unlinkConfirmation: null,
  };
  store.sessions.push(session);
  return session;
}

export function findSession(store: Store, id: string | undefined): Session | undefined {
  if (!id) return undefined;
  return store.sessions.find((session) => session.id === id);
}

export function currentUser(store: Store, session: Session): User | undefined {
  if (!session.userId) return undefined;
  return store.users.find((item) => item.id === session.userId);
}

export function isPlatformAdmin(person: User | undefined): boolean {
  return person?.status === 'active' && person.systemRole === 'platform_admin';
}

export function ownedOrganizationIds(store: Store, person: User): string[] {
  return store.memberships
    .filter((membership) => membership.userId === person.id && membership.role === 'owner')
    .map((membership) => membership.organizationId);
}

export function canManageOrganization(
  store: Store,
  person: User | undefined,
  organizationId: string,
): boolean {
  if (!person || person.status === 'inactive' || person.status === 'archived') return false;
  if (isPlatformAdmin(person)) return true;
  return ownedOrganizationIds(store, person).includes(organizationId);
}

export function manageableOrganizations(
  store: Store,
  person: User | undefined,
  activeOnly: boolean,
): Organization[] {
  if (!person || person.status === 'inactive' || person.status === 'archived') return [];
  return store.organizations.filter((organization) => {
    if (activeOnly && organization.status !== 'active') return false;
    if (isPlatformAdmin(person)) return true;
    return ownedOrganizationIds(store, person).includes(organization.id);
  });
}

export function visibleUsers(store: Store, person: User): User[] {
  if (isPlatformAdmin(person)) return store.users;
  const owned = new Set(ownedOrganizationIds(store, person));
  const ids = new Set<string>([person.id]);
  for (const membership of store.memberships) {
    if (owned.has(membership.organizationId)) ids.add(membership.userId);
  }
  return store.users.filter((item) => ids.has(item.id));
}

export function isOwner(store: Store, person: User | undefined): boolean {
  if (!person || person.status === 'inactive' || person.status === 'archived') return false;
  return ownedOrganizationIds(store, person).length > 0;
}

export function adminAccess(
  store: Store,
  person: User | undefined,
): 'admin' | 'owner' | 'member' | 'inactive' | 'none' {
  if (!person) return 'none';
  if (person.status === 'inactive') return 'inactive';
  if (person.status === 'archived') return 'inactive';
  if (isPlatformAdmin(person)) return 'admin';
  if (isOwner(store, person)) return 'owner';
  return 'member';
}

export function findUserByIdentifier(store: Store, identifier: string): User | undefined {
  const needle = identifier.trim();
  const lower = needle.toLowerCase();
  return store.users.find(
    (item) => item.login === needle || (item.email !== null && item.email.toLowerCase() === lower),
  );
}

export function organizationById(store: Store, id: string): Organization | undefined {
  return store.organizations.find((organization) => organization.id === id);
}

export function activeMemberCount(store: Store, organizationId: string): number {
  return store.memberships.filter((membership) => {
    if (membership.organizationId !== organizationId) return false;
    const person = store.users.find((item) => item.id === membership.userId);
    return person?.status === 'active';
  }).length;
}

export function activeClientCount(store: Store, organizationId: string): number {
  return store.clients.filter(
    (client) => client.organizationId === organizationId && client.status === 'active',
  ).length;
}

export function ownersOf(store: Store, organizationId: string): Membership[] {
  return store.memberships.filter(
    (membership) => membership.organizationId === organizationId && membership.role === 'owner',
  );
}

export function isSoleOwner(store: Store, person: User): boolean {
  return store.organizations.some((organization) => {
    if (organization.status !== 'active') return false;
    const owners = ownersOf(store, organization.id);
    return owners.length === 1 && owners[0]?.userId === person.id;
  });
}

export function isLastActivePlatformAdmin(store: Store, person: User): boolean {
  if (person.systemRole !== 'platform_admin' || person.status !== 'active') return false;
  const active = store.users.filter(
    (item) => item.systemRole === 'platform_admin' && item.status === 'active',
  );
  return active.length <= 1;
}

export function archiveBlocked(store: Store, person: User): boolean {
  return isLastActivePlatformAdmin(store, person) || isSoleOwner(store, person);
}

export function signInMethodCount(store: Store, person: User): number {
  const links = store.links.filter((item) => item.userId === person.id).length;
  const password = person.passwordHash ? 1 : 0;
  const email = person.email && person.emailVerified ? 1 : 0;
  return password + email + links;
}

export function recordAudit(
  store: Store,
  actor: string,
  action: string,
  target: string,
  organizationId: string | null,
  targetUserId: string | null,
  stateBefore: string,
  stateAfter: string,
): void {
  store.audits.push({
    id: `aud_${store.clock.hex(8)}`,
    timestamp: new Date(store.clock.now()).toISOString(),
    action,
    actor,
    target,
    correlationId: `cor_${store.clock.hex(8)}`,
    organizationId,
    targetUserId,
    stateBefore,
    stateAfter,
  });
}

export function sendEmail(store: Store, person: User, purpose: EmailPurpose): string | null {
  const latest = store.emails
    .filter((email) => email.userId === person.id && email.purpose === purpose)
    .sort((left, right) => right.sentAt - left.sentAt)[0];
  if (latest && store.clock.now() - latest.sentAt < EMAIL_INTERVAL_MS) return null;
  const token = `em_${store.clock.hex(16)}`;
  store.emails.push({
    userId: person.id,
    purpose,
    sentAt: store.clock.now(),
    token,
    expiresAt: store.clock.now() + EMAIL_TTL_MS,
  });
  return token;
}

export function emailByToken(store: Store, token: string | undefined): EmailRecord | undefined {
  if (!token) return undefined;
  return store.emails.find((email) => email.token === token);
}

export function eligibleForEmail(person: User | undefined): person is User {
  return person?.status === 'pending' || person?.status === 'active';
}

export function actorFields(store: Store, session: Session): ActorFields {
  const person = currentUser(store, session);
  return {
    csrf: session.csrf,
    signedIn: Boolean(person),
    displayName: person?.displayName ?? null,
  };
}

export function bannerFrom(url: URL, allowed: readonly BannerName[]): BannerName | null {
  const value = url.searchParams.get('banner');
  if (!value) return null;
  return allowed.find((banner) => banner === value) ?? null;
}

export function errorFrom(url: URL, allowed: readonly FormErrorName[]): FormErrorName | null {
  const value = url.searchParams.get('error');
  if (!value) return null;
  return allowed.find((error) => error === value) ?? null;
}

export function splitList(value: string, fallback: string[]): string[] {
  const items = value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return items.length > 0 ? items : fallback;
}

export function safeProviderUrl(
  issuer: string,
  provider: string,
  state: string,
  returnUrl: string,
): string | null {
  let url: URL;
  try {
    url = new URL(issuer);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  url.searchParams.set('provider', provider);
  url.searchParams.set('state', state);
  url.searchParams.set('returnUrl', returnUrl);
  return url.toString();
}
