/**
 * JSON page models the server renders for the PatternFly screens. Field names on the forms the
 * screens post follow the auth server's HTML pages (`username`, `orgSlug`, `userLoginOrEmail`,
 * `userId`, `newRole`, `clientName`, `id`).
 */

export type MembershipRole = 'member' | 'owner';

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
  | 'scope-not-allowed'
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

/** An organization a form may target. `id` is the slug, which the forms post as `orgSlug`. */
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
  id: string;
  issuer: string;
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
        clientId: string;
        state: string | null;
        /** Scopes shown as checked boxes; `openid` travels as a hidden field when requested. */
        scopes: string[];
        openid: boolean;
      }
    | { page: 'unauthenticated' }
    | { page: 'denied'; reason: DeniedReason }
    | { page: 'not-found' }
    | { page: 'link-unavailable'; message: string | null }
    | { page: 'error'; title: string; message: string }
    | { page: 'users'; users: UserRow[]; query: string; status: string }
    | { page: 'invite'; organizations: OrgChoice[]; error: FormErrorName | null }
    | {
        page: 'user';
        user: UserDetail;
        banner: BannerName | null;
        /** Auth-server `error=` text for a blocked action. */
        message: string | null;
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
        /** Selected organization slug, or empty for every authorized organization. */
        organizationId: string;
        members: MemberRow[];
        banner: BannerName | null;
        error: FormErrorName | null;
        message: string | null;
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
    | { page: 'link-confirm'; account: AccountSummary; external: ExternalIdentity; token: string }
    | { page: 'unlink-confirm'; provider: string; issuer: string; subjectHint: string }
  );
