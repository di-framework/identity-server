import type {
  DirectoryMember,
  Membership,
  MembershipDetail,
  Organization,
  UserAccount,
} from './models.ts';

export interface NewUser {
  id: string;
  login: string;
  email: string;
  displayName: string;
}

export interface NewOrganization {
  id: string;
  slug: string;
  name: string;
}

/** A fully specified account, as bootstrap and the HTML admin create them. */
export interface NewAccount {
  id: string;
  login: string;
  email: string | null;
  displayName: string;
  passwordHash: string | null;
  emailVerified: boolean;
  systemRole: string;
  status: string;
}

export interface AccountChanges {
  passwordHash?: string;
  systemRole?: string;
  status?: string;
  emailVerified?: boolean;
}

/** Directory port. Application services depend on this, not on Postgres. */
export interface DirectoryRepository {
  transaction<T>(fn: () => Promise<T>): Promise<T>;
  listUsers(): Promise<UserAccount[]>;
  findUser(id: string): Promise<UserAccount | undefined>;
  insertUser(user: NewUser): Promise<void>;
  /** First user whose normalized email or normalized login matches, in any status. */
  findUserByEmailOrLogin(email: string, login: string): Promise<UserAccount | undefined>;
  /** Active user whose normalized login or normalized email equals `identifier` (form login). */
  findActiveByLoginOrEmail(identifier: string): Promise<UserAccount | undefined>;
  /** User with this normalized email, in any status (passwordless request). */
  findUserByEmail(email: string): Promise<UserAccount | undefined>;
  insertAccount(account: NewAccount): Promise<void>;
  updateAccount(id: string, changes: AccountChanges): Promise<void>;
  updateDisplayName(id: string, displayName: string): Promise<void>;
  archiveUser(id: string): Promise<void>;
  countMembershipsForUser(id: string): Promise<number>;
  listOrganizations(): Promise<Organization[]>;
  findOrganization(slug: string): Promise<Organization | undefined>;
  insertOrganization(organization: NewOrganization): Promise<void>;
  updateOrganizationName(slug: string, name: string): Promise<void>;
  deleteOrganization(slug: string): Promise<void>;
  countMembershipsForSlug(slug: string): Promise<number>;
  findMembership(slug: string, userId: string): Promise<Membership | undefined>;
  upsertMembership(organizationId: string, userId: string, role: string): Promise<void>;
  deleteMembership(slug: string, userId: string): Promise<boolean>;
  listMembers(slug: string, afterId: string | undefined, limit: number): Promise<DirectoryMember[]>;
  findOrganizationById(id: string): Promise<Organization | undefined>;
  archiveOrganization(slug: string, at: number): Promise<void>;
  /** Every membership of a user, ordered by organization slug (`findAllForUser`). */
  membershipsForUser(userId: string): Promise<MembershipDetail[]>;
  /** Every membership of an organization, ordered by user login (`findAllForOrganization`). */
  membershipsForOrganization(slug: string): Promise<MembershipDetail[]>;
  /** Every membership, ordered by slug then login (`findAllWithDetails`). */
  allMemberships(): Promise<MembershipDetail[]>;
  /** Owners of an organization, in any user status (`countByOrganizationSlugAndRole`). */
  countOwners(slug: string): Promise<number>;
  countActivePlatformAdmins(): Promise<number>;
}
