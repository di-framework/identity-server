import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import type {
  AccountChanges,
  DirectoryRepository,
  NewAccount,
  NewOrganization,
  NewUser,
} from '../domain/directory-repository.ts';
import {
  DirectoryMember,
  Membership,
  type MembershipDetail,
  Organization,
  UserAccount,
} from '../domain/models.ts';

interface UserRow {
  id: string;
  login: string;
  email: string | null;
  display_name: string;
  email_verified: boolean;
  status: string;
  password_hash: string | null;
  system_role: string;
  avatar_url: string | null;
}

interface OrganizationRow {
  id: string;
  slug: string;
  name: string;
  created_at: unknown;
  archived_at: unknown;
}

interface MembershipRow {
  organization_id: string;
  slug: string;
  name: string;
  archived_at: unknown;
  user_id: string;
  login: string;
  display_name: string;
  email: string | null;
  role: string;
}

const MEMBERSHIP_SELECT = `SELECT o.id::text AS organization_id, o.slug, o.name, o.archived_at,
         u.id::text AS user_id, u.login, u.display_name, u.email, m.role
  FROM organization_memberships m
  JOIN organizations o ON o.id = m.organization_id
  JOIN users u ON u.id = m.user_id`;

interface MemberRow {
  id: string;
  login: string;
  display_name: string;
  avatar_url: string | null;
  email: string | null;
  email_verified: boolean;
  role: string;
}

const USER_COLUMNS = `id::text AS id, login, email, display_name, email_verified, status,
  password_hash, system_role, avatar_url`;

@Container()
export class PostgresDirectoryRepository implements DirectoryRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  transaction<T>(fn: () => Promise<T>): Promise<T> {
    return this.db.transaction(fn);
  }

  async listUsers(): Promise<UserAccount[]> {
    const rows = await this.db.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users ORDER BY id`);
    return rows.map((row) => this.user(row));
  }

  async findUser(id: string): Promise<UserAccount | undefined> {
    const row = await this.db.one<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`, [id]);
    return row ? this.user(row) : undefined;
  }

  insertUser(user: NewUser): Promise<void> {
    return this.db.write(
      `INSERT INTO users (id, login, normalized_login, email, normalized_email, display_name, email_verified, status)
       VALUES (?, ?, ?, ?, ?, ?, false, 'pending')`,
      [
        user.id,
        user.login,
        user.login.toLowerCase(),
        user.email,
        user.email.toLowerCase(),
        user.displayName,
      ],
    );
  }

  async lockUser(id: string): Promise<UserAccount | undefined> {
    const row = await this.db.one<UserRow>(
      `SELECT ${USER_COLUMNS} FROM users WHERE id = ? FOR UPDATE`,
      [id],
    );
    return row ? this.user(row) : undefined;
  }

  async findUserByEmailOrLogin(email: string, login: string): Promise<UserAccount | undefined> {
    const row = await this.db.one<UserRow>(
      `SELECT ${USER_COLUMNS} FROM users
       WHERE normalized_email = ? OR normalized_login = ?
       ORDER BY created_at, id LIMIT 1`,
      [email.trim().toLowerCase(), login.trim().toLowerCase()],
    );
    return row ? this.user(row) : undefined;
  }

  async findActiveByLoginOrEmail(identifier: string): Promise<UserAccount | undefined> {
    const normalized = identifier.trim().toLowerCase();
    const row = await this.db.one<UserRow>(
      `SELECT ${USER_COLUMNS} FROM users
       WHERE (normalized_login = ? OR normalized_email = ?) AND status = 'active'
       ORDER BY created_at, id LIMIT 1`,
      [normalized, normalized],
    );
    return row ? this.user(row) : undefined;
  }

  async findUserByEmail(email: string): Promise<UserAccount | undefined> {
    const row = await this.db.one<UserRow>(
      `SELECT ${USER_COLUMNS} FROM users WHERE normalized_email = ?`,
      [email.trim().toLowerCase()],
    );
    return row ? this.user(row) : undefined;
  }

  insertAccount(account: NewAccount): Promise<void> {
    return this.db.write(
      `INSERT INTO users (id, login, normalized_login, email, normalized_email, password_hash,
         display_name, email_verified, system_role, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        account.id,
        account.login,
        account.login.toLowerCase(),
        account.email,
        account.email?.toLowerCase() ?? null,
        account.passwordHash,
        account.displayName,
        account.emailVerified,
        account.systemRole,
        account.status,
      ],
    );
  }

  async updateAccount(id: string, changes: AccountChanges): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];
    for (const [column, value] of [
      ['password_hash', changes.passwordHash],
      ['system_role', changes.systemRole],
      ['status', changes.status],
      ['email_verified', changes.emailVerified],
    ] as const) {
      if (value === undefined) continue;
      sets.push(`${column} = ?`);
      params.push(value);
    }
    if (sets.length === 0) return;
    await this.db.write(`UPDATE users SET ${sets.join(', ')}, updated_at = now() WHERE id = ?`, [
      ...params,
      id,
    ]);
  }

  updateDisplayName(id: string, displayName: string): Promise<void> {
    return this.db.write(`UPDATE users SET display_name = ?, updated_at = now() WHERE id = ?`, [
      displayName,
      id,
    ]);
  }

  archiveUser(id: string): Promise<void> {
    return this.db.write(`UPDATE users SET status = 'archived', updated_at = now() WHERE id = ?`, [
      id,
    ]);
  }

  countMembershipsForUser(id: string): Promise<number> {
    return this.db.count(
      `SELECT count(*)::int AS count FROM organization_memberships WHERE user_id = ?`,
      [id],
    );
  }

  async listOrganizations(): Promise<Organization[]> {
    const rows = await this.db.query<OrganizationRow>(
      `SELECT id::text AS id, slug, name, created_at, archived_at FROM organizations ORDER BY slug`,
    );
    return rows.map((row) => this.organization(row));
  }

  async findOrganization(slug: string): Promise<Organization | undefined> {
    const row = await this.db.one<OrganizationRow>(
      `SELECT id::text AS id, slug, name, created_at, archived_at FROM organizations WHERE slug = ?`,
      [slug],
    );
    return row ? this.organization(row) : undefined;
  }

  insertOrganization(organization: NewOrganization): Promise<void> {
    return this.db.write(`INSERT INTO organizations (id, slug, name) VALUES (?, ?, ?)`, [
      organization.id,
      organization.slug,
      organization.name,
    ]);
  }

  updateOrganizationName(slug: string, name: string): Promise<void> {
    return this.db.write(`UPDATE organizations SET name = ? WHERE slug = ?`, [name, slug]);
  }

  deleteOrganization(slug: string): Promise<void> {
    return this.db.write(`DELETE FROM organizations WHERE slug = ?`, [slug]);
  }

  countMembershipsForSlug(slug: string): Promise<number> {
    return this.db.count(
      `SELECT count(*)::int AS count FROM organization_memberships m
       JOIN organizations o ON o.id = m.organization_id WHERE o.slug = ?`,
      [slug],
    );
  }

  async findMembership(slug: string, userId: string): Promise<Membership | undefined> {
    const row = await this.db.one<{ role: string }>(
      `SELECT m.role FROM organization_memberships m
       JOIN organizations o ON o.id = m.organization_id
       WHERE o.slug = ? AND m.user_id = ?`,
      [slug, userId],
    );
    return row ? new Membership(slug, userId, row.role) : undefined;
  }

  upsertMembership(organizationId: string, userId: string, role: string): Promise<void> {
    return this.db.write(
      `INSERT INTO organization_memberships (organization_id, user_id, role)
       VALUES (?, ?, ?)
       ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
      [organizationId, userId, role],
    );
  }

  async deleteMembership(slug: string, userId: string): Promise<boolean> {
    const result = await this.db.run(
      `DELETE FROM organization_memberships AS m
       USING organizations AS o
       WHERE m.organization_id = o.id AND o.slug = ? AND m.user_id = ?
       RETURNING 1`,
      [slug, userId],
    );
    return (result.changes ?? 0) > 0;
  }

  async listMembers(
    slug: string,
    afterId: string | undefined,
    limit: number,
  ): Promise<DirectoryMember[]> {
    const params: unknown[] = [slug];
    let cursor = '';
    if (afterId) {
      cursor = ' AND u.id > ?';
      params.push(afterId);
    }
    params.push(limit);
    const rows = await this.db.query<MemberRow>(
      `SELECT u.id::text AS id, u.login, u.display_name, u.avatar_url, u.email, u.email_verified, m.role
       FROM organization_memberships m
       JOIN organizations o ON o.id = m.organization_id
       JOIN users u ON u.id = m.user_id
       WHERE o.slug = ?${cursor}
       ORDER BY u.id
       LIMIT ?`,
      params,
    );
    return rows.map((row) => this.member(row));
  }

  async lockOrganization(slug: string): Promise<void> {
    await this.db.query(`SELECT id::text AS id FROM organizations WHERE slug = ? FOR UPDATE`, [
      slug,
    ]);
  }

  async lockPlatformAdmins(): Promise<void> {
    await this.db.query(
      `SELECT pg_advisory_xact_lock(hashtextextended('platform_admins', 0))::text AS locked`,
    );
  }

  async findOrganizationById(id: string): Promise<Organization | undefined> {
    const row = await this.db.one<OrganizationRow>(
      `SELECT id::text AS id, slug, name, created_at, archived_at FROM organizations WHERE id = ?`,
      [id],
    );
    return row ? this.organization(row) : undefined;
  }

  archiveOrganization(slug: string, at: number): Promise<void> {
    return this.db.write(`UPDATE organizations SET archived_at = ? WHERE slug = ?`, [
      new Date(at),
      slug,
    ]);
  }

  async membershipsForUser(userId: string): Promise<MembershipDetail[]> {
    const rows = await this.db.query<MembershipRow>(
      `${MEMBERSHIP_SELECT} WHERE m.user_id = ? ORDER BY o.slug`,
      [userId],
    );
    return rows.map((row) => this.membership(row));
  }

  async membershipsForOrganization(slug: string): Promise<MembershipDetail[]> {
    const rows = await this.db.query<MembershipRow>(
      `${MEMBERSHIP_SELECT} WHERE o.slug = ? ORDER BY u.login`,
      [slug],
    );
    return rows.map((row) => this.membership(row));
  }

  async allMemberships(): Promise<MembershipDetail[]> {
    const rows = await this.db.query<MembershipRow>(
      `${MEMBERSHIP_SELECT} ORDER BY o.slug, u.login`,
    );
    return rows.map((row) => this.membership(row));
  }

  countOwners(slug: string): Promise<number> {
    return this.db.count(
      `SELECT count(*)::int AS count FROM organization_memberships m
       JOIN organizations o ON o.id = m.organization_id WHERE o.slug = ? AND m.role = 'owner'`,
      [slug],
    );
  }

  countActivePlatformAdmins(): Promise<number> {
    return this.db.count(
      `SELECT count(*)::int AS count FROM users WHERE system_role = 'platform_admin' AND status = 'active'`,
    );
  }

  private membership(row: MembershipRow): MembershipDetail {
    return {
      organizationId: row.organization_id,
      organizationSlug: row.slug,
      organizationName: row.name,
      organizationArchivedAt: Timestamps.isoOrNull(row.archived_at),
      userId: row.user_id,
      userLogin: row.login,
      userDisplayName: row.display_name,
      userEmail: row.email,
      role: row.role,
    };
  }

  private user(row: UserRow): UserAccount {
    return new UserAccount(
      String(row.id),
      String(row.login),
      row.email == null ? null : String(row.email),
      String(row.display_name),
      row.email_verified === true,
      String(row.status),
      row.password_hash == null ? null : String(row.password_hash),
      String(row.system_role),
      row.avatar_url == null ? null : String(row.avatar_url),
    );
  }

  private organization(row: OrganizationRow): Organization {
    return new Organization(
      String(row.id),
      String(row.slug),
      String(row.name),
      Timestamps.iso(row.created_at),
      Timestamps.isoOrNull(row.archived_at),
    );
  }

  private member(row: MemberRow): DirectoryMember {
    return new DirectoryMember(
      String(row.id),
      String(row.login),
      String(row.display_name),
      row.avatar_url == null ? null : String(row.avatar_url),
      row.email == null ? null : String(row.email),
      row.email_verified === true,
      String(row.role),
    );
  }
}
