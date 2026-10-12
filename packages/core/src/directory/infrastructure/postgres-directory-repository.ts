import { Component, Container } from '@di-framework/core/decorators';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import {
  type ColumnCipher,
  ColumnEncryption,
} from '../../shared/infrastructure/column-encryption.ts';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import { Sql, sql } from '../../shared/infrastructure/sql.ts';
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

function membershipSelect(cipher: ColumnCipher): Sql {
  return sql`SELECT o.id::text AS organization_id, o.slug, o.name, o.archived_at,
         u.id::text AS user_id, u.login, ${cipher.read('u.display_name', 'display_name', { enc: 'u.display_name_enc' })},
         ${cipher.read('u.email', 'email', { enc: 'u.email_enc' })}, m.role
  FROM organization_memberships m
  JOIN organizations o ON o.id = m.organization_id
  JOIN users u ON u.id = m.user_id`;
}

interface MemberRow {
  id: string;
  login: string;
  display_name: string;
  avatar_url: string | null;
  email: string | null;
  email_verified: boolean;
  role: string;
}

/** `email`, `display_name` and `avatar_url` are encrypted once column encryption is enabled. */
function userColumns(cipher: ColumnCipher): Sql {
  return sql`id::text AS id, login, ${cipher.read('email', 'email')},
  ${cipher.read('display_name', 'display_name')}, email_verified, status, password_hash,
  system_role, ${cipher.read('avatar_url', 'avatar_url')}`;
}

/**
 * Locks every owner row of membership `m`'s organization in `user_id` order, then counts them.
 * Including the target row and a fixed lock order prevents cross-lock deadlocks when two
 * statements demote or remove different owners at the same time.
 */
const OWNER_COUNT = `(SELECT count(*) FROM (
    SELECT 1 FROM organization_memberships AS x
    WHERE x.organization_id = m.organization_id AND x.role = 'owner'
    ORDER BY x.user_id FOR UPDATE
  ) AS owners)`;

const ACTIVE_PLATFORM_ADMIN_COUNT = `(SELECT count(*) FROM (
    SELECT 1 FROM users AS x
    WHERE x.system_role = 'platform_admin' AND x.status = 'active'
    ORDER BY x.id FOR UPDATE
  ) AS active_admins)`;

/**
 * Once column encryption is enabled, `normalized_email` is written only as its blind index and
 * email lookups match the blind index or a legacy plaintext `normalized_email`.
 */
@Container()
export class PostgresDirectoryRepository implements DirectoryRepository {
  constructor(
    @Component(PostgresGateway) private readonly db: PostgresGateway,
    @Component(ColumnEncryption) private readonly encryption: ColumnEncryption,
  ) {}

  transaction<T>(fn: () => Promise<T>): Promise<T> {
    return this.db.transaction(fn);
  }

  async listUsers(): Promise<UserAccount[]> {
    const cipher = await this.encryption.cipher();
    const rows = await this.db.query<UserRow>(
      sql`SELECT ${userColumns(cipher)} FROM users ORDER BY id`,
    );
    return rows.map((row) => this.user(row));
  }

  async findUser(id: string): Promise<UserAccount | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<UserRow>(
      sql`SELECT ${userColumns(cipher)} FROM users WHERE id = ${id}`,
    );
    return row ? this.user(row) : undefined;
  }

  insertUser(user: NewUser): Promise<void> {
    return this.insertPerson({
      id: user.id,
      login: user.login,
      email: user.email,
      displayName: user.displayName,
      passwordHash: null,
      emailVerified: false,
      systemRole: 'user',
      status: 'pending',
    });
  }

  async lockUser(id: string): Promise<UserAccount | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<UserRow>(
      sql`SELECT ${userColumns(cipher)} FROM users WHERE id = ${id} FOR UPDATE`,
    );
    return row ? this.user(row) : undefined;
  }

  async findUserByEmailOrLogin(email: string, login: string): Promise<UserAccount | undefined> {
    const cipher = await this.encryption.cipher();
    const normalizedEmail = email.trim().toLowerCase();
    const row = await this.db.one<UserRow>(
      sql`SELECT ${userColumns(cipher)} FROM users
       WHERE ${cipher.matches('normalized_email', 'normalized_email_bidx', normalizedEmail)}
         OR normalized_login = ${login.trim().toLowerCase()}
       ORDER BY created_at, id LIMIT 1`,
    );
    return row ? this.user(row) : undefined;
  }

  async findActiveByLoginOrEmail(identifier: string): Promise<UserAccount | undefined> {
    const cipher = await this.encryption.cipher();
    const normalized = identifier.trim().toLowerCase();
    const row = await this.db.one<UserRow>(
      sql`SELECT ${userColumns(cipher)} FROM users
       WHERE (normalized_login = ${normalized}
         OR ${cipher.matches('normalized_email', 'normalized_email_bidx', normalized)})
         AND status = 'active'
       ORDER BY created_at, id LIMIT 1`,
    );
    return row ? this.user(row) : undefined;
  }

  async findUserByEmail(email: string): Promise<UserAccount | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<UserRow>(
      sql`SELECT ${userColumns(cipher)} FROM users
       WHERE ${cipher.matches('normalized_email', 'normalized_email_bidx', email.trim().toLowerCase())}`,
    );
    return row ? this.user(row) : undefined;
  }

  insertAccount(account: NewAccount): Promise<void> {
    return this.insertPerson(account);
  }

  /**
   * Inserts a user. The email is unique by its normalized form: legacy rows through
   * `normalized_email`, new rows through `normalized_email_bidx`, and a new row is refused (409)
   * while a legacy row holds the same plaintext address.
   */
  private async insertPerson(person: NewAccount): Promise<void> {
    const cipher = await this.encryption.cipher();
    const normalizedEmail = person.email?.toLowerCase() ?? null;
    const inserted = await this.db.writeCount(
      sql`INSERT INTO users (id, login, normalized_login, email, email_enc, normalized_email,
         normalized_email_bidx, password_hash, display_name, display_name_enc, email_verified,
         system_role, status)
       SELECT ${person.id}::uuid, ${person.login}::varchar, ${person.login.toLowerCase()}::varchar,
         ${cipher.plain(person.email)}::varchar, ${cipher.encrypt(person.email)}::bytea,
         ${cipher.plain(normalizedEmail)}::varchar, ${cipher.blindIndex(normalizedEmail)}::bytea,
         ${person.passwordHash}::varchar, ${cipher.plain(person.displayName)}::varchar,
         ${cipher.encrypt(person.displayName)}::bytea, ${person.emailVerified}::boolean,
         ${person.systemRole}::varchar, ${person.status}::varchar
       WHERE NOT EXISTS (SELECT 1 FROM users WHERE normalized_email = ${normalizedEmail})`,
    );
    if (inserted === 0) throw new IdentityError(409, 'Conflict');
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

  async updateDisplayName(id: string, displayName: string): Promise<void> {
    const cipher = await this.encryption.cipher();
    return this.db.write(
      sql`UPDATE users SET display_name = ${cipher.plain(displayName)},
         display_name_enc = ${cipher.encrypt(displayName)}, updated_at = now()
       WHERE id = ${id}`,
    );
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

  async demoteOwner(slug: string, userId: string): Promise<boolean> {
    const result = await this.db.run(
      `UPDATE organization_memberships AS m SET role = 'member'
       FROM organizations AS o
       WHERE o.id = m.organization_id AND o.slug = ? AND m.user_id = ? AND m.role = 'owner'
         AND ${OWNER_COUNT} > 1
       RETURNING 1`,
      [slug, userId],
    );
    return (result.changes ?? 0) > 0;
  }

  async deleteMembershipUnlessLastOwner(slug: string, userId: string): Promise<boolean> {
    const result = await this.db.run(
      `DELETE FROM organization_memberships AS m
       USING organizations AS o
       WHERE m.organization_id = o.id AND o.slug = ? AND m.user_id = ?
         AND (m.role <> 'owner' OR ${OWNER_COUNT} > 1)
       RETURNING 1`,
      [slug, userId],
    );
    return (result.changes ?? 0) > 0;
  }

  async archiveUnlessLast(id: string): Promise<boolean> {
    // The locked sub-selects make concurrent archives and owner changes wait for each other
    // and re-check the row they waited on, so the two counts cannot both pass at once.
    const result = await this.db.run(
      `UPDATE users AS u SET status = 'archived', updated_at = now()
       WHERE u.id = ?
         AND (u.system_role <> 'platform_admin' OR ${ACTIVE_PLATFORM_ADMIN_COUNT} > 1)
         AND NOT EXISTS (
           SELECT 1 FROM organization_memberships AS m
           JOIN organizations AS o ON o.id = m.organization_id
           WHERE m.user_id = u.id AND m.role = 'owner' AND o.archived_at IS NULL
             AND ${OWNER_COUNT} <= 1
         )
       RETURNING 1`,
      [id],
    );
    return (result.changes ?? 0) > 0;
  }

  async listMembers(
    slug: string,
    afterId: string | undefined,
    limit: number,
  ): Promise<DirectoryMember[]> {
    const cipher = await this.encryption.cipher();
    const cursor = afterId ? sql` AND u.id > ${afterId}` : Sql.raw('');
    const rows = await this.db.query<MemberRow>(
      sql`SELECT u.id::text AS id, u.login,
         ${cipher.read('u.display_name', 'display_name', { enc: 'u.display_name_enc' })},
         ${cipher.read('u.avatar_url', 'avatar_url', { enc: 'u.avatar_url_enc' })},
         ${cipher.read('u.email', 'email', { enc: 'u.email_enc' })}, u.email_verified, m.role
       FROM organization_memberships m
       JOIN organizations o ON o.id = m.organization_id
       JOIN users u ON u.id = m.user_id
       WHERE o.slug = ${slug}${cursor}
       ORDER BY u.id
       LIMIT ${limit}`,
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
      sql`${membershipSelect(await this.encryption.cipher())} WHERE m.user_id = ${userId}
       ORDER BY o.slug`,
    );
    return rows.map((row) => this.membership(row));
  }

  async membershipsForOrganization(slug: string): Promise<MembershipDetail[]> {
    const rows = await this.db.query<MembershipRow>(
      sql`${membershipSelect(await this.encryption.cipher())} WHERE o.slug = ${slug}
       ORDER BY u.login`,
    );
    return rows.map((row) => this.membership(row));
  }

  async allMemberships(): Promise<MembershipDetail[]> {
    const rows = await this.db.query<MembershipRow>(
      sql`${membershipSelect(await this.encryption.cipher())} ORDER BY o.slug, u.login`,
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
