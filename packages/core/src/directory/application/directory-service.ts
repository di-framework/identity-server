import { Component, Container } from '@di-framework/core/decorators';
import {
  type Delivery,
  PasswordlessService,
} from '../../account/application/passwordless-service.ts';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { OAuthRepository } from '../../oauth/domain/oauth-client.ts';
import { JsonBody } from '../../shared/application/json-body.ts';
import { CursorCodec } from '../../shared/domain/cursor.ts';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import { ServiceResult } from '../../shared/domain/service-result.ts';
import { AUDIT, DIRECTORY, IDENTITY_SETTINGS, OAUTH } from '../../shared/domain/tokens.ts';
import type { IdentitySettings } from '../../shared/infrastructure/identity-settings.ts';
import type { DirectoryRepository } from '../domain/directory-repository.ts';
import { UserAccount } from '../domain/models.ts';

interface Command {
  actor: string;
  idempotencyKey?: string;
  body: Record<string, unknown>;
}

const ROLES = new Set(['member', 'owner']);

@Container()
export class DirectoryService {
  constructor(
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(OAUTH) private readonly oauth: OAuthRepository,
    @Component(CursorCodec) private readonly cursors: CursorCodec,
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(PasswordlessService) private readonly passwordless: PasswordlessService,
  ) {}

  async listUsers(): Promise<ServiceResult<ReturnType<DirectoryService['user']>[]>> {
    const users = await this.directory.listUsers();
    return new ServiceResult(
      200,
      users.map((user) => this.user(user)),
    );
  }

  async getUser(userId: string): Promise<ServiceResult<ReturnType<DirectoryService['user']>>> {
    const user = await this.find(userId);
    if (!user) return new ServiceResult(404);
    return new ServiceResult(200, this.user(user));
  }

  async createUser(command: Command): Promise<ServiceResult<{ id: string; status: string }>> {
    const body = new JsonBody(command.body);
    const login = body.text('login');
    const email = body.text('email');
    const displayName = body.text('displayName');
    if (
      !login ||
      !email ||
      !displayName ||
      login.length > 128 ||
      email.length > 254 ||
      displayName.length > 255
    ) {
      return new ServiceResult(400);
    }
    try {
      let deliver: Delivery | undefined;
      const result = await this.directory.transaction(async () => {
        const replay = await this.replayUser(command.idempotencyKey, login, email, displayName);
        if (replay) return replay;
        const id = crypto.randomUUID();
        await this.directory.insertUser({ id, login, email, displayName });
        deliver = await this.passwordless.invite(
          new UserAccount(id, login, email, displayName, false, 'pending', null),
        );
        await this.audit.append({
          action: 'admin.user_created',
          actor: command.actor,
          target: id,
          correlationId: command.idempotencyKey ?? null,
          after: { status: 'pending' },
        });
        return new ServiceResult(201, { id, status: 'pending' });
      });
      await deliver?.();
      return result;
    } catch (error) {
      return this.failed(error);
    }
  }

  async updateUser(
    userId: string,
    command: Command,
  ): Promise<ServiceResult<ReturnType<DirectoryService['user']>>> {
    const displayName = new JsonBody(command.body).text('displayName');
    if (!displayName || displayName.length > 255) return new ServiceResult(400);
    if (!this.isUuid(userId)) return new ServiceResult(400);
    const user = await this.directory.findUser(userId);
    if (!user) return new ServiceResult(404);
    if (user.status === 'archived') return new ServiceResult(409);
    await this.directory.updateDisplayName(user.id, displayName);
    await this.audit.append({
      action: 'admin.user_updated',
      actor: command.actor,
      target: user.id,
      correlationId: command.idempotencyKey ?? null,
      before: { displayName: user.displayName },
      after: { displayName },
    });
    return new ServiceResult(
      200,
      this.user(
        new UserAccount(
          user.id,
          user.login,
          user.email,
          displayName,
          user.emailVerified,
          user.status,
          user.passwordHash,
        ),
      ),
    );
  }

  async archiveUser(userId: string, command: Command): Promise<ServiceResult> {
    if (!this.isUuid(userId)) return new ServiceResult(404);
    const user = await this.directory.findUser(userId);
    if (!user) return new ServiceResult(404);
    if (user.status !== 'archived') {
      const memberships = await this.directory.countMembershipsForUser(user.id);
      if (memberships > 0) return new ServiceResult(409);
    }
    await this.directory.archiveUser(user.id);
    await this.audit.append({
      action: 'admin.user_archived',
      actor: command.actor,
      target: user.id,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(204);
  }

  async listOrganizations(): Promise<
    ServiceResult<ReturnType<DirectoryService['organization']>[]>
  > {
    const organizations = await this.directory.listOrganizations();
    return new ServiceResult(
      200,
      organizations.map((organization) => this.organization(organization)),
    );
  }

  async getOrganization(
    slug: string,
  ): Promise<ServiceResult<ReturnType<DirectoryService['organization']>>> {
    const organization = await this.directory.findOrganization(slug);
    if (!organization) return new ServiceResult(404);
    return new ServiceResult(200, this.organization(organization));
  }

  async createOrganization(command: Command): Promise<ServiceResult<{ id: string; slug: string }>> {
    const body = new JsonBody(command.body);
    const slug = body.text('slug');
    const name = body.text('name');
    if (!slug || !name || slug.length > 128 || name.length > 255) return new ServiceResult(400);
    try {
      return await this.directory.transaction(async () => {
        const replay = await this.replayOrganization(command.idempotencyKey, slug, name);
        if (replay) return replay;
        const id = crypto.randomUUID();
        await this.directory.insertOrganization({ id, slug, name });
        await this.audit.append({
          action: 'admin.organization_created',
          actor: command.actor,
          target: slug,
          correlationId: command.idempotencyKey ?? null,
          after: { name },
        });
        return new ServiceResult(201, { id, slug });
      });
    } catch (error) {
      return this.failed(error);
    }
  }

  async updateOrganization(
    slug: string,
    command: Command,
  ): Promise<ServiceResult<ReturnType<DirectoryService['organization']>>> {
    const name = new JsonBody(command.body).text('name');
    if (!name || name.length > 255) return new ServiceResult(400);
    const organization = await this.directory.findOrganization(slug);
    if (!organization) return new ServiceResult(404);
    await this.directory.updateOrganizationName(slug, name);
    await this.audit.append({
      action: 'admin.organization_updated',
      actor: command.actor,
      target: slug,
      correlationId: command.idempotencyKey ?? null,
      before: { name: organization.name },
      after: { name },
    });
    return new ServiceResult(200, this.organization({ ...organization, name }));
  }

  async deleteOrganization(slug: string, command: Command): Promise<ServiceResult> {
    const organization = await this.directory.findOrganization(slug);
    if (!organization) return new ServiceResult(404);
    const memberships = await this.directory.countMembershipsForSlug(slug);
    const clients = await this.oauth.countActive(slug);
    if (memberships > 0 || clients > 0) return new ServiceResult(409);
    await this.directory.deleteOrganization(slug);
    await this.audit.append({
      action: 'admin.organization_deleted',
      actor: command.actor,
      target: slug,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(204);
  }

  async getMembership(slug: string, userId: string): Promise<ServiceResult> {
    if (!this.isUuid(userId)) return new ServiceResult(404);
    const membership = await this.directory.findMembership(slug, userId);
    if (!membership) return new ServiceResult(404);
    return new ServiceResult(200, {
      organization_slug: membership.organizationSlug,
      user_id: membership.userId,
      role: membership.role,
    });
  }

  async putMembership(slug: string, userId: string, command: Command): Promise<ServiceResult> {
    const role = new JsonBody(command.body).text('role');
    if (!ROLES.has(role)) return new ServiceResult(400);
    if (!this.isUuid(userId)) return new ServiceResult(400);
    const organization = await this.directory.findOrganization(slug);
    if (!organization) return new ServiceResult(404);
    const user = await this.directory.findUser(userId);
    if (!user) return new ServiceResult(404);
    if (user.status === 'archived') return new ServiceResult(409);
    await this.directory.upsertMembership(organization.id, userId, role);
    await this.audit.append({
      action: 'admin.membership_upserted',
      actor: command.actor,
      target: `${slug}/${userId}`,
      correlationId: command.idempotencyKey ?? null,
      after: { role },
    });
    return new ServiceResult(204);
  }

  async deleteMembership(slug: string, userId: string, command: Command): Promise<ServiceResult> {
    if (!this.isUuid(userId)) return new ServiceResult(404);
    const removed = await this.directory.deleteMembership(slug, userId);
    if (!removed) return new ServiceResult(404);
    await this.audit.append({
      action: 'admin.membership_deleted',
      actor: command.actor,
      target: `${slug}/${userId}`,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(204);
  }

  async listMembers(
    slug: string,
    cursor: string | undefined,
    limit: string | undefined,
  ): Promise<ServiceResult> {
    const decoded = this.cursors.decode(cursor);
    if (decoded.invalid) return new ServiceResult(400);
    const pageSize = this.cursors.limit(limit);
    const rows = await this.directory.listMembers(slug, decoded.id, pageSize + 1);
    const page = rows.slice(0, pageSize);
    const last = page[page.length - 1];
    const next = last && rows.length > pageSize ? this.cursors.encode(last.id) : null;
    return new ServiceResult(200, {
      items: page.map((member) => ({
        issuer: this.settings.issuer,
        subject: member.id,
        login: member.login,
        display_name: member.displayName,
        picture: member.picture,
        email: member.email,
        email_verified: member.emailVerified,
        organization_role: member.role,
      })),
      next_cursor: next,
    });
  }

  private async find(userId: string): Promise<UserAccount | undefined> {
    if (!this.isUuid(userId)) return undefined;
    return this.directory.findUser(userId);
  }

  private async replayUser(
    key: string | undefined,
    login: string,
    email: string,
    displayName: string,
  ): Promise<ServiceResult<{ id: string; status: string }> | undefined> {
    if (!key) return undefined;
    const target = await this.audit.idempotentTarget('admin.user_created', key);
    if (!target) return undefined;
    const existing = await this.directory.findUser(target);
    if (!existing) return undefined;
    if (
      existing.login === login &&
      existing.email === email &&
      existing.displayName === displayName
    ) {
      return new ServiceResult(201, { id: existing.id, status: existing.status });
    }
    return new ServiceResult(409);
  }

  private async replayOrganization(
    key: string | undefined,
    slug: string,
    name: string,
  ): Promise<ServiceResult<{ id: string; slug: string }> | undefined> {
    if (!key) return undefined;
    const target = await this.audit.idempotentTarget('admin.organization_created', key);
    if (!target) return undefined;
    const existing = await this.directory.findOrganization(target);
    if (!existing) return undefined;
    if (existing.slug === slug && existing.name === name) {
      return new ServiceResult(201, { id: existing.id, slug: existing.slug });
    }
    return new ServiceResult(409);
  }

  private user(user: UserAccount) {
    return {
      id: user.id,
      login: user.login,
      email: user.email,
      display_name: user.displayName,
      email_verified: user.emailVerified,
      status: user.status,
    };
  }

  private organization(organization: {
    id: string;
    slug: string;
    name: string;
    createdAt: string;
  }) {
    return {
      id: organization.id,
      slug: organization.slug,
      name: organization.name,
      created_at: organization.createdAt,
    };
  }

  private failed(error: unknown): ServiceResult<never> {
    return new ServiceResult(error instanceof IdentityError ? error.status : 500);
  }

  private isUuid(value: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
  }
}
