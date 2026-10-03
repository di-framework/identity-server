import { Component, Container } from '@di-framework/core/decorators';
import { PasswordlessService } from '../../account/application/passwordless-service.ts';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { MembershipDetail, Organization, UserAccount } from '../../directory/domain/models.ts';
import { AUDIT, DIRECTORY } from '../../shared/domain/tokens.ts';
import {
  AdminPolicy,
  type AdminResult,
  failure,
  formEncode,
  invalidId,
  ok,
  redirect,
  UUID_PATTERN,
} from './admin-policy.ts';

export interface InviteForm {
  login: string;
  email: string;
  displayName: string;
  orgSlug?: string | null;
  role?: string | null;
}

/** `/admin/users/**` (`AdminUserController.kt`). Restore and password reset exist only here. */
@Container()
export class UserAdminService {
  constructor(
    @Component(AdminPolicy) private readonly policy: AdminPolicy,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(PasswordlessService) private readonly passwordless: PasswordlessService,
  ) {}

  /** Platform admins see everyone; owners see themselves and users who share an owned org. */
  async list(
    actorId: string,
    filter: { q?: string; status?: string } = {},
  ): Promise<UserAccount[]> {
    await this.policy.check(actorId, 'USER_VIEW');
    const context = await this.policy.context(actorId);
    const q = filter.q?.toLowerCase() ?? '';
    const status = filter.status?.toLowerCase() ?? '';
    const users = await this.directory.listUsers();
    // Owners see users in their owned organizations: one membership read per owned organization.
    const shared = new Set<string>([actorId]);
    if (!context.isPlatformAdmin) {
      for (const slug of context.ownedOrgSlugs) {
        for (const m of await this.directory.membershipsForOrganization(slug)) shared.add(m.userId);
      }
    }
    const visible: UserAccount[] = [];
    for (const user of users) {
      if (status && user.status.toLowerCase() !== status) continue;
      if (
        q &&
        !user.login.toLowerCase().includes(q) &&
        !user.displayName.toLowerCase().includes(q) &&
        !(user.email ?? '').toLowerCase().includes(q)
      ) {
        continue;
      }
      if (!context.isPlatformAdmin && !shared.has(user.id)) continue;
      visible.push(user);
    }
    return visible;
  }

  async inviteOrganizations(actorId: string): Promise<Organization[]> {
    await this.policy.check(actorId, 'USER_INVITE');
    return this.policy.availableOrganizations(await this.policy.context(actorId));
  }

  async invite(actorId: string, form: InviteForm): Promise<AdminResult<never>> {
    const orgSlug = form.orgSlug?.trim() || null;
    await this.policy.check(actorId, 'USER_INVITE', { orgSlug });
    const login = form.login.trim();
    const email = form.email.trim();
    if (!login || !email) return failure(400, 'Invalid Input', 'Login and email are required.');
    if (await this.directory.findUserByEmailOrLogin(email, login)) {
      return failure(409, 'Conflict', 'A user with this email or login already exists.');
    }
    const id = crypto.randomUUID();
    await this.directory.transaction(async () => {
      await this.directory.insertAccount({
        id,
        login,
        email,
        displayName: form.displayName.trim() || login,
        passwordHash: null,
        emailVerified: false,
        systemRole: 'user',
        status: 'pending',
      });
      if (orgSlug) {
        const organization = await this.directory.findOrganization(orgSlug);
        if (organization && organization.archivedAt === null) {
          await this.directory.upsertMembership(
            organization.id,
            id,
            form.role === 'owner' ? 'owner' : 'member',
          );
        }
      }
      await this.passwordless.requestSignIn(email);
      await this.audit.append({
        action: 'admin.user.invite',
        actor: actorId,
        target: id,
        correlationId: crypto.randomUUID(),
        after: { login, status: 'pending', orgSlug: orgSlug ?? '' },
      });
    });
    return redirect(`/admin/users/${id}?invited=1`);
  }

  async detail(
    actorId: string,
    id: string,
  ): Promise<AdminResult<{ user: UserAccount; memberships: MembershipDetail[] }>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    await this.policy.check(actorId, 'USER_VIEW', { userId: id });
    const user = await this.directory.findUser(id);
    if (!user) return failure(404, 'User Not Found', `User with ID ${id} does not exist.`);
    return ok({ user, memberships: await this.directory.membershipsForUser(id) });
  }

  async archive(actorId: string, id: string): Promise<AdminResult<never>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    await this.policy.check(actorId, 'USER_ARCHIVE', { userId: id });
    // Lock the platform-admin set and every organization the user owns, in slug order, so the
    // last-admin and last-owner checks hold against concurrent archives and membership changes.
    return this.directory.transaction(async () => {
      await this.directory.lockPlatformAdmins();
      const owned = (await this.directory.membershipsForUser(id))
        .filter((m) => m.role === 'owner')
        .map((m) => m.organizationSlug)
        .sort();
      for (const slug of owned) await this.directory.lockOrganization(slug);
      const user = await this.directory.findUser(id);
      if (!user) return failure(404, 'Not Found', '');
      const blocked = await this.archiveBlock(id);
      if (blocked) return redirect(`/admin/users/${id}?error=${formEncode(blocked)}`);
      await this.directory.updateAccount(id, { status: 'archived' });
      await this.audit.append({
        action: 'admin.user.archive',
        actor: actorId,
        target: id,
        correlationId: crypto.randomUUID(),
        before: { status: user.status },
        after: { status: 'archived' },
      });
      return redirect(`/admin/users/${id}?archived=1`);
    });
  }

  async restore(actorId: string, id: string): Promise<AdminResult<never>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    await this.policy.check(actorId, 'USER_RESTORE', { userId: id });
    const user = await this.directory.findUser(id);
    if (!user) return failure(404, 'Not Found', '');
    await this.directory.updateAccount(id, { status: 'active' });
    await this.audit.append({
      action: 'admin.user.restore',
      actor: actorId,
      target: id,
      correlationId: crypto.randomUUID(),
      before: { status: user.status },
      after: { status: 'active' },
    });
    return redirect(`/admin/users/${id}?restored=1`);
  }

  async passwordReset(actorId: string, id: string): Promise<AdminResult<never>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    await this.policy.check(actorId, 'USER_PASSWORD_RESET', { userId: id });
    const user = await this.directory.findUser(id);
    if (!user) return failure(404, 'Not Found', '');
    if (user.email) await this.passwordless.requestSignIn(user.email);
    await this.audit.append({
      action: 'admin.user.password_reset',
      actor: actorId,
      target: id,
      correlationId: crypto.randomUUID(),
      after: { resetRequested: true },
    });
    return redirect(`/admin/users/${id}?reset=1`);
  }

  private async archiveBlock(userId: string): Promise<string | undefined> {
    if (!(await this.policy.canDemoteOrArchivePlatformAdmin(userId))) {
      return 'Cannot archive the last active platform administrator';
    }
    const owned = (await this.directory.membershipsForUser(userId)).filter(
      (m) => m.role === 'owner' && m.organizationArchivedAt === null,
    );
    for (const membership of owned) {
      if (!(await this.policy.canRemoveOrDemoteOrgOwner(membership.organizationSlug, userId))) {
        return `Cannot archive user who is the sole owner of active organization ${membership.organizationSlug}`;
      }
    }
    return undefined;
  }
}
