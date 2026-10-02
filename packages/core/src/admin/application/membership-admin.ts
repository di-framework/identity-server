import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { MembershipDetail, Organization } from '../../directory/domain/models.ts';
import { AUDIT, DIRECTORY } from '../../shared/domain/tokens.ts';
import {
  AdminPolicy,
  type AdminResult,
  failure,
  formEncode,
  invalidId,
  redirect,
  UUID_PATTERN,
} from './admin-policy.ts';

/** `/admin/memberships/**` (`AdminMembershipController.kt`), with the last-owner blocks. */
@Container()
export class MembershipAdminService {
  constructor(
    @Component(AdminPolicy) private readonly policy: AdminPolicy,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
  ) {}

  async list(
    actorId: string,
    orgSlug?: string | null,
  ): Promise<{ memberships: MembershipDetail[]; organizations: Organization[] }> {
    const slug = orgSlug?.trim() || null;
    await this.policy.check(actorId, 'MEMBERSHIP_VIEW', { orgSlug: slug });
    const context = await this.policy.context(actorId);
    let memberships: MembershipDetail[];
    if (slug) memberships = await this.directory.membershipsForOrganization(slug);
    else if (context.isPlatformAdmin) memberships = await this.directory.allMemberships();
    else {
      memberships = [];
      for (const owned of [...context.ownedOrgSlugs].sort()) {
        memberships.push(...(await this.directory.membershipsForOrganization(owned)));
      }
    }
    return { memberships, organizations: await this.policy.availableOrganizations(context) };
  }

  async add(
    actorId: string,
    form: { orgSlug: string; userLoginOrEmail: string; role: string },
  ): Promise<AdminResult<never>> {
    await this.policy.check(actorId, 'MEMBERSHIP_ADD', { orgSlug: form.orgSlug });
    const organization = await this.directory.findOrganization(form.orgSlug);
    const identifier = form.userLoginOrEmail.trim();
    const user = await this.directory.findUserByEmailOrLogin(identifier, identifier);
    const back = (query: string) =>
      redirect(`/admin/memberships?orgSlug=${formEncode(form.orgSlug)}&${query}`);
    if (!organization || organization.archivedAt !== null) {
      return back(`error=${formEncode('Invalid or archived organization')}`);
    }
    if (!user) return back(`error=${formEncode('User not found')}`);
    if (user.status === 'archived') {
      return back(`error=${formEncode('Cannot add archived user to organization')}`);
    }
    if (await this.directory.findMembership(organization.slug, user.id)) {
      return back(`error=${formEncode('User is already a member')}`);
    }
    const role = form.role === 'owner' ? 'owner' : 'member';
    await this.directory.upsertMembership(organization.id, user.id, role);
    await this.audit.append({
      action: 'admin.membership.add',
      actor: actorId,
      target: `${organization.slug}:${user.id}`,
      correlationId: crypto.randomUUID(),
      after: { orgSlug: organization.slug, userId: user.id, role },
    });
    return back('added=1');
  }

  async changeRole(
    actorId: string,
    form: { orgSlug: string; userId: string; newRole: string },
  ): Promise<AdminResult<never>> {
    if (!UUID_PATTERN.test(form.userId)) return invalidId();
    await this.policy.check(actorId, 'MEMBERSHIP_ROLE_CHANGE', { orgSlug: form.orgSlug });
    const organization = await this.directory.findOrganization(form.orgSlug);
    const membership = organization
      ? await this.directory.findMembership(organization.slug, form.userId)
      : undefined;
    if (!organization || !membership) return failure(404, 'Not Found', '');
    const role = form.newRole === 'owner' ? 'owner' : 'member';
    const back = (query: string) =>
      redirect(`/admin/memberships?orgSlug=${formEncode(form.orgSlug)}&${query}`);
    if (
      membership.role === 'owner' &&
      role === 'member' &&
      !(await this.policy.canRemoveOrDemoteOrgOwner(form.orgSlug, form.userId))
    ) {
      return back(`error=${formEncode('Cannot demote last owner')}`);
    }
    await this.directory.upsertMembership(organization.id, form.userId, role);
    await this.audit.append({
      action: 'admin.membership.role_change',
      actor: actorId,
      target: `${form.orgSlug}:${form.userId}`,
      correlationId: crypto.randomUUID(),
      before: { role: membership.role },
      after: { role },
    });
    return back('changed=1');
  }

  async remove(
    actorId: string,
    form: { orgSlug: string; userId: string },
  ): Promise<AdminResult<never>> {
    if (!UUID_PATTERN.test(form.userId)) return invalidId();
    await this.policy.check(actorId, 'MEMBERSHIP_REMOVE', { orgSlug: form.orgSlug });
    const organization = await this.directory.findOrganization(form.orgSlug);
    const membership = organization
      ? await this.directory.findMembership(organization.slug, form.userId)
      : undefined;
    if (!organization || !membership) return failure(404, 'Not Found', '');
    const back = (query: string) =>
      redirect(`/admin/memberships?orgSlug=${formEncode(form.orgSlug)}&${query}`);
    if (
      membership.role === 'owner' &&
      !(await this.policy.canRemoveOrDemoteOrgOwner(form.orgSlug, form.userId))
    ) {
      return back(`error=${formEncode('Cannot remove last owner')}`);
    }
    await this.directory.deleteMembership(form.orgSlug, form.userId);
    await this.audit.append({
      action: 'admin.membership.remove',
      actor: actorId,
      target: `${form.orgSlug}:${form.userId}`,
      correlationId: crypto.randomUUID(),
      before: { role: membership.role },
    });
    return back('removed=1');
  }
}
