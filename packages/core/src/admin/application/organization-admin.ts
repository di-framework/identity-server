import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { Organization } from '../../directory/domain/models.ts';
import type { OAuthRepository } from '../../oauth/domain/oauth-client.ts';
import type { Clock } from '../../shared/domain/clock.ts';
import { AUDIT, CLOCK, DIRECTORY, OAUTH } from '../../shared/domain/tokens.ts';
import {
  AdminPolicy,
  type AdminResult,
  failure,
  invalidId,
  ok,
  redirect,
  UUID_PATTERN,
} from './admin-policy.ts';

export interface OrganizationRow {
  organization: Organization;
  /** Every membership, as `countByOrganizationSlug`. */
  memberCount: number;
  /** Lifecycle rows with `revoked_at` null. */
  clientCount: number;
}

const SLUG = /^[a-z0-9-]+$/;

/** `/admin/organizations/**` (`AdminOrganizationController.kt`). Archive exists only here. */
@Container()
export class OrganizationAdminService {
  constructor(
    @Component(AdminPolicy) private readonly policy: AdminPolicy,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(OAUTH) private readonly oauth: OAuthRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  async list(
    actorId: string,
    status?: string,
  ): Promise<{ rows: OrganizationRow[]; canCreate: boolean }> {
    await this.policy.check(actorId, 'ORG_VIEW');
    const context = await this.policy.context(actorId);
    const wanted = status?.toLowerCase();
    const organizations = (await this.directory.listOrganizations()).filter(
      (organization) =>
        (context.isPlatformAdmin || context.ownedOrgSlugs.has(organization.slug)) &&
        (wanted === 'active'
          ? organization.archivedAt === null
          : wanted === 'archived'
            ? organization.archivedAt !== null
            : true),
    );
    const rows: OrganizationRow[] = [];
    for (const organization of organizations) rows.push(await this.row(organization));
    return { rows, canCreate: context.isPlatformAdmin };
  }

  async checkCreate(actorId: string): Promise<void> {
    await this.policy.check(actorId, 'ORG_CREATE');
  }

  async create(actorId: string, form: { slug: string; name: string }): Promise<AdminResult<never>> {
    await this.policy.check(actorId, 'ORG_CREATE');
    const slug = form.slug.trim().toLowerCase();
    if (!SLUG.test(slug)) {
      return failure(
        400,
        'Invalid Organization Slug',
        'Organization slug must contain only lowercase letters, numbers, and hyphens.',
      );
    }
    if (await this.directory.findOrganization(slug)) {
      return failure(
        409,
        'Organization Slug Exists',
        `Organization with slug '${slug}' already exists.`,
      );
    }
    const id = crypto.randomUUID();
    const name = form.name.trim() || slug;
    await this.directory.insertOrganization({ id, slug, name });
    await this.audit.append({
      action: 'admin.org.create',
      actor: actorId,
      target: slug,
      correlationId: crypto.randomUUID(),
      after: { id, slug, name },
    });
    return redirect(`/admin/organizations/${id}?created=1`);
  }

  async detail(
    actorId: string,
    id: string,
  ): Promise<AdminResult<OrganizationRow & { canArchive: boolean }>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    const organization = await this.directory.findOrganizationById(id);
    if (!organization) {
      return failure(404, 'Organization Not Found', `Organization with ID ${id} does not exist.`);
    }
    await this.policy.check(actorId, 'ORG_VIEW', { orgSlug: organization.slug });
    const context = await this.policy.context(actorId);
    return ok({
      ...(await this.row(organization)),
      canArchive: context.isPlatformAdmin && organization.archivedAt === null,
    });
  }

  async updateSettings(actorId: string, id: string, name: string): Promise<AdminResult<never>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    const organization = await this.directory.findOrganizationById(id);
    if (!organization) return failure(404, 'Not Found', '');
    await this.policy.check(actorId, 'ORG_EDIT_SETTINGS', { orgSlug: organization.slug });
    const next = name.trim() || organization.slug;
    await this.directory.updateOrganizationName(organization.slug, next);
    await this.audit.append({
      action: 'admin.org.edit_settings',
      actor: actorId,
      target: organization.slug,
      correlationId: crypto.randomUUID(),
      before: { name: organization.name },
      after: { name: next },
    });
    return redirect(`/admin/organizations/${id}?updated=1`);
  }

  async archive(actorId: string, id: string): Promise<AdminResult<never>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    const organization = await this.directory.findOrganizationById(id);
    if (!organization) return failure(404, 'Not Found', '');
    await this.policy.check(actorId, 'ORG_ARCHIVE', { orgSlug: organization.slug });
    const at = this.clock.now();
    await this.directory.archiveOrganization(organization.slug, at);
    await this.audit.append({
      action: 'admin.org.archive',
      actor: actorId,
      target: organization.slug,
      correlationId: crypto.randomUUID(),
      after: { archivedAt: new Date(at).toISOString() },
    });
    return redirect(`/admin/organizations/${id}?archived=1`);
  }

  private async row(organization: Organization): Promise<OrganizationRow> {
    return {
      organization,
      memberCount: await this.directory.countMembershipsForSlug(organization.slug),
      clientCount: await this.oauth.countActive(organization.slug),
    };
  }
}
