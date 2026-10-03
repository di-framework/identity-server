import { evaluatePolicy } from '@di-framework/authz';
import { Component, Container } from '@di-framework/core/decorators';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { Organization } from '../../directory/domain/models.ts';
import { policyDocument } from '../../shared/application/policies.ts';
import { DIRECTORY } from '../../shared/domain/tokens.ts';
// Side-effect import: registers `AdminAccessPolicy` before the first compile.
import '../domain/admin-access-policy.ts';
import { ADMIN_RESOURCE, type AdminCapability } from '../domain/admin-access-policy.ts';

export type { AdminCapability };

export interface AuthorizationContext {
  userId: string;
  isPlatformAdmin: boolean;
  /** Slugs of non-archived organizations the user owns. */
  ownedOrgSlugs: Set<string>;
  memberOrgSlugs: Set<string>;
}

/** HTML admin denial. The browser layer answers 403. */
export class AdminAccessDenied extends Error {
  constructor(readonly capability: AdminCapability) {
    super(`Access denied for capability ${capability}`);
    this.name = 'AdminAccessDenied';
  }
}

/**
 * Who may do what in the HTML admin (`AdminPolicy.kt`). The rules are `AdminAccessPolicy`,
 * evaluated with `@di-framework/authz`: an inactive actor is always denied, an active platform
 * admin may do everything, organization create/archive and platform-admin management are
 * platform-admin only, and everyone else acts only on organizations they own.
 */
@Container()
export class AdminPolicy {
  constructor(@Component(DIRECTORY) private readonly directory: DirectoryRepository) {}

  async context(userId: string): Promise<AuthorizationContext> {
    const user = await this.directory.findUser(userId);
    if (!user) {
      return {
        userId,
        isPlatformAdmin: false,
        ownedOrgSlugs: new Set(),
        memberOrgSlugs: new Set(),
      };
    }
    const memberships = (await this.directory.membershipsForUser(userId)).filter(
      (membership) => membership.organizationArchivedAt === null,
    );
    return {
      userId,
      isPlatformAdmin: user.systemRole === 'platform_admin' && user.status === 'active',
      ownedOrgSlugs: new Set(
        memberships.filter((m) => m.role === 'owner').map((m) => m.organizationSlug),
      ),
      memberOrgSlugs: new Set(memberships.map((m) => m.organizationSlug)),
    };
  }

  async authorized(
    actorId: string,
    capability: AdminCapability,
    target: { orgSlug?: string | null; userId?: string } = {},
  ): Promise<boolean> {
    const actor = await this.directory.findUser(actorId);
    const context = await this.context(actorId);
    const decision = evaluatePolicy(policyDocument(ADMIN_RESOURCE), {
      resource: ADMIN_RESOURCE,
      action: capability,
      subject: {
        id: actorId,
        roles: context.isPlatformAdmin ? ['platform_admin'] : [],
        scopes: [],
        claims: {
          active: actor?.status === 'active',
          ownsOrganization: context.ownedOrgSlugs.size > 0,
        },
      },
      value: await this.facts(actorId, context, target),
    });
    return decision.allowed;
  }

  /** What the policy needs to know about the target, as in `isOrgOwnerAuthorized`. */
  private async facts(
    actorId: string,
    context: AuthorizationContext,
    target: { orgSlug?: string | null; userId?: string },
  ): Promise<{ targeted: boolean; ownedByActor: boolean }> {
    if (target.orgSlug) {
      return { targeted: true, ownedByActor: context.ownedOrgSlugs.has(target.orgSlug) };
    }
    if (target.userId !== undefined) {
      if (target.userId === actorId) {
        return { targeted: true, ownedByActor: context.ownedOrgSlugs.size > 0 };
      }
      const theirs = await this.directory.membershipsForUser(target.userId);
      return {
        targeted: true,
        ownedByActor: theirs.some((m) => context.ownedOrgSlugs.has(m.organizationSlug)),
      };
    }
    return { targeted: false, ownedByActor: false };
  }

  async check(
    actorId: string,
    capability: AdminCapability,
    target: { orgSlug?: string | null; userId?: string } = {},
  ): Promise<void> {
    if (!(await this.authorized(actorId, capability, target))) {
      throw new AdminAccessDenied(capability);
    }
  }

  /** False only when the target is a platform admin and no other active one remains. */
  async canDemoteOrArchivePlatformAdmin(targetUserId: string): Promise<boolean> {
    const target = await this.directory.findUser(targetUserId);
    if (target?.systemRole !== 'platform_admin') return true;
    return (await this.directory.countActivePlatformAdmins()) > 1;
  }

  /**
   * False only when the target is a member of the organization and it has one owner. As in the
   * auth server, callers combine this with their own owner-role check.
   */
  async canRemoveOrDemoteOrgOwner(slug: string, targetUserId: string): Promise<boolean> {
    const organization = await this.directory.findOrganization(slug);
    if (!organization) return false;
    const member = await this.directory.findMembership(slug, targetUserId);
    if (!member) return true;
    return (await this.directory.countOwners(slug)) > 1;
  }

  /** Non-archived organizations the actor may choose in invite, membership, and client forms. */
  async availableOrganizations(context: AuthorizationContext): Promise<Organization[]> {
    const organizations = await this.directory.listOrganizations();
    return organizations.filter(
      (organization) =>
        organization.archivedAt === null &&
        (context.isPlatformAdmin || context.ownedOrgSlugs.has(organization.slug)),
    );
  }
}

/** Result of an HTML admin action, using the auth server's status codes and redirect targets. */
export type AdminResult<T> =
  | { kind: 'ok'; value: T }
  | { kind: 'redirect'; location: string }
  | { kind: 'error'; status: 400 | 404 | 409; title: string; message: string };

export const ok = <T>(value: T): AdminResult<T> => ({ kind: 'ok', value });
export const redirect = <T = never>(location: string): AdminResult<T> => ({
  kind: 'redirect',
  location,
});
export const failure = <T = never>(
  status: 400 | 404 | 409,
  title: string,
  message: string,
): AdminResult<T> => ({ kind: 'error', status, title, message });

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Spring answers 400 when a `UUID` path or form value does not parse. */
export function invalidId<T = never>(): AdminResult<T> {
  return failure(400, 'Bad Request', 'The identifier is not valid.');
}

/** Splits a comma-separated form field, trimming and dropping blanks. */
export function commaList(value: string | null | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/** Query-string encoding with `+` for spaces, as the auth server writes its `error=` values. */
export function formEncode(value: string): string {
  return encodeURIComponent(value).replaceAll('%20', '+');
}
