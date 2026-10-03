import { Allow, Deny, Equals, HasRole, Policy } from '@di-framework/authz';

/** HTML admin capabilities (`AdminCapability` in the auth server). Used as policy actions. */
export const ADMIN_CAPABILITIES = [
  'USER_VIEW',
  'USER_INVITE',
  'USER_ARCHIVE',
  'USER_RESTORE',
  'USER_PASSWORD_RESET',
  'MEMBERSHIP_VIEW',
  'MEMBERSHIP_ADD',
  'MEMBERSHIP_ROLE_CHANGE',
  'MEMBERSHIP_REMOVE',
  'OAUTH_CLIENT_VIEW',
  'OAUTH_CLIENT_CREATE',
  'OAUTH_CLIENT_EDIT',
  'OAUTH_CLIENT_ROTATE_SECRET',
  'OAUTH_CLIENT_REVOKE',
  'ORG_VIEW',
  'ORG_CREATE',
  'ORG_EDIT_SETTINGS',
  'ORG_ARCHIVE',
  'AUDIT_VIEW',
  'PLATFORM_ADMIN_MANAGE',
] as const;

export type AdminCapability = (typeof ADMIN_CAPABILITIES)[number];

/** Platform-admin only: creating and archiving organizations and managing platform admins. */
export const PLATFORM_ONLY: readonly AdminCapability[] = [
  'ORG_CREATE',
  'ORG_ARCHIVE',
  'PLATFORM_ADMIN_MANAGE',
];

/** Capabilities an owner may use with no target, provided they own an organization. */
export const GENERAL: readonly AdminCapability[] = [
  'USER_VIEW',
  'USER_INVITE',
  'MEMBERSHIP_VIEW',
  'OAUTH_CLIENT_VIEW',
  'OAUTH_CLIENT_CREATE',
  'ORG_VIEW',
  'AUDIT_VIEW',
];

const OWNER_CAPABILITIES = ADMIN_CAPABILITIES.filter(
  (capability) => !PLATFORM_ONLY.includes(capability),
);

export const ADMIN_RESOURCE = 'admin';

/**
 * `AdminPolicy.isAuthorized` as a declarative policy. The subject carries `platform_admin` as a
 * role and `active` / `ownsOrganization` claims; the resource carries facts the caller computed
 * about the target (`targeted`, `ownedByActor`). Denies win, and no matching allow denies.
 */
@Policy(ADMIN_RESOURCE)
export class AdminAccessPolicy {
  @Deny(...ADMIN_CAPABILITIES)
  @Equals('subject.claims.active', false)
  inactiveActor() {}

  @Allow(...ADMIN_CAPABILITIES)
  @HasRole('platform_admin')
  platformAdmin() {}

  @Allow(...OWNER_CAPABILITIES)
  @Equals('resource.ownedByActor', true)
  ownedTarget() {}

  @Allow(...GENERAL)
  @Equals('resource.targeted', false)
  @Equals('subject.claims.ownsOrganization', true)
  generalView() {}
}
