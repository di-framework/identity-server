import { Component, Container } from '@di-framework/core/decorators';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import { DIRECTORY } from '../../shared/domain/tokens.ts';

/** Custom claim holding `[{ slug, role }]` for every membership (`DirectoryRepository.kt`). */
export const ORGANIZATION_ROLES_CLAIM = 'https://gsio.ltd/claims/organization_roles';

/**
 * Profile claims shared by ID tokens and UserInfo (`SecurityConfiguration` token customizer and
 * UserInfo mapper). Only an active user gets them.
 */
@Container()
export class UserClaims {
  constructor(@Component(DIRECTORY) private readonly directory: DirectoryRepository) {}

  async forUser(userId: string): Promise<Record<string, unknown> | undefined> {
    const user = await this.directory.findUser(userId);
    if (user?.status !== 'active') return undefined;
    const memberships = await this.directory.membershipsForUser(userId);
    const claims: Record<string, unknown> = {
      preferred_username: user.login,
      name: user.displayName,
      email_verified: user.emailVerified,
      [ORGANIZATION_ROLES_CLAIM]: memberships.map((m) => ({
        slug: m.organizationSlug,
        role: m.role,
      })),
    };
    if (user.email) claims.email = user.email;
    if (user.avatarUrl) claims.picture = user.avatarUrl;
    return claims;
  }
}
