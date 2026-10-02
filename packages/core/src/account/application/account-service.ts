import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { UserAccount } from '../../directory/domain/models.ts';
import { AUDIT, DIRECTORY } from '../../shared/domain/tokens.ts';
import { PasswordHasher } from '../../shared/infrastructure/crypto/passwords.ts';

/** `POST /account/password` minimum length. */
export const MIN_PASSWORD_LENGTH = 12;

/** Form login and password changes against Postgres users with Argon2 hashes. */
@Container()
export class AccountService {
  constructor(
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(PasswordHasher) private readonly passwords: PasswordHasher,
  ) {}

  /** Active user by login or email whose stored hash matches; otherwise undefined. */
  async signIn(identifier: string, password: string): Promise<UserAccount | undefined> {
    const user = await this.directory.findActiveByLoginOrEmail(identifier);
    if (!user?.passwordHash) return undefined;
    return (await this.passwords.verify(password, user.passwordHash)) ? user : undefined;
  }

  /**
   * Sets a new password. Too short: `short`, nothing changes. Otherwise the hash is stored
   * only for an active user, and `account.password_rotated` is audited either way, as the
   * auth server does.
   */
  async setPassword(userId: string, password: string): Promise<'short' | 'saved'> {
    if (password.length < MIN_PASSWORD_LENGTH) return 'short';
    const user = await this.directory.findUser(userId);
    if (user?.status === 'active') {
      await this.directory.updateAccount(user.id, {
        passwordHash: await this.passwords.hash(password),
      });
    }
    await this.audit.append({
      action: 'account.password_rotated',
      actor: null,
      target: userId,
      correlationId: null,
    });
    return 'saved';
  }

  /** Active user by id, as the auth server's `findUserById`. */
  async activeUser(userId: string | null): Promise<UserAccount | undefined> {
    if (!userId) return undefined;
    const user = await this.directory.findUser(userId);
    return user?.status === 'active' ? user : undefined;
  }
}
