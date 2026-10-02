import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { UserAccount } from '../../directory/domain/models.ts';
import { Mailer } from '../../mail/application/mailer.ts';
import type { Clock } from '../../shared/domain/clock.ts';
import {
  AUDIT,
  CHALLENGES,
  CLOCK,
  DIRECTORY,
  IDENTITY_SETTINGS,
} from '../../shared/domain/tokens.ts';
import { Hashing, TOKEN_PATTERN } from '../../shared/infrastructure/crypto/hashing.ts';
import type { IdentitySettings } from '../../shared/infrastructure/identity-settings.ts';
import type { ChallengePurpose, ChallengeRepository } from '../domain/challenge.ts';

export const CHALLENGE_TTL_MS = 15 * 60 * 1000;
export const CHALLENGE_INTERVAL_MS = 60 * 1000;

export interface ConsumedChallenge {
  user: UserAccount;
  purpose: ChallengePurpose;
}

/**
 * Email sign-in links (`PasswordlessService.kt`). Unknown and ineligible addresses get the same
 * response and no mail. One challenge per email and purpose per minute. Links last 15 minutes.
 */
@Container()
export class PasswordlessService {
  constructor(
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(CHALLENGES) private readonly challenges: ChallengeRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(Mailer) private readonly mail: Mailer,
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  /** Pending accounts get purpose `activation`, active ones `sign_in`; anyone else nothing. */
  async requestSignIn(email: string): Promise<void> {
    const user = await this.directory.findUserByEmail(email);
    if (!user) return;
    if (user.status === 'pending') await this.issue(user, 'activation');
    else if (user.status === 'active') await this.issue(user, 'sign_in');
  }

  invite(user: UserAccount): Promise<void> {
    return this.issue(user, 'invite');
  }

  /** Consumes a challenge under a row lock, then activates the user and verifies the email. */
  consume(token: string): Promise<ConsumedChallenge | undefined> {
    if (!TOKEN_PATTERN.test(token)) return Promise.resolve(undefined);
    return this.directory.transaction(async () => {
      const now = this.clock.now();
      const challenge = await this.challenges.lockByHash(Hashing.sha256Hex(token));
      if (!challenge || challenge.consumedAt !== null || challenge.expiresAt <= now)
        return undefined;
      const user = challenge.userId ? await this.directory.findUser(challenge.userId) : undefined;
      if (!user || (user.status !== 'pending' && user.status !== 'active')) return undefined;
      await this.challenges.markConsumed(challenge.id, now);
      await this.directory.updateAccount(user.id, { status: 'active', emailVerified: true });
      await this.audit.append({
        action: 'passwordless.consumed',
        actor: null,
        target: user.id,
        correlationId: null,
      });
      const active = (await this.directory.findUser(user.id)) as UserAccount;
      return { user: active, purpose: challenge.purpose };
    });
  }

  private async issue(user: UserAccount, purpose: ChallengePurpose): Promise<void> {
    const email = user.email;
    if (!email) return;
    const now = this.clock.now();
    if ((await this.challenges.countSince(email, purpose, now - CHALLENGE_INTERVAL_MS)) > 0) return;
    const token = Hashing.token();
    const id = crypto.randomUUID();
    await this.challenges.insert(
      {
        id,
        userId: user.id,
        email,
        tokenHash: Hashing.sha256Hex(token),
        purpose,
        expiresAt: now + CHALLENGE_TTL_MS,
        consumedAt: null,
      },
      now,
    );
    try {
      await this.mail.send({
        to: email,
        subject: 'Your GSIO sign-in link',
        text: `Open this link to continue to GSIO:\n${this.settings.publicOrigin}/passwordless/confirm?token=${token}\n\nThis link expires in 15 minutes.`,
      });
    } catch {
      await this.challenges.markConsumed(id, this.clock.now());
      await this.audit.append({
        action: 'passwordless.delivery_failed',
        actor: null,
        target: user.id,
        correlationId: null,
      });
    }
  }
}
