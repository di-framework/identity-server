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

/** Sends a staged sign-in link. Run it after the transaction that staged it commits. */
export type Delivery = () => Promise<void>;

const NOTHING: Delivery = async () => {};

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
    if (user.status === 'pending') await (await this.stage(user, 'activation'))();
    else if (user.status === 'active') await (await this.stage(user, 'sign_in'))();
  }

  /**
   * Stages an `invite` challenge in the caller's transaction and returns its delivery, so the
   * mail goes out only after the new account commits and no connection is held over SMTP.
   */
  invite(user: UserAccount): Promise<Delivery> {
    return this.stage(user, 'invite');
  }

  /**
   * Consumes a challenge, then activates the user and verifies the email. The row lock
   * serializes callers on a pooled server; `claim` is one conditional statement, so the token is
   * single-use on a database that runs every statement on its own.
   */
  consume(token: string): Promise<ConsumedChallenge | undefined> {
    if (!TOKEN_PATTERN.test(token)) return Promise.resolve(undefined);
    return this.directory.transaction(async () => {
      const now = this.clock.now();
      const challenge = await this.challenges.lockByHash(Hashing.sha256Hex(token));
      if (!challenge || challenge.consumedAt !== null || challenge.expiresAt <= now)
        return undefined;
      const user = challenge.userId ? await this.directory.findUser(challenge.userId) : undefined;
      if (!user || (user.status !== 'pending' && user.status !== 'active')) return undefined;
      if (!(await this.challenges.claim(challenge.id, now))) return undefined;
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

  /**
   * Inserts a challenge unless one was issued for this email and purpose in the last minute. The
   * check and insert are one statement, so a database without transactions still issues one
   * challenge per request; the transaction-scoped lock on the email and purpose additionally
   * serializes concurrent requests on a pooled server.
   */
  private stage(user: UserAccount, purpose: ChallengePurpose): Promise<Delivery> {
    const email = user.email;
    if (!email) return Promise.resolve(NOTHING);
    return this.directory.transaction(async () => {
      await this.challenges.lockIssuance(email, purpose);
      const now = this.clock.now();
      const token = Hashing.token();
      const id = crypto.randomUUID();
      const inserted = await this.challenges.insertUnlessRecent(
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
        now - CHALLENGE_INTERVAL_MS,
      );
      if (!inserted) return NOTHING;
      return () => this.deliver(user.id, email, id, token);
    });
  }

  private async deliver(userId: string, email: string, id: string, token: string): Promise<void> {
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
        target: userId,
        correlationId: null,
      });
    }
  }
}
