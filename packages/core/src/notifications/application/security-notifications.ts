import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { IdentityLink } from '../../linking/domain/identity-link.ts';
import { Mailer } from '../../mail/application/mailer.ts';
import type { Clock } from '../../shared/domain/clock.ts';
import { AUDIT, CLOCK, DIRECTORY, NOTIFICATIONS } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import type { NotificationAction, NotificationRepository } from '../domain/notification.ts';

/** How long a claimed notification stays out of `due` while its mail is being sent. */
export const DELIVERY_LEASE_MS = 60_000;

/** `min(30s * 2^min(attempts - 1, 7), 1h)`, with no attempt limit. */
export function retryDelayMs(attempts: number): number {
  const exponent = Math.min(Math.max(attempts - 1, 0), 7);
  return Math.min(30_000 * 2 ** exponent, 3_600_000);
}

/**
 * Outbox for link and unlink events (`IdentitySecurityNotificationService.kt`). One row per event
 * key `sha256(action|userId|issuer|subject)`. Mail goes only to an active account's verified
 * address and carries the action, provider, a short subject hint, and the time, never tokens,
 * claims, or the subject itself.
 */
@Container()
export class SecurityNotificationService {
  constructor(
    @Component(NOTIFICATIONS) private readonly notifications: NotificationRepository,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(Mailer) private readonly mail: Mailer,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  async enqueue(
    action: NotificationAction,
    userId: string,
    link: IdentityLink,
    correlationId: string | null,
  ): Promise<void> {
    const user = await this.directory.findUser(userId);
    if (!user) return;
    const email = user.email?.trim() ?? '';
    const recipient = email && user.emailVerified && user.status === 'active' ? email : null;
    const eventKey = Hashing.sha256Hex(`${action}|${userId}|${link.issuer}|${link.subject}`);
    const identityHint = Hashing.sha256Hex(link.subject).slice(0, 16);
    const status = recipient ? 'pending' : 'skipped_no_verified_contact';
    const now = this.clock.now();
    const inserted = await this.notifications.insertIfAbsent({
      id: crypto.randomUUID(),
      eventKey,
      userId,
      action,
      recipientEmail: recipient,
      providerName: link.providerName.replaceAll(/[\r\n]/g, ' ').slice(0, 128),
      issuer: link.issuer,
      identityHint,
      correlationId: correlationId?.slice(0, 128) ?? null,
      status,
      attempts: 0,
      nextAttemptAt: now,
      createdAt: now,
      sentAt: null,
      lastError: null,
    });
    if (!inserted) return;
    await this.audit.append({
      action: 'identity_security_notification.queued',
      actor: null,
      target: eventKey,
      correlationId,
      after: { action, status, identity_hint: identityHint },
    });
  }

  /**
   * Sends one due notification; failures stay retryable with backoff. Claiming the row is one
   * statement, so two workers (or two guest invocations) never send the same mail, and the
   * claim lapses after `DELIVERY_LEASE_MS` if the outcome is never saved.
   */
  deliver(id: string): Promise<void> {
    return this.directory.transaction(async () => {
      const now = this.clock.now();
      const notification = await this.notifications.claim(id, now, now + DELIVERY_LEASE_MS);
      if (!notification) return;
      if (!notification.recipientEmail) {
        await this.notifications.save({
          ...notification,
          status: 'skipped_no_verified_contact',
          lastError: null,
        });
        return;
      }
      const attempts = notification.attempts + 1;
      try {
        await this.mail.send({
          to: notification.recipientEmail,
          subject: 'GSIO account security notification',
          text:
            `An external identity was ${notification.action} on your GSIO account.\n\n` +
            `Provider: ${notification.providerName}\n` +
            `Identity hint: ${notification.identityHint}\n` +
            `Time: ${new Date(now).toISOString()}\n\n` +
            'If you did not make this change, review your linked identities and secure your account.',
        });
        await this.notifications.save({
          ...notification,
          attempts,
          status: 'sent',
          sentAt: now,
          lastError: null,
        });
        await this.audit.append({
          action: 'identity_security_notification.sent',
          actor: null,
          target: notification.eventKey,
          correlationId: notification.correlationId,
          after: { status: 'sent' },
        });
      } catch {
        await this.notifications.save({
          ...notification,
          attempts,
          status: 'failed',
          lastError: 'delivery_failed',
          nextAttemptAt: now + retryDelayMs(attempts),
        });
        await this.audit.append({
          action: 'identity_security_notification.failed',
          actor: null,
          target: notification.eventKey,
          correlationId: notification.correlationId,
          after: { status: 'failed', attempts },
        });
      }
    });
  }
}

/** Fixed-delay delivery loop (`IdentitySecurityNotificationScheduler`). */
@Container()
export class NotificationWorker {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = false;

  constructor(
    @Component(NOTIFICATIONS) private readonly notifications: NotificationRepository,
    @Component(SecurityNotificationService) private readonly service: SecurityNotificationService,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  /** Delivers up to 50 due notifications, oldest first. Returns how many were attempted. */
  async runOnce(): Promise<number> {
    const ids = await this.notifications.due(this.clock.now(), 50);
    for (const id of ids) await this.service.deliver(id);
    return ids.length;
  }

  /** Runs `runOnce`, then waits `delayMs` after it finishes, until `stop`. Backs off on consecutive errors. */
  start(delayMs: number, onError: (error: unknown) => void = () => {}): void {
    if (this.running) return;
    this.running = true;
    let consecutiveFailures = 0;
    const tick = async () => {
      try {
        await this.runOnce();
        consecutiveFailures = 0;
      } catch (error) {
        consecutiveFailures++;
        onError(error);
      }
      const backoff = Math.min(delayMs * 2 ** Math.min(consecutiveFailures, 5), 60_000);
      if (this.running) this.timer = setTimeout(tick, backoff);
    };
    this.timer = setTimeout(tick, delayMs);
  }

  stop(): void {
    this.running = false;
    clearTimeout(this.timer);
  }
}
