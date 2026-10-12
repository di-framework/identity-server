import { Component, Container } from '@di-framework/core/decorators';
import { ColumnEncryption } from '../../shared/infrastructure/column-encryption.ts';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import { sql } from '../../shared/infrastructure/sql.ts';
import type {
  NotificationAction,
  NotificationRepository,
  NotificationStatus,
  SecurityNotification,
} from '../domain/notification.ts';

interface Row {
  id: string;
  event_key: string;
  user_id: string;
  action: NotificationAction;
  recipient_email: string | null;
  provider_name: string;
  issuer: string;
  identity_hint: string;
  correlation_id: string | null;
  status: NotificationStatus;
  attempts: number;
  next_attempt_at: unknown;
  created_at: unknown;
  sent_at: unknown;
  last_error: string | null;
}

/** `recipient_email` is encrypted once column encryption is enabled. */
@Container()
export class PostgresNotificationRepository implements NotificationRepository {
  constructor(
    @Component(PostgresGateway) private readonly db: PostgresGateway,
    @Component(ColumnEncryption) private readonly encryption: ColumnEncryption,
  ) {}

  async insertIfAbsent(n: SecurityNotification): Promise<boolean> {
    const cipher = await this.encryption.cipher();
    const result = await this.db.run(
      sql`INSERT INTO identity_security_notifications (id, event_key, user_id, action, recipient_email,
         recipient_email_enc, provider_name, issuer, identity_hint, correlation_id, status, attempts,
         next_attempt_at, created_at, sent_at, last_error)
       VALUES (${n.id}, ${n.eventKey}, ${n.userId}, ${n.action}, ${cipher.plain(n.recipientEmail)},
         ${cipher.encrypt(n.recipientEmail)}, ${n.providerName}, ${n.issuer}, ${n.identityHint},
         ${n.correlationId}, ${n.status}, ${n.attempts}, ${new Date(n.nextAttemptAt)},
         ${new Date(n.createdAt)}, ${n.sentAt == null ? null : new Date(n.sentAt)}, ${n.lastError})
       ON CONFLICT (event_key) DO NOTHING
       RETURNING 1`,
    );
    return (result.changes ?? 0) > 0;
  }

  async claim(id: string, now: number, until: number): Promise<SecurityNotification | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<Row>(
      sql`UPDATE identity_security_notifications SET next_attempt_at = ${new Date(until)}
       WHERE id = ${id} AND status IN ('pending', 'failed') AND next_attempt_at <= ${new Date(now)}
       RETURNING id::text AS id, event_key, user_id::text AS user_id, action,
         ${cipher.read('recipient_email', 'recipient_email')}, provider_name, issuer,
         identity_hint, correlation_id, status, attempts, next_attempt_at, created_at, sent_at,
         last_error`,
    );
    if (!row) return undefined;
    return {
      id: row.id,
      eventKey: row.event_key,
      userId: row.user_id,
      action: row.action,
      recipientEmail: row.recipient_email,
      providerName: row.provider_name,
      issuer: row.issuer,
      identityHint: row.identity_hint,
      correlationId: row.correlation_id,
      status: row.status,
      attempts: row.attempts,
      nextAttemptAt: Timestamps.ms(row.next_attempt_at),
      createdAt: Timestamps.ms(row.created_at),
      sentAt: row.sent_at == null ? null : Timestamps.ms(row.sent_at),
      lastError: row.last_error,
    };
  }

  save(n: SecurityNotification): Promise<void> {
    return this.db.write(
      `UPDATE identity_security_notifications
       SET status = ?, attempts = ?, next_attempt_at = ?, sent_at = ?, last_error = ?
       WHERE id = ?`,
      [
        n.status,
        n.attempts,
        new Date(n.nextAttemptAt),
        n.sentAt == null ? null : new Date(n.sentAt),
        n.lastError,
        n.id,
      ],
    );
  }

  async due(now: number, limit: number): Promise<string[]> {
    const rows = await this.db.query<{ id: string }>(
      `SELECT id::text AS id FROM identity_security_notifications
       WHERE status IN ('pending', 'failed') AND next_attempt_at < ?
       ORDER BY created_at LIMIT ?`,
      [new Date(now), limit],
    );
    return rows.map((row) => row.id);
  }
}
