export type NotificationAction = 'linked' | 'unlinked';
export type NotificationStatus = 'pending' | 'failed' | 'sent' | 'skipped_no_verified_contact';

/** One `identity_security_notifications` outbox row. */
export interface SecurityNotification {
  id: string;
  eventKey: string;
  userId: string;
  action: NotificationAction;
  recipientEmail: string | null;
  providerName: string;
  issuer: string;
  identityHint: string;
  correlationId: string | null;
  status: NotificationStatus;
  attempts: number;
  nextAttemptAt: number;
  createdAt: number;
  sentAt: number | null;
  lastError: string | null;
}

export interface NotificationRepository {
  /** `ON CONFLICT (event_key) DO NOTHING`; true when a row was inserted. */
  insertIfAbsent(notification: SecurityNotification): Promise<boolean>;
  /**
   * Takes a due pending or failed row for delivery by moving its next attempt to `until`, in
   * one statement, so two workers never send the same mail. Undefined when the row is not due,
   * already taken, or in another status. The lease lapses if the outcome is never saved.
   */
  claim(id: string, now: number, until: number): Promise<SecurityNotification | undefined>;
  save(notification: SecurityNotification): Promise<void>;
  /** Ids of the oldest 50 pending or failed rows whose next attempt is due. */
  due(now: number, limit: number): Promise<string[]>;
}
