import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import type { BrowserSession, SessionRepository } from '../domain/session.ts';

interface Row {
  id: string;
  user_id: string | null;
  csrf_token: string;
  last_authenticated_at: unknown;
  attributes: Record<string, string>;
  expires_at: unknown;
}

@Container()
export class PostgresSessionRepository implements SessionRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  insert(session: BrowserSession, now: number): Promise<void> {
    return this.db.write(
      `INSERT INTO browser_sessions (id, user_id, csrf_token, last_authenticated_at, attributes,
         created_at, last_seen_at, expires_at)
       VALUES (?, ?, ?, ?, ?::text::jsonb, ?, ?, ?)`,
      [...this.values(session), new Date(now), new Date(now), new Date(session.expiresAt)],
    );
  }

  async find(id: string): Promise<BrowserSession | undefined> {
    const row = await this.db.one<Row>(
      `SELECT id, user_id::text AS user_id, csrf_token, last_authenticated_at, attributes, expires_at
       FROM browser_sessions WHERE id = ?`,
      [id],
    );
    if (!row) return undefined;
    return {
      id: row.id,
      userId: row.user_id,
      csrf: row.csrf_token,
      lastAuthenticatedAt:
        row.last_authenticated_at == null ? null : Timestamps.ms(row.last_authenticated_at),
      attributes: row.attributes,
      expiresAt: Timestamps.ms(row.expires_at),
    };
  }

  update(session: BrowserSession, now: number): Promise<void> {
    return this.db.write(
      `UPDATE browser_sessions SET user_id = ?, csrf_token = ?, last_authenticated_at = ?,
         attributes = ?::text::jsonb, last_seen_at = ?, expires_at = ?
       WHERE id = ?`,
      [...this.values(session).slice(1), new Date(now), new Date(session.expiresAt), session.id],
    );
  }

  rename(oldId: string, session: BrowserSession, now: number): Promise<void> {
    return this.db.write(
      `UPDATE browser_sessions SET id = ?, user_id = ?, csrf_token = ?, last_authenticated_at = ?,
         attributes = ?::text::jsonb, last_seen_at = ?, expires_at = ?
       WHERE id = ?`,
      [...this.values(session), new Date(now), new Date(session.expiresAt), oldId],
    );
  }

  delete(id: string): Promise<void> {
    return this.db.write(`DELETE FROM browser_sessions WHERE id = ?`, [id]);
  }

  async deleteExpired(now: number): Promise<number> {
    const result = await this.db.run(
      `DELETE FROM browser_sessions WHERE expires_at <= ? RETURNING 1`,
      [new Date(now)],
    );
    return result.changes ?? 0;
  }

  private values(session: BrowserSession): unknown[] {
    return [
      session.id,
      session.userId,
      session.csrf,
      session.lastAuthenticatedAt == null ? null : new Date(session.lastAuthenticatedAt),
      JSON.stringify(session.attributes),
    ];
  }
}
