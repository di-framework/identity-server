import { Component, Container } from '@di-framework/core/decorators';
import { ColumnEncryption } from '../../shared/infrastructure/column-encryption.ts';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import { Sql, sql } from '../../shared/infrastructure/sql.ts';
import type { BrowserSession, SessionRepository } from '../domain/session.ts';

interface Row {
  id: string;
  user_id: string | null;
  csrf_token: string;
  last_authenticated_at: unknown;
  attributes: string;
  created_at: unknown;
  expires_at: unknown;
}

/** `attributes` is encrypted once column encryption is enabled (V18). */
@Container()
export class PostgresSessionRepository implements SessionRepository {
  constructor(
    @Component(PostgresGateway) private readonly db: PostgresGateway,
    @Component(ColumnEncryption) private readonly encryption: ColumnEncryption,
  ) {}

  async insert(session: BrowserSession, now: number): Promise<void> {
    const columns = await this.columns(session);
    return this.db.write(
      sql`INSERT INTO browser_sessions (${Sql.raw(Object.keys(columns).join(', '))},
         created_at, last_seen_at, expires_at)
       VALUES (${Sql.join(Object.values(columns), ', ')}, ${new Date(session.createdAt ?? now)},
         ${new Date(now)}, ${new Date(session.expiresAt)})`,
    );
  }

  async find(id: string): Promise<BrowserSession | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<Row>(
      sql`SELECT id, user_id::text AS user_id, csrf_token, last_authenticated_at,
         ${cipher.read('attributes', 'attributes', { json: true })}, created_at, expires_at
       FROM browser_sessions WHERE id = ${id}`,
    );
    if (!row) return undefined;
    return {
      id: row.id,
      userId: row.user_id,
      csrf: row.csrf_token,
      lastAuthenticatedAt:
        row.last_authenticated_at == null ? null : Timestamps.ms(row.last_authenticated_at),
      attributes: JSON.parse(row.attributes) as Record<string, string>,
      createdAt: row.created_at == null ? undefined : Timestamps.ms(row.created_at),
      expiresAt: Timestamps.ms(row.expires_at),
    };
  }

  async update(session: BrowserSession, now: number): Promise<void> {
    const { id: _id, ...columns } = await this.columns(session);
    return this.db.write(
      sql`UPDATE browser_sessions SET ${assignments(columns)}, last_seen_at = ${new Date(now)},
         expires_at = ${new Date(session.expiresAt)}
       WHERE id = ${session.id}`,
    );
  }

  async rename(oldId: string, session: BrowserSession, now: number): Promise<void> {
    const columns = await this.columns(session);
    return this.db.write(
      sql`UPDATE browser_sessions SET ${assignments(columns)}, last_seen_at = ${new Date(now)},
         expires_at = ${new Date(session.expiresAt)}
       WHERE id = ${oldId}`,
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

  /** Column values to write, by column name. */
  private async columns(session: BrowserSession): Promise<Record<string, Sql>> {
    const cipher = await this.encryption.cipher();
    const attributes = JSON.stringify(session.attributes);
    return {
      id: sql`${session.id}`,
      user_id: sql`${session.userId}`,
      csrf_token: sql`${session.csrf}`,
      last_authenticated_at: sql`${
        session.lastAuthenticatedAt == null ? null : new Date(session.lastAuthenticatedAt)
      }`,
      attributes: cipher.plain(attributes, { json: true }),
      attributes_enc: cipher.encrypt(attributes),
    };
  }
}

function assignments(columns: Record<string, Sql>): Sql {
  return Sql.join(
    Object.entries(columns).map(([column, value]) => sql`${Sql.raw(column)} = ${value}`),
    ', ',
  );
}
