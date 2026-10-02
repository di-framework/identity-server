import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import type { LinkRepository, NewConfirmation } from '../domain/identity-link.ts';
import { IdentityLink, UnlinkConfirmation } from '../domain/identity-link.ts';

interface LinkRow {
  id: string;
  provider_name: string;
  issuer: string;
  subject: string;
  created_at: unknown;
  updated_at: unknown;
}

interface ConfirmationRow {
  token_hash: string;
  user_id: string;
  session_hash: string;
  issuer: string;
  subject: string;
  expires_at: unknown;
}

@Container()
export class PostgresLinkRepository implements LinkRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  async list(userId: string): Promise<IdentityLink[]> {
    const rows = await this.db.query<LinkRow>(
      `SELECT id::text AS id, provider_name, issuer, subject, created_at, updated_at
       FROM identity_links WHERE user_id = ? ORDER BY created_at ASC`,
      [userId],
    );
    return rows.map((row) => this.link(row));
  }

  async find(userId: string, issuer: string, subject: string): Promise<IdentityLink | undefined> {
    const row = await this.db.one<LinkRow>(
      `SELECT id::text AS id, provider_name, issuer, subject, created_at, updated_at
       FROM identity_links WHERE user_id = ? AND issuer = ? AND subject = ?`,
      [userId, issuer, subject],
    );
    return row ? this.link(row) : undefined;
  }

  countOther(userId: string, linkId: string): Promise<number> {
    return this.db.count(
      `SELECT count(*)::int AS count FROM identity_links WHERE user_id = ? AND id <> ?`,
      [userId, linkId],
    );
  }

  delete(id: string): Promise<void> {
    return this.db.write(`DELETE FROM identity_links WHERE id = ?`, [id]);
  }

  insertConfirmation(confirmation: NewConfirmation): Promise<void> {
    return this.db.write(
      `INSERT INTO identity_unlink_confirmations (
         token_hash, user_id, session_hash, issuer, subject, created_at, expires_at
       ) VALUES (?, ?, ?, ?, ?, now(), ?)`,
      [
        confirmation.tokenHash,
        confirmation.userId,
        confirmation.sessionHash,
        confirmation.issuer,
        confirmation.subject,
        confirmation.expiresAt,
      ],
    );
  }

  async findConfirmation(tokenHash: string): Promise<UnlinkConfirmation | undefined> {
    const row = await this.db.one<ConfirmationRow>(
      `SELECT token_hash, user_id::text AS user_id, session_hash, issuer, subject, expires_at
       FROM identity_unlink_confirmations WHERE token_hash = ?`,
      [tokenHash],
    );
    if (!row) return undefined;
    return new UnlinkConfirmation(
      row.token_hash,
      String(row.user_id),
      row.session_hash,
      row.issuer,
      row.subject,
      new Date(row.expires_at as string | Date).getTime(),
    );
  }

  deleteConfirmation(tokenHash: string): Promise<void> {
    return this.db.write(`DELETE FROM identity_unlink_confirmations WHERE token_hash = ?`, [
      tokenHash,
    ]);
  }

  private link(row: LinkRow): IdentityLink {
    return new IdentityLink(
      String(row.id),
      row.provider_name,
      row.issuer,
      row.subject,
      Timestamps.iso(row.created_at),
      Timestamps.iso(row.updated_at),
    );
  }
}
