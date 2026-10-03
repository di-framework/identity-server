import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import type {
  LinkFlow,
  LinkRepository,
  NewConfirmation,
  NewIdentityLink,
} from '../domain/identity-link.ts';
import { IdentityLink, UnlinkConfirmation } from '../domain/identity-link.ts';

interface LinkRow {
  id: string;
  user_id: string;
  provider_name: string;
  provider_email: string | null;
  issuer: string;
  subject: string;
  created_at: unknown;
  updated_at: unknown;
}

interface FlowRow {
  token_hash: string;
  user_id: string;
  session_hash: string;
  provider_name: string;
  issuer: string;
  nonce: string;
  code_verifier: string;
  code_challenge: string;
  return_url: string;
  created_at: unknown;
  expires_at: unknown;
}

const LINK_COLUMNS = `id::text AS id, user_id::text AS user_id, provider_name, provider_email, issuer,
  subject, created_at, updated_at`;

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
      `SELECT ${LINK_COLUMNS} FROM identity_links WHERE user_id = ? ORDER BY created_at ASC`,
      [userId],
    );
    return rows.map((row) => this.link(row));
  }

  async find(userId: string, issuer: string, subject: string): Promise<IdentityLink | undefined> {
    const row = await this.db.one<LinkRow>(
      `SELECT ${LINK_COLUMNS} FROM identity_links WHERE user_id = ? AND issuer = ? AND subject = ?`,
      [userId, issuer, subject],
    );
    return row ? this.link(row) : undefined;
  }

  async findById(id: string): Promise<IdentityLink | undefined> {
    const row = await this.db.one<LinkRow>(
      `SELECT ${LINK_COLUMNS} FROM identity_links WHERE id = ?`,
      [id],
    );
    return row ? this.link(row) : undefined;
  }

  async insert(link: NewIdentityLink): Promise<IdentityLink> {
    await this.db.write(
      `INSERT INTO identity_links (id, user_id, issuer, subject, provider_name, provider_email)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [link.id, link.userId, link.issuer, link.subject, link.providerName, link.providerEmail],
    );
    return (await this.findById(link.id)) as IdentityLink;
  }

  async lockByIdentity(issuer: string, subject: string): Promise<IdentityLink | undefined> {
    const row = await this.db.one<LinkRow>(
      `SELECT ${LINK_COLUMNS} FROM identity_links WHERE issuer = ? AND subject = ? FOR UPDATE`,
      [issuer, subject],
    );
    return row ? this.link(row) : undefined;
  }

  async lockForUser(
    userId: string,
    issuer: string,
    subject: string,
  ): Promise<IdentityLink | undefined> {
    const row = await this.db.one<LinkRow>(
      `SELECT ${LINK_COLUMNS} FROM identity_links
       WHERE user_id = ? AND issuer = ? AND subject = ? FOR UPDATE`,
      [userId, issuer, subject],
    );
    return row ? this.link(row) : undefined;
  }

  async latestConfirmation(
    userId: string,
    sessionHash: string,
  ): Promise<UnlinkConfirmation | undefined> {
    const row = await this.db.one<ConfirmationRow>(
      `SELECT token_hash, user_id::text AS user_id, session_hash, issuer, subject, expires_at
       FROM identity_unlink_confirmations WHERE user_id = ? AND session_hash = ?
       ORDER BY created_at DESC LIMIT 1`,
      [userId, sessionHash],
    );
    return row ? this.confirmation(row) : undefined;
  }

  insertFlow(flow: LinkFlow): Promise<void> {
    return this.db.write(
      `INSERT INTO identity_link_flows (token_hash, user_id, session_hash, provider_name, issuer, nonce,
         code_verifier, code_challenge, return_url, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        flow.tokenHash,
        flow.userId,
        flow.sessionHash,
        flow.providerName,
        flow.issuer,
        flow.nonce,
        flow.codeVerifier,
        flow.codeChallenge,
        flow.returnUrl,
        new Date(flow.createdAt),
        new Date(flow.expiresAt),
      ],
    );
  }

  async takeFlow(tokenHash: string): Promise<LinkFlow | undefined> {
    const row = await this.db.one<FlowRow>(
      `DELETE FROM identity_link_flows WHERE token_hash = ?
       RETURNING token_hash, user_id::text AS user_id, session_hash, provider_name, issuer, nonce,
         code_verifier, code_challenge, return_url, created_at, expires_at`,
      [tokenHash],
    );
    if (!row) return undefined;
    return {
      tokenHash: row.token_hash,
      userId: row.user_id,
      sessionHash: row.session_hash,
      providerName: row.provider_name,
      issuer: row.issuer,
      nonce: row.nonce,
      codeVerifier: row.code_verifier,
      codeChallenge: row.code_challenge,
      returnUrl: row.return_url,
      createdAt: Timestamps.ms(row.created_at),
      expiresAt: Timestamps.ms(row.expires_at),
    };
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
    return row ? this.confirmation(row) : undefined;
  }

  private confirmation(row: ConfirmationRow): UnlinkConfirmation {
    return new UnlinkConfirmation(
      row.token_hash,
      String(row.user_id),
      row.session_hash,
      row.issuer,
      row.subject,
      Timestamps.ms(row.expires_at),
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
      row.user_id,
      row.provider_email,
    );
  }
}
