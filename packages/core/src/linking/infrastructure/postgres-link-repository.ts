import { Component, Container } from '@di-framework/core/decorators';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import {
  type ColumnCipher,
  ColumnEncryption,
} from '../../shared/infrastructure/column-encryption.ts';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import { type Sql, sql } from '../../shared/infrastructure/sql.ts';
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

function linkColumns(cipher: ColumnCipher): Sql {
  return sql`id::text AS id, user_id::text AS user_id, provider_name,
    ${cipher.read('provider_email', 'provider_email')}, issuer, ${cipher.read('subject', 'subject')},
    created_at, updated_at`;
}

function confirmationColumns(cipher: ColumnCipher): Sql {
  return sql`token_hash, user_id::text AS user_id, session_hash, issuer,
    ${cipher.read('subject', 'subject')}, expires_at`;
}

interface ConfirmationRow {
  token_hash: string;
  user_id: string;
  session_hash: string;
  issuer: string;
  subject: string;
  expires_at: unknown;
}

/**
 * Once column encryption is enabled: `identity_links.subject` is encrypted with a blind index
 * (unique per issuer), `provider_email`, the flow `nonce` and `code_verifier`, and the unlink
 * confirmation `subject` are encrypted. Lookups by subject match the blind index or legacy
 * plaintext.
 */
@Container()
export class PostgresLinkRepository implements LinkRepository {
  constructor(
    @Component(PostgresGateway) private readonly db: PostgresGateway,
    @Component(ColumnEncryption) private readonly encryption: ColumnEncryption,
  ) {}

  async list(userId: string): Promise<IdentityLink[]> {
    const cipher = await this.encryption.cipher();
    const rows = await this.db.query<LinkRow>(
      sql`SELECT ${linkColumns(cipher)} FROM identity_links WHERE user_id = ${userId}
       ORDER BY created_at ASC`,
    );
    return rows.map((row) => this.link(row));
  }

  async find(userId: string, issuer: string, subject: string): Promise<IdentityLink | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<LinkRow>(
      sql`SELECT ${linkColumns(cipher)} FROM identity_links
       WHERE user_id = ${userId} AND issuer = ${issuer}
         AND ${cipher.matches('subject', 'subject_bidx', subject)}`,
    );
    return row ? this.link(row) : undefined;
  }

  async findById(id: string): Promise<IdentityLink | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<LinkRow>(
      sql`SELECT ${linkColumns(cipher)} FROM identity_links WHERE id = ${id}`,
    );
    return row ? this.link(row) : undefined;
  }

  /**
   * `(issuer, subject)` is unique across legacy plaintext rows (V7's constraint) and new rows
   * (`(issuer, subject_bidx)`). A new row is also refused while a legacy row has the same
   * plaintext subject; legacy rows are only ever written before encryption is enabled.
   */
  async insert(link: NewIdentityLink): Promise<IdentityLink> {
    const cipher = await this.encryption.cipher();
    const inserted = await this.db.writeCount(
      sql`INSERT INTO identity_links (id, user_id, issuer, subject, subject_enc, subject_bidx,
         provider_name, provider_email, provider_email_enc)
       SELECT ${link.id}::uuid, ${link.userId}::uuid, ${link.issuer}::varchar,
         ${cipher.plain(link.subject)}::varchar, ${cipher.encrypt(link.subject)}::bytea,
         ${cipher.blindIndex(link.subject)}::bytea, ${link.providerName}::varchar,
         ${cipher.plain(link.providerEmail)}::varchar, ${cipher.encrypt(link.providerEmail)}::bytea
       WHERE NOT EXISTS (
         SELECT 1 FROM identity_links WHERE issuer = ${link.issuer} AND subject = ${link.subject}
       )
       RETURNING 1`,
    );
    if (inserted === 0) throw new IdentityError(409, 'Conflict');
    return (await this.findById(link.id)) as IdentityLink;
  }

  async lockByIdentity(issuer: string, subject: string): Promise<IdentityLink | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<LinkRow>(
      sql`SELECT ${linkColumns(cipher)} FROM identity_links
       WHERE issuer = ${issuer} AND ${cipher.matches('subject', 'subject_bidx', subject)}
       FOR UPDATE`,
    );
    return row ? this.link(row) : undefined;
  }

  async lockForUser(
    userId: string,
    issuer: string,
    subject: string,
  ): Promise<IdentityLink | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<LinkRow>(
      sql`SELECT ${linkColumns(cipher)} FROM identity_links
       WHERE user_id = ${userId} AND issuer = ${issuer}
         AND ${cipher.matches('subject', 'subject_bidx', subject)} FOR UPDATE`,
    );
    return row ? this.link(row) : undefined;
  }

  async latestConfirmation(
    userId: string,
    sessionHash: string,
  ): Promise<UnlinkConfirmation | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<ConfirmationRow>(
      sql`SELECT ${confirmationColumns(cipher)}
       FROM identity_unlink_confirmations WHERE user_id = ${userId} AND session_hash = ${sessionHash}
       ORDER BY created_at DESC LIMIT 1`,
    );
    return row ? this.confirmation(row) : undefined;
  }

  async insertFlow(flow: LinkFlow): Promise<void> {
    const cipher = await this.encryption.cipher();
    return this.db.write(
      sql`INSERT INTO identity_link_flows (token_hash, user_id, session_hash, provider_name, issuer,
         nonce, nonce_enc, code_verifier, code_verifier_enc, code_challenge, return_url, created_at,
         expires_at)
       VALUES (${flow.tokenHash}, ${flow.userId}, ${flow.sessionHash}, ${flow.providerName},
         ${flow.issuer}, ${cipher.plain(flow.nonce)}, ${cipher.encrypt(flow.nonce)},
         ${cipher.plain(flow.codeVerifier)}, ${cipher.encrypt(flow.codeVerifier)},
         ${flow.codeChallenge}, ${flow.returnUrl}, ${new Date(flow.createdAt)},
         ${new Date(flow.expiresAt)})`,
    );
  }

  async takeFlow(tokenHash: string): Promise<LinkFlow | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<FlowRow>(
      sql`DELETE FROM identity_link_flows WHERE token_hash = ${tokenHash}
       RETURNING token_hash, user_id::text AS user_id, session_hash, provider_name, issuer,
         ${cipher.read('nonce', 'nonce')}, ${cipher.read('code_verifier', 'code_verifier')},
         code_challenge, return_url, created_at, expires_at`,
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

  delete(id: string): Promise<void> {
    return this.db.write(`DELETE FROM identity_links WHERE id = ?`, [id]);
  }

  async deleteUnlessLastMethod(id: string): Promise<boolean> {
    const result = await this.db.run(
      `DELETE FROM identity_links AS l
       USING users AS u
       WHERE l.id = ? AND u.id = l.user_id
         AND (COALESCE(btrim(u.password_hash), '') <> ''
              OR (u.email_verified
                  AND (COALESCE(btrim(u.email), '') <> '' OR u.email_enc IS NOT NULL))
              OR (SELECT count(*) FROM (
                    SELECT 1 FROM identity_links AS x
                    WHERE x.user_id = l.user_id
                    ORDER BY x.id FOR UPDATE
                  ) AS links) > 1)
       RETURNING 1`,
      [id],
    );
    return (result.changes ?? 0) > 0;
  }

  async insertConfirmation(confirmation: NewConfirmation): Promise<void> {
    const cipher = await this.encryption.cipher();
    return this.db.write(
      sql`INSERT INTO identity_unlink_confirmations (
         token_hash, user_id, session_hash, issuer, subject, subject_enc, created_at, expires_at
       ) VALUES (${confirmation.tokenHash}, ${confirmation.userId}, ${confirmation.sessionHash},
         ${confirmation.issuer}, ${cipher.plain(confirmation.subject)},
         ${cipher.encrypt(confirmation.subject)}, now(), ${confirmation.expiresAt})`,
    );
  }

  async takeConfirmation(tokenHash: string): Promise<UnlinkConfirmation | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<ConfirmationRow>(
      sql`DELETE FROM identity_unlink_confirmations WHERE token_hash = ${tokenHash}
       RETURNING ${confirmationColumns(cipher)}`,
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
