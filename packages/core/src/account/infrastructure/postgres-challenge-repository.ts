import { Component, Container } from '@di-framework/core/decorators';
import { ColumnEncryption } from '../../shared/infrastructure/column-encryption.ts';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import { sql } from '../../shared/infrastructure/sql.ts';
import type { ChallengePurpose, ChallengeRepository, EmailChallenge } from '../domain/challenge.ts';

interface Row {
  id: string;
  user_id: string | null;
  email: string;
  token_hash: string;
  purpose: ChallengePurpose;
  expires_at: unknown;
  consumed_at: unknown;
}

/**
 * `email` is encrypted once column encryption is enabled, with a blind index of the trimmed,
 * lower-cased address for the issuance rate limit.
 */
@Container()
export class PostgresChallengeRepository implements ChallengeRepository {
  constructor(
    @Component(PostgresGateway) private readonly db: PostgresGateway,
    @Component(ColumnEncryption) private readonly encryption: ColumnEncryption,
  ) {}

  async lockIssuance(email: string, purpose: ChallengePurpose): Promise<void> {
    await this.db.query(`SELECT pg_advisory_xact_lock(hashtextextended(?, 0))::text AS locked`, [
      `email_challenges ${purpose} ${email}`,
    ]);
  }

  async insertUnlessRecent(
    challenge: EmailChallenge,
    now: number,
    since: number,
  ): Promise<boolean> {
    const cipher = await this.encryption.cipher();
    const normalized = challenge.email.trim().toLowerCase();
    // The select list is cast so the parameter types do not depend on the insert target.
    const result = await this.db.run(
      sql`INSERT INTO email_challenges (id, user_id, email, email_enc, email_bidx, token_hash, purpose,
         expires_at, consumed_at, created_at)
       SELECT ${challenge.id}::uuid, ${challenge.userId}::uuid,
         ${cipher.plain(challenge.email)}::varchar, ${cipher.encrypt(challenge.email)}::bytea,
         ${cipher.blindIndex(normalized)}::bytea, ${challenge.tokenHash}::varchar,
         ${challenge.purpose}::varchar, ${new Date(challenge.expiresAt)}::timestamptz,
         ${challenge.consumedAt == null ? null : new Date(challenge.consumedAt)}::timestamptz,
         ${new Date(now)}::timestamptz
       WHERE NOT EXISTS (
         SELECT 1 FROM email_challenges
         WHERE ${cipher.matches('email', 'email_bidx', normalized, challenge.email)}
           AND purpose = ${challenge.purpose} AND created_at > ${new Date(since)}
       )
       RETURNING 1`,
    );
    return (result.changes ?? 0) > 0;
  }

  async lockByHash(tokenHash: string): Promise<EmailChallenge | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<Row>(
      sql`SELECT id::text AS id, user_id::text AS user_id, ${cipher.read('email', 'email')},
         token_hash, purpose, expires_at, consumed_at
       FROM email_challenges WHERE token_hash = ${tokenHash} FOR UPDATE`,
    );
    if (!row) return undefined;
    return {
      id: row.id,
      userId: row.user_id,
      email: row.email,
      tokenHash: row.token_hash,
      purpose: row.purpose,
      expiresAt: Timestamps.ms(row.expires_at),
      consumedAt: row.consumed_at == null ? null : Timestamps.ms(row.consumed_at),
    };
  }

  async claim(id: string, now: number): Promise<boolean> {
    const result = await this.db.run(
      `UPDATE email_challenges SET consumed_at = ?
       WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
       RETURNING 1`,
      [new Date(now), id, new Date(now)],
    );
    return (result.changes ?? 0) > 0;
  }

  markConsumed(id: string, now: number): Promise<void> {
    return this.db.write(`UPDATE email_challenges SET consumed_at = ? WHERE id = ?`, [
      new Date(now),
      id,
    ]);
  }
}
