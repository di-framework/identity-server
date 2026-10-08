import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
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

@Container()
export class PostgresChallengeRepository implements ChallengeRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

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
    // The select list is cast so the parameter types do not depend on the insert target.
    const result = await this.db.run(
      `INSERT INTO email_challenges (id, user_id, email, token_hash, purpose, expires_at, consumed_at, created_at)
       SELECT ?::uuid, ?::uuid, ?::varchar, ?::varchar, ?::varchar, ?::timestamptz, ?::timestamptz, ?::timestamptz
       WHERE NOT EXISTS (
         SELECT 1 FROM email_challenges WHERE email = ? AND purpose = ? AND created_at > ?
       )
       RETURNING 1`,
      [
        challenge.id,
        challenge.userId,
        challenge.email,
        challenge.tokenHash,
        challenge.purpose,
        new Date(challenge.expiresAt),
        challenge.consumedAt == null ? null : new Date(challenge.consumedAt),
        new Date(now),
        challenge.email,
        challenge.purpose,
        new Date(since),
      ],
    );
    return (result.changes ?? 0) > 0;
  }

  async lockByHash(tokenHash: string): Promise<EmailChallenge | undefined> {
    const row = await this.db.one<Row>(
      `SELECT id::text AS id, user_id::text AS user_id, email, token_hash, purpose, expires_at, consumed_at
       FROM email_challenges WHERE token_hash = ? FOR UPDATE`,
      [tokenHash],
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
