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

  countSince(email: string, purpose: ChallengePurpose, since: number): Promise<number> {
    return this.db.count(
      `SELECT count(*)::int AS count FROM email_challenges
       WHERE email = ? AND purpose = ? AND created_at > ?`,
      [email, purpose, new Date(since)],
    );
  }

  insert(challenge: EmailChallenge, now: number): Promise<void> {
    return this.db.write(
      `INSERT INTO email_challenges (id, user_id, email, token_hash, purpose, expires_at, consumed_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        challenge.id,
        challenge.userId,
        challenge.email,
        challenge.tokenHash,
        challenge.purpose,
        new Date(challenge.expiresAt),
        challenge.consumedAt == null ? null : new Date(challenge.consumedAt),
        new Date(now),
      ],
    );
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

  markConsumed(id: string, now: number): Promise<void> {
    return this.db.write(`UPDATE email_challenges SET consumed_at = ? WHERE id = ?`, [
      new Date(now),
      id,
    ]);
  }
}
