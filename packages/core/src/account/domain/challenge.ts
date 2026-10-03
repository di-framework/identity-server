export type ChallengePurpose = 'sign_in' | 'activation' | 'invite';

/** An `email_challenges` row. Only the SHA-256 of the token is stored. */
export interface EmailChallenge {
  id: string;
  userId: string | null;
  email: string;
  tokenHash: string;
  purpose: ChallengePurpose;
  expiresAt: number;
  consumedAt: number | null;
}

export interface ChallengeRepository {
  /** Serializes issuance for one email and purpose until the current transaction ends. */
  lockIssuance(email: string, purpose: ChallengePurpose): Promise<void>;
  countSince(email: string, purpose: ChallengePurpose, since: number): Promise<number>;
  insert(challenge: EmailChallenge, now: number): Promise<void>;
  /** Finds by token hash with `FOR UPDATE`; call inside a transaction. */
  lockByHash(tokenHash: string): Promise<EmailChallenge | undefined>;
  markConsumed(id: string, now: number): Promise<void>;
}
