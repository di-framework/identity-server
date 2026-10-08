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
  /**
   * Inserts the challenge unless one for its email and purpose was created after `since`, in
   * one statement. True when the row was inserted.
   */
  insertUnlessRecent(challenge: EmailChallenge, now: number, since: number): Promise<boolean>;
  /** Finds by token hash with `FOR UPDATE`; call inside a transaction. */
  lockByHash(tokenHash: string): Promise<EmailChallenge | undefined>;
  /**
   * Consumes an unconsumed, unexpired challenge in one statement. False when it was already
   * consumed, so a token is single-use even when two requests present it at once.
   */
  claim(id: string, now: number): Promise<boolean>;
  markConsumed(id: string, now: number): Promise<void>;
}
