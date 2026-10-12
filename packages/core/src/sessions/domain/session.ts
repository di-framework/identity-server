/** Browser session cookie (HttpOnly, `Secure` per settings, SameSite=Lax). */
export const SESSION_COOKIE = 'identity_session';

/**
 * Session attribute names. The link and unlink entries hold only the SHA-256 hex of their tokens,
 * never a raw token that could complete the flow (#54); the names differ from the auth server's
 * raw-token attributes, which `V17__clear_session_secrets.sql` removes from existing rows.
 */
export const SESSION_ATTRIBUTES = {
  pendingLink: 'GSIO_IDENTITY_LINK_PENDING_TOKEN_HASH',
  unlinkConfirmation: 'GSIO_IDENTITY_UNLINK_CONFIRMATION_TOKEN_HASH',
  savedRequest: 'SPRING_SECURITY_SAVED_REQUEST',
} as const;

export interface BrowserSession {
  /** SHA-256 hex of the cookie value. */
  id: string;
  userId: string | null;
  csrf: string;
  /** `GSIO_LAST_AUTHENTICATED_AT`: epoch ms of the last password or passwordless sign-in. */
  lastAuthenticatedAt: number | null;
  attributes: Record<string, string>;
  createdAt?: number;
  expiresAt: number;
}

export interface SessionRepository {
  insert(session: BrowserSession, now: number): Promise<void>;
  find(id: string): Promise<BrowserSession | undefined>;
  update(session: BrowserSession, now: number): Promise<void>;
  /** Moves a session to a new id (session fixation protection on sign-in). */
  rename(oldId: string, session: BrowserSession, now: number): Promise<void>;
  delete(id: string): Promise<void>;
  deleteExpired(now: number): Promise<number>;
}
