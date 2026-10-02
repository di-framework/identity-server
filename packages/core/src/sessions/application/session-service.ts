import { Component, Container } from '@di-framework/core/decorators';
import type { Clock } from '../../shared/domain/clock.ts';
import { CLOCK, SESSIONS } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import type { BrowserSession, SessionRepository } from '../domain/session.ts';

/** Servlet session idle timeout in the auth server's `application.yml`. */
export const SESSION_IDLE_MS = 30 * 60 * 1000;

/** A session plus the cookie value that identifies it. Only the hash is stored. */
export interface ActiveSession {
  token: string;
  session: BrowserSession;
}

/** Postgres-backed browser sessions with a 30-minute idle timeout and a per-session CSRF token. */
@Container()
export class SessionService {
  constructor(
    @Component(SESSIONS) private readonly sessions: SessionRepository,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  async start(): Promise<ActiveSession> {
    const token = Hashing.token();
    const now = this.clock.now();
    const session: BrowserSession = {
      id: Hashing.sha256Hex(token),
      userId: null,
      csrf: Hashing.token(),
      lastAuthenticatedAt: null,
      attributes: {},
      expiresAt: now + SESSION_IDLE_MS,
    };
    await this.sessions.insert(session, now);
    return { token, session };
  }

  /** The live session for a cookie value, with its idle timer reset; expired ones are removed. */
  async resolve(token: string | undefined): Promise<ActiveSession | undefined> {
    if (!token) return undefined;
    const found = await this.sessions.find(Hashing.sha256Hex(token));
    if (!found) return undefined;
    const now = this.clock.now();
    if (found.expiresAt <= now) {
      await this.sessions.delete(found.id);
      return undefined;
    }
    const session = { ...found, expiresAt: now + SESSION_IDLE_MS };
    await this.sessions.update(session, now);
    return { token, session };
  }

  /**
   * Records a successful sign-in. `rotate` issues a new cookie value and CSRF token, as Spring's
   * form login does; passwordless confirmation keeps the session id, as the auth server does.
   */
  async signIn(current: ActiveSession, userId: string, rotate: boolean): Promise<ActiveSession> {
    const now = this.clock.now();
    const base = {
      ...current.session,
      userId,
      lastAuthenticatedAt: now,
      expiresAt: now + SESSION_IDLE_MS,
    };
    if (!rotate) {
      await this.sessions.update(base, now);
      return { token: current.token, session: base };
    }
    const token = Hashing.token();
    const session = { ...base, id: Hashing.sha256Hex(token), csrf: Hashing.token() };
    await this.sessions.rename(current.session.id, session, now);
    return { token, session };
  }

  async setAttribute(
    current: ActiveSession,
    name: string,
    value: string | null,
  ): Promise<ActiveSession> {
    const attributes = { ...current.session.attributes };
    if (value === null) delete attributes[name];
    else attributes[name] = value;
    const session = { ...current.session, attributes };
    await this.sessions.update(session, this.clock.now());
    return { token: current.token, session };
  }

  destroy(current: ActiveSession): Promise<void> {
    return this.sessions.delete(current.session.id);
  }

  purgeExpired(): Promise<number> {
    return this.sessions.deleteExpired(this.clock.now());
  }

  /** CSRF check for state-changing browser forms. */
  csrfMatches(current: ActiveSession, submitted: string | null | undefined): boolean {
    return typeof submitted === 'string' && Hashing.equal(submitted, current.session.csrf);
  }
}
