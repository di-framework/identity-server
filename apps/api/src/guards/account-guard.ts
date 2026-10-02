import { Component, Container } from '@di-framework/core/decorators';
import { Introspector } from '@di-framework/identity/src/authorization/application/introspector.ts';
import { SessionService } from '@di-framework/identity/src/sessions/application/session-service.ts';
import { SESSION_COOKIE } from '@di-framework/identity/src/sessions/domain/session.ts';
import type { Caller } from './request-context.ts';

/** Reads one cookie value from a `Cookie` header. */
export function cookieValue(header: string | null, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) return part.slice(separator + 1).trim();
  }
  return undefined;
}

/**
 * `/api/v1/account/**` callers: a browser session cookie, or an opaque bearer token whose
 * principal is a user. The auth server authenticates these routes the same two ways; a bearer
 * caller has no session, so it can list links but cannot pass the unlink step-up.
 */
@Container()
export class AccountGuard {
  constructor(
    @Component(SessionService) private readonly sessions: SessionService,
    @Component(Introspector) private readonly introspector: Introspector,
  ) {}

  async authorize(request: Request): Promise<Caller | Response> {
    const authorization = request.headers.get('authorization');
    if (authorization) {
      const match = /^Bearer\s+(\S+)$/i.exec(authorization);
      const principal = match?.[1] ? await this.introspector.accessToken(match[1]) : undefined;
      if (!principal) {
        return new Response(null, {
          status: 401,
          headers: { 'www-authenticate': 'Bearer error="invalid_token"' },
        });
      }
      return {
        kind: 'token',
        principalName: principal.principalName,
        clientId: principal.clientId,
        scopes: principal.scopes,
      };
    }
    const active = await this.sessions.resolve(
      cookieValue(request.headers.get('cookie'), SESSION_COOKIE),
    );
    if (!active?.session.userId) {
      return new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer' } });
    }
    return {
      kind: 'session',
      principalName: active.session.userId,
      sessionId: active.session.id,
      lastAuthenticatedAt: active.session.lastAuthenticatedAt,
    };
  }
}
