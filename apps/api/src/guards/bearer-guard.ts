import { Component, Container } from '@di-framework/core/decorators';
import { Introspector } from '@di-framework/identity/src/authorization/application/introspector.ts';
import type { TokenCaller } from './request-context.ts';

/** Scope a path requires, or `undefined` when the bearer guard does not apply. */
export function requiredScope(method: string, pathname: string): string | undefined {
  if (pathname.startsWith('/api/admin')) {
    return method === 'GET' || method === 'HEAD' ? 'admin:read' : 'admin:write';
  }
  if (pathname.startsWith('/api/v1/organizations')) return 'directory:read';
  return undefined;
}

/**
 * Opaque bearer-token resource server for `/api/admin/**` and the directory API
 * (`SecurityConfiguration.applicationSecurity` plus `ApiController.requireScope`).
 * Missing or invalid token: 401 with `WWW-Authenticate`. Missing scope: 403. Both bodies empty.
 */
@Container()
export class BearerGuard {
  constructor(@Component(Introspector) private readonly introspector: Introspector) {}

  async authorize(request: Request, scope: string): Promise<TokenCaller | Response> {
    const header = request.headers.get('authorization') ?? '';
    const match = /^Bearer\s+(\S+)$/i.exec(header);
    if (!match?.[1]) {
      return new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer' } });
    }
    const principal = await this.introspector.accessToken(match[1]);
    if (!principal) {
      return new Response(null, {
        status: 401,
        headers: { 'www-authenticate': 'Bearer error="invalid_token"' },
      });
    }
    if (!principal.scopes.includes(scope)) {
      return new Response(null, {
        status: 403,
        headers: { 'www-authenticate': `Bearer error="insufficient_scope", scope="${scope}"` },
      });
    }
    return {
      kind: 'token',
      principalName: principal.principalName,
      clientId: principal.clientId,
      scopes: principal.scopes,
    };
  }
}
