import { evaluatePolicy } from '@di-framework/authz';
import { Component, Container } from '@di-framework/core/decorators';
import { Introspector } from '@di-framework/identity/src/authorization/application/introspector.ts';
import { policyDocument } from '@di-framework/identity/src/shared/application/policies.ts';
// Side-effect import: registers the API policies before the first compile.
import './api-policies.ts';
import { ADMIN_API, DIRECTORY_API } from './api-policies.ts';
import type { TokenCaller } from './request-context.ts';

/** The authz resource and action a path needs, plus the scope OpenAPI documents for it. */
export interface ApiAccess {
  resource: string;
  action: 'read' | 'write';
  scope: string;
}

export function apiAccess(method: string, pathname: string): ApiAccess | undefined {
  if (pathname.startsWith('/api/admin')) {
    return method === 'GET' || method === 'HEAD'
      ? { resource: ADMIN_API, action: 'read', scope: 'admin:read' }
      : { resource: ADMIN_API, action: 'write', scope: 'admin:write' };
  }
  if (pathname.startsWith('/api/v1/organizations')) {
    return { resource: DIRECTORY_API, action: 'read', scope: 'directory:read' };
  }
  return undefined;
}

/** Scope a path requires, or `undefined` when the bearer guard does not apply. */
export function requiredScope(method: string, pathname: string): string | undefined {
  return apiAccess(method, pathname)?.scope;
}

/**
 * Opaque bearer-token resource server for `/api/admin/**` and the directory API
 * (`SecurityConfiguration.applicationSecurity` plus `ApiController.requireScope`). Scope rules
 * are `@di-framework/authz` policies in `api-policies.ts`.
 * Missing or invalid token: 401 with `WWW-Authenticate`. Missing scope: 403. Both bodies empty.
 */
@Container()
export class BearerGuard {
  constructor(@Component(Introspector) private readonly introspector: Introspector) {}

  async authorize(request: Request, access: ApiAccess): Promise<TokenCaller | Response> {
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
    const decision = evaluatePolicy(policyDocument(ADMIN_API, DIRECTORY_API), {
      resource: access.resource,
      action: access.action,
      subject: { id: principal.principalName, roles: [], scopes: principal.scopes, claims: {} },
    });
    if (!decision.allowed) {
      return new Response(null, {
        status: 403,
        headers: {
          'www-authenticate': `Bearer error="insufficient_scope", scope="${access.scope}"`,
        },
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
