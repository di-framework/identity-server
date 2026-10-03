import { Component, Container } from '@di-framework/core/decorators';
import { ClientAuthenticator } from '@di-framework/identity/src/authorization/application/client-authenticator.ts';
import { Introspector } from '@di-framework/identity/src/authorization/application/introspector.ts';
import { ServerMetadata } from '@di-framework/identity/src/authorization/application/server-metadata.ts';
import { TokenService } from '@di-framework/identity/src/authorization/application/token-service.ts';
import { OAuthError } from '@di-framework/identity/src/authorization/domain/models.ts';

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' };

/**
 * Public OAuth 2 endpoints that need no browser session: token, introspection, revocation,
 * JWKS, and discovery. Form-encoded and redirect-based, so they are not codegen manifests
 * (auth-server's OpenAPI document omits them as well).
 */
@Container()
export class AuthorizationEndpoints {
  private readonly routes: Record<
    string,
    { method: string; handle: (request: Request) => Promise<Response> }
  > = {
    '/oauth2/token': { method: 'POST', handle: (request) => this.token(request) },
    '/oauth2/introspect': { method: 'POST', handle: (request) => this.introspect(request) },
    '/oauth2/revoke': { method: 'POST', handle: (request) => this.revoke(request) },
    '/oauth2/jwks': { method: 'GET', handle: async () => json(this.metadata.jwks()) },
    '/.well-known/openid-configuration': {
      method: 'GET',
      handle: async () => json(this.metadata.openidConfiguration()),
    },
    '/.well-known/oauth-authorization-server': {
      method: 'GET',
      handle: async () => json(this.metadata.authorizationServer()),
    },
  };

  constructor(
    @Component(ClientAuthenticator) private readonly clients: ClientAuthenticator,
    @Component(TokenService) private readonly tokens: TokenService,
    @Component(Introspector) private readonly introspector: Introspector,
    @Component(ServerMetadata) private readonly metadata: ServerMetadata,
  ) {}

  handles(pathname: string): boolean {
    return pathname in this.routes;
  }

  async fetch(request: Request): Promise<Response> {
    const route = this.routes[new URL(request.url).pathname];
    if (!route) return new Response(null, { status: 404 });
    if (request.method !== route.method) {
      return new Response(null, { status: 405, headers: { allow: route.method } });
    }
    try {
      return await route.handle(request);
    } catch (error) {
      if (error instanceof OAuthError) {
        return json({ error: error.code }, error.status, NO_STORE);
      }
      return new Response(null, { status: 500 });
    }
  }

  private async token(request: Request): Promise<Response> {
    const form = await this.form(request);
    const client = await this.clients.authenticate(request.headers.get('authorization'), form);
    return json(await this.tokens.exchange(client, form), 200, NO_STORE);
  }

  private async introspect(request: Request): Promise<Response> {
    const form = await this.form(request);
    const client = await this.clients.authenticate(request.headers.get('authorization'), form);
    return json(
      await this.introspector.introspect(client, this.required(form, 'token')),
      200,
      NO_STORE,
    );
  }

  private async revoke(request: Request): Promise<Response> {
    const form = await this.form(request);
    const client = await this.clients.authenticate(request.headers.get('authorization'), form);
    await this.introspector.revoke(client, this.required(form, 'token'));
    return new Response(null, { status: 200, headers: NO_STORE });
  }

  private async form(request: Request): Promise<URLSearchParams> {
    const type = request.headers.get('content-type') ?? '';
    if (!type.startsWith('application/x-www-form-urlencoded')) {
      throw new OAuthError('invalid_request');
    }
    return new URLSearchParams(await request.text());
  }

  private required(form: URLSearchParams, name: string): string {
    const value = form.get(name);
    if (!value) throw new OAuthError('invalid_request');
    return value;
  }
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}
