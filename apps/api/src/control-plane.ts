import { useContainer } from '@di-framework/core/container';
import { Component, Container } from '@di-framework/core/decorators';
import { Controller, json } from '@di-framework/http';
import { AuditService } from '@di-framework/identity/src/audit/application/audit-service.ts';
import '@di-framework/identity/src/composition.ts';
import { DirectoryService } from '@di-framework/identity/src/directory/application/directory-service.ts';
import {
  type AccountCaller,
  LinkService,
} from '@di-framework/identity/src/linking/application/link-service.ts';
import { OAuthService } from '@di-framework/identity/src/oauth/application/oauth-service.ts';
import type { ServiceResult } from '@di-framework/identity/src/shared/domain/service-result.ts';
import { AuthorizationEndpoints } from './authorization/endpoints.ts';
import { AccountGuard } from './guards/account-guard.ts';
import { apiAccess, BearerGuard } from './guards/bearer-guard.ts';
import { RequestContext } from './guards/request-context.ts';
import { OperationsEndpoints } from './operations/health.ts';

export interface RouteRequest {
  headers: { get(name: string): string | null };
  content?: unknown;
  params?: Record<string, string | undefined>;
  query?: Record<string, string | string[] | undefined>;
}

export class RequestValues {
  constructor(private readonly request: RouteRequest) {}

  header(name: string): string | undefined {
    const value = this.request.headers.get(name)?.trim();
    if (!value) return undefined;
    return value;
  }

  query(name: string): string | undefined {
    const value = this.request.query?.[name];
    const text = Array.isArray(value) ? value[0] : value;
    if (typeof text !== 'string' || text.trim() === '') return undefined;
    return text.trim();
  }

  param(name: string): string {
    return this.request.params?.[name] ?? '';
  }

  body(): Record<string, unknown> {
    const content = this.request.content;
    if (typeof content !== 'object' || content === null || Array.isArray(content)) return {};
    return content as Record<string, unknown>;
  }

  /** Principal name of the authenticated caller, as the auth server's `authentication.name`. */
  actor(): string {
    return RequestContext.current()?.principalName ?? 'system';
  }
}

/** The signed-in user behind an account route, from the request context. */
function accountCaller(): AccountCaller | undefined {
  const caller = RequestContext.current();
  if (!caller) return undefined;
  return caller.kind === 'session'
    ? {
        userId: caller.principalName,
        sessionId: caller.sessionId,
        lastAuthenticatedAt: caller.lastAuthenticatedAt,
      }
    : { userId: caller.principalName };
}

export class HttpResponse {
  static from(result: ServiceResult<unknown>): Response {
    if (result.body === undefined) return new Response(null, { status: result.status });
    return json(result.body, { status: result.status });
  }
}

@Controller()
export class ControlPlaneController {
  constructor(
    @Component(DirectoryService) private readonly directory: DirectoryService,
    @Component(OAuthService) private readonly oauth: OAuthService,
    @Component(AuditService) private readonly records: AuditService,
    @Component(LinkService) private readonly links: LinkService,
  ) {}

  dispatch(operationId: string, request: RouteRequest): Promise<ServiceResult<unknown>> {
    const candidate = (this as unknown as Record<string, unknown>)[operationId];
    if (typeof candidate !== 'function') throw new Error(`No handler for ${operationId}`);
    return (candidate as (request: RouteRequest) => Promise<ServiceResult<unknown>>).call(
      this,
      request,
    );
  }

  users(): Promise<ServiceResult<unknown>> {
    return this.directory.listUsers();
  }

  createUser(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.createUser({
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  getUser(request: RouteRequest): Promise<ServiceResult<unknown>> {
    return this.directory.getUser(new RequestValues(request).param('userId'));
  }

  updateUser(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.updateUser(values.param('userId'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  archiveUser(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.archiveUser(values.param('userId'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  organizations(): Promise<ServiceResult<unknown>> {
    return this.directory.listOrganizations();
  }

  createOrganization(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.createOrganization({
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  getOrganization(request: RouteRequest): Promise<ServiceResult<unknown>> {
    return this.directory.getOrganization(new RequestValues(request).param('slug'));
  }

  updateOrganization(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.updateOrganization(values.param('slug'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  deleteOrganization(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.deleteOrganization(values.param('slug'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: {},
    });
  }

  getMembership(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.getMembership(values.param('slug'), values.param('userId'));
  }

  putMembership(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.putMembership(values.param('slug'), values.param('userId'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  deleteMembership(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.deleteMembership(values.param('slug'), values.param('userId'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: {},
    });
  }

  oauthClients(): Promise<ServiceResult<unknown>> {
    return this.oauth.list();
  }

  createOAuthClient(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.oauth.create({
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  getOAuthClient(request: RouteRequest): Promise<ServiceResult<unknown>> {
    return this.oauth.get(new RequestValues(request).param('clientId'));
  }

  updateOAuthClient(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.oauth.update(values.param('clientId'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  rotateOAuthClientSecret(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.oauth.rotate(values.param('clientId'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: values.body(),
    });
  }

  revokeOAuthClient(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.oauth.revoke(values.param('clientId'), {
      actor: values.actor(),
      idempotencyKey: values.header('idempotency-key'),
      body: {},
    });
  }

  audit(): Promise<ServiceResult<unknown>> {
    return this.records.list();
  }

  members(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.directory.listMembers(
      values.param('slug'),
      values.query('cursor'),
      values.query('limit'),
    );
  }

  apiList(): Promise<ServiceResult<unknown>> {
    return this.links.list(accountCaller());
  }

  apiPrepareUnlink(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.links.prepare(accountCaller(), {
      issuer: values.query('issuer'),
      subject: values.query('subject'),
    });
  }

  apiUnlink(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.links.unlink(accountCaller(), {
      issuer: values.query('issuer'),
      subject: values.query('subject'),
      confirmationToken: values.query('confirmationToken'),
    });
  }
}

@Container()
export class ControlPlaneRouter {
  constructor(
    @Component(AuthorizationEndpoints) private readonly authorization: AuthorizationEndpoints,
    @Component(BearerGuard) private readonly bearer: BearerGuard,
    @Component(OperationsEndpoints) private readonly operations: OperationsEndpoints,
    @Component(AccountGuard) private readonly account: AccountGuard,
  ) {}

  /** Paths this router owns: the JSON API, session-free OAuth 2 endpoints, health, readiness. */
  handles(pathname: string): boolean {
    return (
      pathname.startsWith('/api/') ||
      this.authorization.handles(pathname) ||
      this.operations.handles(pathname)
    );
  }

  async fetch(request: Request): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (this.authorization.handles(pathname)) return this.authorization.fetch(request);
    if (this.operations.handles(pathname)) return this.operations.fetch(request);
    const access = apiAccess(request.method, pathname);
    if (access) {
      const caller = await this.bearer.authorize(request, access);
      if (caller instanceof Response) return caller;
      return RequestContext.run(caller, () => this.route(pathname, request));
    }
    if (pathname.startsWith('/api/v1/account')) {
      const caller = await this.account.authorize(request);
      if (caller instanceof Response) return caller;
      return RequestContext.run(caller, () => this.route(pathname, request));
    }
    return this.route(pathname, request);
  }

  private async route(pathname: string, request: Request): Promise<Response> {
    if (pathname.startsWith('/api/admin')) {
      const { routes } = await import('./generated/admin/v1/http.ts');
      return routes.fetch(request);
    }
    if (pathname.startsWith('/api/v1/account')) {
      const { routes } = await import('./generated/account/v1/http.ts');
      return routes.fetch(request);
    }
    if (pathname.startsWith('/api/v1/organizations')) {
      const { routes } = await import('./generated/organizations/v1/http.ts');
      return routes.fetch(request);
    }
    return new Response(null, { status: 404 });
  }
}

@Container()
export class IdentityServer {
  constructor(@Component(ControlPlaneRouter) private readonly router: ControlPlaneRouter) {}

  start(port = 0) {
    const router = this.router;
    return Bun.serve({
      port,
      fetch: (request: Request) => router.fetch(request),
    });
  }
}

export const controlPlane = useContainer().resolve(ControlPlaneRouter);
