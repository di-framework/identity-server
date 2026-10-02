import { resolve } from 'node:path';
import { useContainer } from '@di-framework/core/container';
import { Component, Container } from '@di-framework/core/decorators';
import { Controller, Endpoint, HttpRouter, json } from '@di-framework/http';
import { AuditService } from '@di-framework/identity/src/audit/application/audit-service.ts';
import { loadOpenApi } from '@di-framework/identity-codegen';
import '@di-framework/identity/src/composition.ts';
import { DirectoryService } from '@di-framework/identity/src/directory/application/directory-service.ts';
import { LinkService } from '@di-framework/identity/src/linking/application/link-service.ts';
import { OAuthService } from '@di-framework/identity/src/oauth/application/oauth-service.ts';
import type { ServiceResult } from '@di-framework/identity/src/shared/domain/service-result.ts';

const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const;
type Method = (typeof METHODS)[number];

type SpecOperation = {
  operationId?: string;
  summary?: string;
  description?: string;
  parameters?: Array<{ in: string }>;
  requestBody?: unknown;
  responses?: Record<string, { content?: Record<string, unknown> }>;
};

type SpecDocument = {
  info?: { title?: string; version?: string; description?: string };
  paths: Record<string, Partial<Record<Method, SpecOperation>>>;
  components?: { schemas?: Record<string, unknown> };
};

export interface RouteRequest {
  headers: { get(name: string): string | null };
  content?: unknown;
  params?: Record<string, string | undefined>;
  query?: Record<string, string | undefined>;
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
    if (typeof value !== 'string' || value.trim() === '') return undefined;
    return value.trim();
  }

  param(name: string): string {
    return this.request.params?.[name] ?? '';
  }

  body(): Record<string, unknown> {
    const content = this.request.content;
    if (typeof content !== 'object' || content === null || Array.isArray(content)) return {};
    return content as Record<string, unknown>;
  }

  actor(): string {
    return this.header('x-actor-id') ?? 'system';
  }
}

export class HttpResponse {
  static from(result: ServiceResult<unknown>): Response {
    if (result.body === undefined) return new Response(null, { status: result.status });
    return json(result.body, { status: result.status });
  }
}

@Container()
export class OpenApiCatalog {
  readonly spec: SpecDocument;
  readonly operations: ControlOperation[];

  constructor() {
    this.spec = loadOpenApi(resolve(import.meta.dir, '../api/v1/openapi.yaml')) as SpecDocument;
    this.operations = this.collect();
  }

  private collect(): ControlOperation[] {
    const operations: ControlOperation[] = [];
    for (const [path, item] of Object.entries(this.spec.paths)) {
      for (const method of METHODS) {
        const operation = item[method];
        if (!operation) continue;
        const jsonApi = this.isJson(operation);
        if (!path.startsWith('/api/') || !jsonApi) continue;
        operations.push(this.toOperation(path, method, operation));
      }
    }
    return operations;
  }

  private isJson(operation: SpecOperation): boolean {
    for (const [code, response] of Object.entries(operation.responses ?? {})) {
      const status = Number(code);
      if (status < 200 || status >= 300) continue;
      if (response.content?.['application/json']) return true;
      if (status === 204 && !response.content) return true;
    }
    return false;
  }

  private toOperation(path: string, method: Method, operation: SpecOperation): ControlOperation {
    const parameters = (operation.parameters ?? []).filter((parameter) => parameter.in !== 'path');
    return {
      operationId: operation.operationId ?? '',
      method,
      ittyPath: path.replaceAll(/\{([^}]+)\}/g, ':$1'),
      metadata: {
        ...(operation.summary ? { summary: operation.summary } : {}),
        ...(operation.description ? { description: operation.description } : {}),
        ...(parameters.length > 0 ? { parameters } : {}),
        ...(operation.requestBody ? { requestBody: operation.requestBody } : {}),
        responses: operation.responses ?? {},
      },
    };
  }
}

interface ControlOperation {
  operationId: string;
  method: Method;
  ittyPath: string;
  metadata: Record<string, unknown>;
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

  apiList(request: RouteRequest): Promise<ServiceResult<unknown>> {
    return this.links.list(new RequestValues(request).header('x-user-id'));
  }

  apiPrepareUnlink(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.links.prepare({
      userId: values.header('x-user-id'),
      sessionId: values.header('x-session-id'),
      issuer: values.query('issuer'),
      subject: values.query('subject'),
    });
  }

  apiUnlink(request: RouteRequest): Promise<ServiceResult<unknown>> {
    const values = new RequestValues(request);
    return this.links.unlink({
      userId: values.header('x-user-id'),
      sessionId: values.header('x-session-id'),
      issuer: values.query('issuer'),
      subject: values.query('subject'),
      confirmationToken: values.query('confirmationToken'),
    });
  }
}

@Container()
export class ControlPlaneRouter {
  readonly http: ReturnType<ReturnType<typeof HttpRouter.builder>['build']>;

  constructor(@Component(OpenApiCatalog) catalog: OpenApiCatalog) {
    const http = HttpRouter.builder().build();
    this.http = http;
    for (const operation of catalog.operations) this.register(http, operation);
  }

  fetch(request: Request): Promise<Response> {
    return this.http.fetch(request);
  }

  private register(http: ControlPlaneRouter['http'], operation: ControlOperation): void {
    const handler = async (request: RouteRequest) => {
      try {
        const controller = useContainer().resolve(ControlPlaneController);
        const result = await controller.dispatch(operation.operationId, request);
        return HttpResponse.from(result);
      } catch (error) {
        return ControlPlaneRouter.error(error);
      }
    };
    const routed = http[operation.method](operation.ittyPath, handler as never);
    const target = ControlPlaneController as unknown as Record<string, unknown>;
    target[operation.operationId] = routed;
    Endpoint(operation.metadata)(ControlPlaneController, operation.operationId);
  }

  private static error(error: unknown): Response {
    const message = error instanceof Error ? error.message : 'Request failed';
    return json({ error: message }, { status: 500 });
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
