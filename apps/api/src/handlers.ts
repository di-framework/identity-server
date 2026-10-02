import { useContainer } from '@di-framework/core/container';
import { Container } from '@di-framework/core/decorators';
import { ControlPlaneController, HttpResponse, type RouteRequest } from './control-plane.ts';

export interface HttpCall {
  transport: 'http';
  request: {
    headers?: { get(name: string): string | null };
    content?: unknown;
    params?: Record<string, string | undefined>;
    query?: Record<string, string | string[] | undefined>;
  };
}

const OPERATIONS = [
  'users',
  'createUser',
  'getUser',
  'updateUser',
  'archiveUser',
  'organizations',
  'createOrganization',
  'getOrganization',
  'updateOrganization',
  'deleteOrganization',
  'getMembership',
  'putMembership',
  'deleteMembership',
  'oauthClients',
  'createOAuthClient',
  'getOAuthClient',
  'updateOAuthClient',
  'rotateOAuthClientSecret',
  'revokeOAuthClient',
  'audit',
  'members',
  'apiList',
  'apiPrepareUnlink',
  'apiUnlink',
] as const;

type OperationName = (typeof OPERATIONS)[number];

@Container()
export class ControlPlaneHandlers {
  constructor() {
    for (const name of OPERATIONS) {
      this[name] = (command, call) => this.respond(name, command, call);
    }
  }

  declare users: (command: unknown, call: HttpCall) => Promise<Response>;
  declare createUser: (command: unknown, call: HttpCall) => Promise<Response>;
  declare getUser: (command: unknown, call: HttpCall) => Promise<Response>;
  declare updateUser: (command: unknown, call: HttpCall) => Promise<Response>;
  declare archiveUser: (command: unknown, call: HttpCall) => Promise<Response>;
  declare organizations: (command: unknown, call: HttpCall) => Promise<Response>;
  declare createOrganization: (command: unknown, call: HttpCall) => Promise<Response>;
  declare getOrganization: (command: unknown, call: HttpCall) => Promise<Response>;
  declare updateOrganization: (command: unknown, call: HttpCall) => Promise<Response>;
  declare deleteOrganization: (command: unknown, call: HttpCall) => Promise<Response>;
  declare getMembership: (command: unknown, call: HttpCall) => Promise<Response>;
  declare putMembership: (command: unknown, call: HttpCall) => Promise<Response>;
  declare deleteMembership: (command: unknown, call: HttpCall) => Promise<Response>;
  declare oauthClients: (command: unknown, call: HttpCall) => Promise<Response>;
  declare createOAuthClient: (command: unknown, call: HttpCall) => Promise<Response>;
  declare getOAuthClient: (command: unknown, call: HttpCall) => Promise<Response>;
  declare updateOAuthClient: (command: unknown, call: HttpCall) => Promise<Response>;
  declare rotateOAuthClientSecret: (command: unknown, call: HttpCall) => Promise<Response>;
  declare revokeOAuthClient: (command: unknown, call: HttpCall) => Promise<Response>;
  declare audit: (command: unknown, call: HttpCall) => Promise<Response>;
  declare members: (command: unknown, call: HttpCall) => Promise<Response>;
  declare apiList: (command: unknown, call: HttpCall) => Promise<Response>;
  declare apiPrepareUnlink: (command: unknown, call: HttpCall) => Promise<Response>;
  declare apiUnlink: (command: unknown, call: HttpCall) => Promise<Response>;

  private async respond(name: OperationName, command: unknown, call: HttpCall): Promise<Response> {
    try {
      const controller = useContainer().resolve(ControlPlaneController);
      const request: RouteRequest = {
        headers: call.request.headers ?? { get: () => null },
        content: command,
        params: call.request.params,
        query: call.request.query,
      };
      const method = controller[name] as (
        request: RouteRequest,
      ) => Promise<{ status: number; body?: unknown }>;
      return HttpResponse.from(await method.call(controller, request));
    } catch (error) {
      console.error(`control-plane ${name} failed`, error);
      return new Response(null, { status: 500 });
    }
  }
}
