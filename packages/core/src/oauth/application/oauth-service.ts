import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import { isLoopbackRedirect } from '../../authorization/domain/loopback.ts';
import { JsonBody } from '../../shared/application/json-body.ts';
import { ClientSecrets } from '../../shared/domain/client-secrets.ts';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import { ServiceResult } from '../../shared/domain/service-result.ts';
import { AUDIT, OAUTH } from '../../shared/domain/tokens.ts';
import { PasswordHasher } from '../../shared/infrastructure/crypto/passwords.ts';
import {
  isTokenEndpointAuthMethod,
  type OAuthClient,
  type OAuthClientMetadata,
  type OAuthRepository,
} from '../domain/oauth-client.ts';

interface Command {
  actor: string;
  idempotencyKey?: string;
  body: Record<string, unknown>;
}

/** What create and rotate return. A public client has no secret. */
export interface IssuedClient {
  client_id: string;
  client_secret?: string;
}

/** `oauth_client_lifecycle.audiences` is `varchar(1000)`, comma-separated. */
const MAX_AUDIENCES_LENGTH = 1000;

/** An `aud` value: non-empty, and storable in the comma-separated column. */
function validAudience(value: string): boolean {
  return value.length > 0 && !/[\s,]/.test(value);
}

function unique(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter((value) => value.length > 0))];
}

function issued(clientId: string, secret: string | null): IssuedClient {
  return secret === null ? { client_id: clientId } : { client_id: clientId, client_secret: secret };
}

/**
 * `/api/admin/oauth-clients`. Every client registered here belongs to an organization (its
 * tenant); only the bootstrap clients from configuration are global. A confidential client
 * (`tokenEndpointAuthMethod` `client_secret_basic`, the default) gets a secret; a public one
 * (`none`) is a native app on loopback redirects with PKCE, as the bootstrap CLI client is, and
 * never has one. The auth method is fixed at registration.
 */
@Container()
export class OAuthService {
  constructor(
    @Component(OAUTH) private readonly oauth: OAuthRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(ClientSecrets) private readonly secrets: ClientSecrets,
    @Component(PasswordHasher) private readonly passwords: PasswordHasher,
  ) {}

  async list(): Promise<ServiceResult<ReturnType<OAuthService['response']>[]>> {
    const clients = await this.oauth.list();
    return new ServiceResult(
      200,
      clients.map((client) => this.response(client)),
    );
  }

  async get(clientId: string): Promise<ServiceResult<ReturnType<OAuthService['response']>>> {
    const client = await this.oauth.find(clientId);
    if (!client) return new ServiceResult(404);
    return new ServiceResult(200, this.response(client));
  }

  async create(command: Command): Promise<ServiceResult<IssuedClient>> {
    const body = new JsonBody(command.body);
    const clientId = body.text('clientId');
    if (!clientId || clientId.length > 100) return new ServiceResult(400);
    const request = this.metadata(clientId, body);
    if (request instanceof ServiceResult) return request;
    const secret =
      request.tokenEndpointAuthMethod === 'none'
        ? null
        : this.secrets.sign(command.idempotencyKey, `create:${clientId}`);
    try {
      // The client and its idempotency record (the audit row) commit together: a concurrent
      // keyed create that loses the unique-index race then finds the record when it replays.
      return await this.oauth.transaction(async () => {
        const replay = await this.replay(command.idempotencyKey, request, secret);
        if (replay) return replay;
        await this.oauth.insert({
          ...request,
          secretHash: secret === null ? null : await this.passwords.hash(secret),
        });
        await this.audit.append({
          action: 'admin.oauth_client_created',
          actor: command.actor,
          target: clientId,
          correlationId: command.idempotencyKey ?? null,
        });
        return new ServiceResult(201, issued(clientId, secret));
      });
    } catch (error) {
      if (command.idempotencyKey) {
        const replay = await this.replay(command.idempotencyKey, request, secret);
        if (replay) return replay;
      }
      return this.failed(error);
    }
  }

  async update(
    clientId: string,
    command: Command,
  ): Promise<ServiceResult<ReturnType<OAuthService['response']>>> {
    const existing = await this.oauth.find(clientId);
    if (!existing) return new ServiceResult(404);
    const request = this.metadata(clientId, new JsonBody(command.body), existing);
    if (request instanceof ServiceResult) return request;
    if (existing.revokedAt) return new ServiceResult(409);
    await this.oauth.update(request);
    await this.audit.append({
      action: 'admin.oauth_client_updated',
      actor: command.actor,
      target: clientId,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(200, this.response({ ...existing, ...request }));
  }

  async rotate(clientId: string, command: Command): Promise<ServiceResult<IssuedClient>> {
    const version = new JsonBody(command.body).text('version');
    if (!version) return new ServiceResult(400);
    const existing = await this.oauth.find(clientId);
    if (!existing) return new ServiceResult(404);
    // A public client has no secret to rotate.
    if (existing.revokedAt || existing.tokenEndpointAuthMethod === 'none') {
      return new ServiceResult(409);
    }
    const secret = this.secrets.sign(command.idempotencyKey, `rotate:${clientId}:${version}`);
    await this.oauth.rotateSecret(clientId, await this.passwords.hash(secret));
    await this.audit.append({
      action: 'admin.oauth_client_secret_rotated',
      actor: command.actor,
      target: clientId,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(200, issued(clientId, secret));
  }

  async revoke(clientId: string, command: Command): Promise<ServiceResult> {
    const existing = await this.oauth.find(clientId);
    if (!existing) return new ServiceResult(404);
    await this.oauth.revoke(clientId);
    await this.audit.append({
      action: 'admin.oauth_client_revoked',
      actor: command.actor,
      target: clientId,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(204);
  }

  /**
   * The validated metadata of a create or update body, or the 400 that refuses it. An update
   * (`existing` given) may repeat the stored token endpoint auth method but not change it: a
   * client is confidential or public for life, which is a 409.
   */
  private metadata(
    clientId: string,
    body: JsonBody,
    existing?: OAuthClient,
  ): OAuthClientMetadata | ServiceResult<never> {
    const organizationSlug = body.optional('organizationSlug');
    if (!organizationSlug || organizationSlug.length > 128) return new ServiceResult(400);
    const method = body.optional('tokenEndpointAuthMethod');
    const tokenEndpointAuthMethod =
      method ?? existing?.tokenEndpointAuthMethod ?? 'client_secret_basic';
    if (!isTokenEndpointAuthMethod(tokenEndpointAuthMethod)) return new ServiceResult(400);
    if (existing && tokenEndpointAuthMethod !== existing.tokenEndpointAuthMethod) {
      return new ServiceResult(409);
    }
    const redirectUris = unique(body.texts('redirectUris'));
    const scopes = unique(body.texts('scopes'));
    const audiences = unique(body.texts('audiences'));
    if (!audiences.every(validAudience) || audiences.join(',').length > MAX_AUDIENCES_LENGTH) {
      return new ServiceResult(400);
    }
    const isPublic = tokenEndpointAuthMethod === 'none';
    // A public client is a native app: authorization code with PKCE, on loopback redirects only.
    const browser = isPublic || body.flag('browser');
    if (browser && redirectUris.length === 0) return new ServiceResult(400);
    if (isPublic && !redirectUris.every(isLoopbackRedirect)) return new ServiceResult(400);
    return {
      clientId,
      organizationSlug,
      redirectUris,
      scopes,
      audiences,
      browser,
      tokenEndpointAuthMethod,
    };
  }

  private async replay(
    key: string | undefined,
    request: OAuthClientMetadata,
    secret: string | null,
  ): Promise<ServiceResult<IssuedClient> | undefined> {
    if (!key) return undefined;
    const target = await this.audit.idempotentTarget('admin.oauth_client_created', key);
    if (!target) return undefined;
    const existing = await this.oauth.find(target);
    if (!existing) return undefined;
    if (!this.same(existing, request)) return new ServiceResult(409);
    return new ServiceResult(201, issued(request.clientId, secret));
  }

  private same(existing: OAuthClient, request: OAuthClientMetadata): boolean {
    return (
      existing.clientId === request.clientId &&
      existing.organizationSlug === request.organizationSlug &&
      existing.browser === request.browser &&
      existing.tokenEndpointAuthMethod === request.tokenEndpointAuthMethod &&
      this.sameSet(existing.redirectUris, request.redirectUris) &&
      this.sameSet(existing.scopes, request.scopes) &&
      this.sameSet(existing.audiences, request.audiences)
    );
  }

  private sameSet(left: string[], right: string[]): boolean {
    if (left.length !== right.length) return false;
    const sortedLeft = [...left].sort();
    const sortedRight = [...right].sort();
    return sortedLeft.every((item, index) => item === sortedRight[index]);
  }

  private response(client: OAuthClient) {
    return {
      client_id: client.clientId,
      organization_slug: client.organizationSlug,
      redirect_uris: client.redirectUris,
      scopes: client.scopes,
      audiences: client.audiences,
      browser: client.browser,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      revoked_at: client.revokedAt,
      created_at: client.createdAt,
    };
  }

  private failed(error: unknown): ServiceResult<never> {
    return new ServiceResult(error instanceof IdentityError ? error.status : 500);
  }
}
