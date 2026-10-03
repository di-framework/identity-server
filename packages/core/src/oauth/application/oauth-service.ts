import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import { JsonBody } from '../../shared/application/json-body.ts';
import { ClientSecrets } from '../../shared/domain/client-secrets.ts';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import { ServiceResult } from '../../shared/domain/service-result.ts';
import { AUDIT, OAUTH } from '../../shared/domain/tokens.ts';
import { PasswordHasher } from '../../shared/infrastructure/crypto/passwords.ts';
import { OAuthClient, type OAuthRepository } from '../domain/oauth-client.ts';

interface Command {
  actor: string;
  idempotencyKey?: string;
  body: Record<string, unknown>;
}

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

  async create(
    command: Command,
  ): Promise<ServiceResult<{ client_id: string; client_secret: string }>> {
    const body = new JsonBody(command.body);
    const clientId = body.text('clientId');
    if (!clientId) return new ServiceResult(400);
    const organizationSlug = body.optional('organizationSlug');
    const redirectUris = body.texts('redirectUris');
    const scopes = body.texts('scopes');
    const browser = body.flag('browser');
    if (browser && redirectUris.length === 0) return new ServiceResult(400);
    const secret = this.secrets.sign(command.idempotencyKey, `create:${clientId}`);
    try {
      const replay = await this.replay(command.idempotencyKey, {
        clientId,
        organizationSlug,
        redirectUris,
        scopes,
        browser,
        secret,
      });
      if (replay) return replay;
      await this.oauth.insert({
        clientId,
        organizationSlug,
        redirectUris,
        scopes,
        browser,
        secretHash: await this.passwords.hash(secret),
      });
      await this.audit.append({
        action: 'admin.oauth_client_created',
        actor: command.actor,
        target: clientId,
        correlationId: command.idempotencyKey ?? null,
      });
      return new ServiceResult(201, { client_id: clientId, client_secret: secret });
    } catch (error) {
      return this.failed(error);
    }
  }

  async update(
    clientId: string,
    command: Command,
  ): Promise<ServiceResult<ReturnType<OAuthService['response']>>> {
    const body = new JsonBody(command.body);
    const redirectUris = body.texts('redirectUris');
    const scopes = body.texts('scopes');
    const browser = body.flag('browser');
    const organizationSlug = body.optional('organizationSlug');
    if (browser && redirectUris.length === 0) return new ServiceResult(400);
    const existing = await this.oauth.find(clientId);
    if (!existing) return new ServiceResult(404);
    if (existing.revokedAt) return new ServiceResult(409);
    await this.oauth.update({ clientId, organizationSlug, redirectUris, scopes, browser });
    await this.audit.append({
      action: 'admin.oauth_client_updated',
      actor: command.actor,
      target: clientId,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(
      200,
      this.response(
        new OAuthClient(
          clientId,
          organizationSlug,
          redirectUris,
          scopes,
          browser,
          existing.revokedAt,
          existing.createdAt,
        ),
      ),
    );
  }

  async rotate(
    clientId: string,
    command: Command,
  ): Promise<ServiceResult<{ client_id: string; client_secret: string }>> {
    const version = new JsonBody(command.body).text('version');
    if (!version) return new ServiceResult(400);
    const existing = await this.oauth.find(clientId);
    if (!existing) return new ServiceResult(404);
    if (existing.revokedAt) return new ServiceResult(409);
    const secret = this.secrets.sign(command.idempotencyKey, `rotate:${clientId}:${version}`);
    await this.oauth.rotateSecret(clientId, await this.passwords.hash(secret));
    await this.audit.append({
      action: 'admin.oauth_client_secret_rotated',
      actor: command.actor,
      target: clientId,
      correlationId: command.idempotencyKey ?? null,
    });
    return new ServiceResult(200, { client_id: clientId, client_secret: secret });
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

  private async replay(
    key: string | undefined,
    request: {
      clientId: string;
      organizationSlug: string | null;
      redirectUris: string[];
      scopes: string[];
      browser: boolean;
      secret: string;
    },
  ): Promise<ServiceResult<{ client_id: string; client_secret: string }> | undefined> {
    if (!key) return undefined;
    const target = await this.audit.idempotentTarget('admin.oauth_client_created', key);
    if (!target) return undefined;
    const existing = await this.oauth.find(target);
    if (!existing) return undefined;
    if (!this.same(existing, request)) return new ServiceResult(409);
    return new ServiceResult(201, { client_id: request.clientId, client_secret: request.secret });
  }

  private same(
    existing: OAuthClient,
    request: {
      clientId: string;
      organizationSlug: string | null;
      redirectUris: string[];
      scopes: string[];
      browser: boolean;
    },
  ): boolean {
    return (
      existing.clientId === request.clientId &&
      existing.organizationSlug === request.organizationSlug &&
      existing.browser === request.browser &&
      this.sameSet(existing.redirectUris, request.redirectUris) &&
      this.sameSet(existing.scopes, request.scopes)
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
      browser: client.browser,
      revoked_at: client.revokedAt,
      created_at: client.createdAt,
    };
  }

  private failed(error: unknown): ServiceResult<never> {
    return new ServiceResult(error instanceof IdentityError ? error.status : 500);
  }
}
