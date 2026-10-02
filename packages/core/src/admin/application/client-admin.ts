import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type {
  RegisteredClient,
  RegisteredClientRepository,
} from '../../authorization/domain/models.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { Organization } from '../../directory/domain/models.ts';
import type { OAuthRepository } from '../../oauth/domain/oauth-client.ts';
import { AUDIT, DIRECTORY, OAUTH, REGISTERED_CLIENTS } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import { PasswordHasher } from '../../shared/infrastructure/crypto/passwords.ts';
import { AdminPolicy, type AdminResult, commaList, failure, ok } from './admin-policy.ts';

export interface ClientForm {
  orgSlug: string;
  clientName: string;
  redirectUris?: string | null;
  grantTypes?: string | null;
  scopes?: string | null;
}

/** A client id and its plain secret, shown once. */
export interface IssuedSecret {
  clientId: string;
  secret: string;
}

/**
 * `/admin/oauth-clients/**` (`AdminOAuthClientController.kt`). Registration assigns `cli_` plus
 * 16 hex characters, stores the typed name and grant types, and returns the secret once. The
 * auth server puts that secret in the redirect URL; this repository returns it to the caller.
 */
@Container()
export class ClientAdminService {
  constructor(
    @Component(AdminPolicy) private readonly policy: AdminPolicy,
    @Component(REGISTERED_CLIENTS) private readonly clients: RegisteredClientRepository,
    @Component(OAUTH) private readonly oauth: OAuthRepository,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(PasswordHasher) private readonly passwords: PasswordHasher,
  ) {}

  async list(
    actorId: string,
    filter: { orgSlug?: string | null; status?: string | null } = {},
  ): Promise<{ clients: RegisteredClient[]; organizations: Organization[] }> {
    const orgSlug = filter.orgSlug?.trim() || null;
    await this.policy.check(actorId, 'OAUTH_CLIENT_VIEW', { orgSlug });
    const context = await this.policy.context(actorId);
    let clients: RegisteredClient[];
    if (orgSlug) clients = await this.clients.list(orgSlug);
    else if (context.isPlatformAdmin) clients = await this.clients.list();
    else {
      clients = [];
      for (const owned of [...context.ownedOrgSlugs].sort()) {
        clients.push(...(await this.clients.list(owned)));
      }
    }
    const status = filter.status?.toLowerCase();
    return {
      clients: clients.filter((client) =>
        status === 'active'
          ? client.revokedAt === null
          : status === 'revoked'
            ? client.revokedAt !== null
            : true,
      ),
      organizations: await this.policy.availableOrganizations(context),
    };
  }

  async registerOrganizations(actorId: string): Promise<Organization[]> {
    await this.policy.check(actorId, 'OAUTH_CLIENT_CREATE');
    return this.policy.availableOrganizations(await this.policy.context(actorId));
  }

  async register(actorId: string, form: ClientForm): Promise<AdminResult<IssuedSecret>> {
    await this.policy.check(actorId, 'OAUTH_CLIENT_CREATE', { orgSlug: form.orgSlug });
    const organization = await this.directory.findOrganization(form.orgSlug);
    if (!organization || organization.archivedAt !== null) {
      return failure(400, 'Invalid Organization', 'Organization is invalid or archived.');
    }
    const clientId = Hashing.clientId();
    const secret = Hashing.token();
    await this.clients.insert({
      clientId,
      clientName: form.clientName.trim() || clientId,
      secretHash: await this.passwords.hash(secret),
      authenticationMethods: ['client_secret_basic'],
      grantTypes: commaList(form.grantTypes ?? 'authorization_code,refresh_token'),
      redirectUris: commaList(form.redirectUris),
      scopes: commaList(form.scopes ?? 'openid,profile,email'),
      settings: { requireProofKey: false, requireAuthorizationConsent: false },
      organizationSlug: form.orgSlug,
    });
    await this.audit.append({
      action: 'admin.oauth_client.create',
      actor: actorId,
      target: `${form.orgSlug}:${clientId}`,
      correlationId: crypto.randomUUID(),
      after: { clientId, orgSlug: form.orgSlug, name: form.clientName.trim() },
    });
    return ok({ clientId, secret });
  }

  async detail(actorId: string, clientId: string): Promise<AdminResult<RegisteredClient>> {
    const client = await this.lifecycleClient(clientId);
    if (!client) {
      return failure(404, 'Client Not Found', `OAuth Client ${clientId} does not exist.`);
    }
    await this.policy.check(actorId, 'OAUTH_CLIENT_VIEW', { orgSlug: client.organizationSlug });
    return ok(client);
  }

  async edit(
    actorId: string,
    clientId: string,
    form: Omit<ClientForm, 'orgSlug'>,
  ): Promise<AdminResult<RegisteredClient>> {
    const client = await this.lifecycleClient(clientId);
    if (!client) return failure(404, 'Not Found', '');
    await this.policy.check(actorId, 'OAUTH_CLIENT_EDIT', { orgSlug: client.organizationSlug });
    const clientName = form.clientName.trim();
    await this.clients.update(clientId, {
      clientName,
      redirectUris: commaList(form.redirectUris),
      grantTypes: commaList(form.grantTypes),
      scopes: commaList(form.scopes),
    });
    await this.audit.append({
      action: 'admin.oauth_client.edit',
      actor: actorId,
      target: `${client.organizationSlug}:${clientId}`,
      correlationId: crypto.randomUUID(),
      before: { name: client.clientName },
      after: { name: clientName },
    });
    return ok(client);
  }

  async rotateSecret(actorId: string, clientId: string): Promise<AdminResult<IssuedSecret>> {
    const client = await this.lifecycleClient(clientId);
    if (!client) return failure(404, 'Not Found', '');
    await this.policy.check(actorId, 'OAUTH_CLIENT_ROTATE_SECRET', {
      orgSlug: client.organizationSlug,
    });
    const secret = Hashing.token();
    await this.clients.update(clientId, { secretHash: await this.passwords.hash(secret) });
    await this.audit.append({
      action: 'admin.oauth_client.rotate_secret',
      actor: actorId,
      target: `${client.organizationSlug}:${clientId}`,
      correlationId: crypto.randomUUID(),
      after: { secretRotated: true },
    });
    return ok({ clientId, secret });
  }

  async revoke(actorId: string, clientId: string, now = Date.now()): Promise<AdminResult<never>> {
    const client = await this.lifecycleClient(clientId);
    if (!client) return failure(404, 'Not Found', '');
    await this.policy.check(actorId, 'OAUTH_CLIENT_REVOKE', { orgSlug: client.organizationSlug });
    await this.oauth.revoke(clientId);
    await this.audit.append({
      action: 'admin.oauth_client.revoke',
      actor: actorId,
      target: `${client.organizationSlug}:${clientId}`,
      correlationId: crypto.randomUUID(),
      after: { revokedAt: new Date(now).toISOString() },
    });
    return { kind: 'redirect', location: `/admin/oauth-clients/${clientId}?revoked=1` };
  }

  /** The admin pages only know clients that have a lifecycle row. */
  private async lifecycleClient(clientId: string): Promise<RegisteredClient | undefined> {
    const client = await this.clients.find(clientId);
    return client && (await this.hasLifecycle(client)) ? client : undefined;
  }

  private async hasLifecycle(client: RegisteredClient): Promise<boolean> {
    return (await this.oauth.find(client.clientId)) !== undefined;
  }
}
