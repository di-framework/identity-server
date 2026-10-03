import { Component, Container } from '@di-framework/core/decorators';
import type { Clock } from '../../shared/domain/clock.ts';
import { AUTHORIZATIONS, CLOCK, REGISTERED_CLIENTS } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import type {
  Authorization,
  AuthorizationRepository,
  RegisteredClient,
  RegisteredClientRepository,
  StoredToken,
} from '../domain/models.ts';

/** The caller behind a valid opaque access token. */
export interface TokenPrincipal {
  /** User id for authorization-code tokens, client id for client-credentials tokens. */
  principalName: string;
  clientId: string;
  scopes: string[];
  issuedAt: number;
  expiresAt: number;
}

/**
 * Resolves opaque tokens with the auth server's rejection order
 * (`DatabaseOpaqueTokenIntrospector`): unknown, invalidated, expired, client missing,
 * client lifecycle revoked.
 */
@Container()
export class Introspector {
  constructor(
    @Component(AUTHORIZATIONS) private readonly authorizations: AuthorizationRepository,
    @Component(REGISTERED_CLIENTS) private readonly clients: RegisteredClientRepository,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  async accessToken(token: string): Promise<TokenPrincipal | undefined> {
    const found = await this.active('access', token);
    if (!found) return undefined;
    const access = found.authorization.access as StoredToken & { scopes: string[] };
    return {
      principalName: found.authorization.principalName,
      clientId: found.client.clientId,
      scopes: access.scopes,
      issuedAt: access.issuedAt,
      expiresAt: access.expiresAt,
    };
  }

  /** RFC 7662 response for access or refresh tokens issued to `caller`. */
  async introspect(caller: RegisteredClient, token: string): Promise<Record<string, unknown>> {
    const found = (await this.active('access', token)) ?? (await this.active('refresh', token));
    if (!found || found.client.id !== caller.id) return { active: false };
    const { authorization, stored } = found;
    return {
      active: true,
      client_id: found.client.clientId,
      sub: authorization.principalName,
      aud: [found.client.clientId],
      scope: (authorization.access?.scopes ?? authorization.authorizedScopes).join(' '),
      iat: Math.floor(stored.issuedAt / 1000),
      exp: Math.floor(stored.expiresAt / 1000),
      token_type: 'Bearer',
    };
  }

  /** RFC 7009. Revoking a refresh token invalidates the whole authorization. */
  async revoke(caller: RegisteredClient, token: string): Promise<void> {
    const hash = Hashing.sha256Hex(token);
    const byAccess = await this.authorizations.findByToken('access', hash);
    const authorization = byAccess ?? (await this.authorizations.findByToken('refresh', hash));
    if (!authorization || authorization.registeredClientId !== caller.id) return;
    if (byAccess?.access) {
      await this.authorizations.save({
        ...byAccess,
        access: { ...byAccess.access, invalidated: true },
      });
      return;
    }
    await this.authorizations.delete(authorization.id);
  }

  private async active(
    kind: 'access' | 'refresh',
    token: string,
  ): Promise<
    { authorization: Authorization; client: RegisteredClient; stored: StoredToken } | undefined
  > {
    const authorization = await this.authorizations.findByToken(kind, Hashing.sha256Hex(token));
    const stored = authorization?.[kind];
    if (!authorization || !stored || stored.invalidated) return undefined;
    if (stored.expiresAt <= this.clock.now()) return undefined;
    const client = await this.clients.findById(authorization.registeredClientId);
    if (!client || client.revokedAt !== null) return undefined;
    return { authorization, client, stored };
  }
}
