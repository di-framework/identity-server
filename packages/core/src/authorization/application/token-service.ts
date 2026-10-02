import { Component, Container } from '@di-framework/core/decorators';
import type { Clock } from '../../shared/domain/clock.ts';
import { AUTHORIZATIONS, CLOCK } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import {
  type Authorization,
  type AuthorizationRepository,
  OAuthError,
  type RegisteredClient,
  TOKEN_SETTINGS,
} from '../domain/models.ts';

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope?: string;
  refresh_token?: string;
  id_token?: string;
}

/** Handler for one `grant_type`. */
export type GrantHandler = (
  client: RegisteredClient,
  form: URLSearchParams,
) => Promise<TokenResponse>;

/** `POST /oauth2/token`. Access tokens are opaque references stored as SHA-256 hashes. */
@Container()
export class TokenService {
  private readonly grants = new Map<string, GrantHandler>();

  constructor(
    @Component(AUTHORIZATIONS) private readonly authorizations: AuthorizationRepository,
    @Component(CLOCK) private readonly clock: Clock,
  ) {
    this.grants.set('client_credentials', (client, form) => this.clientCredentials(client, form));
  }

  exchange(client: RegisteredClient, form: URLSearchParams): Promise<TokenResponse> {
    const grantType = form.get('grant_type') ?? '';
    const handler = this.grants.get(grantType);
    if (!handler) return Promise.reject(new OAuthError('unsupported_grant_type'));
    if (!client.grantTypes.includes(grantType)) {
      return Promise.reject(new OAuthError('unauthorized_client'));
    }
    return handler(client, form);
  }

  /** Requested scopes must be a subset of the client's. No `scope` grants none, as SAS does. */
  requestedScopes(client: RegisteredClient, raw: string | null): string[] {
    const requested = [...new Set((raw ?? '').split(' ').filter((scope) => scope.length > 0))];
    if (requested.some((scope) => !client.scopes.includes(scope))) {
      throw new OAuthError('invalid_scope');
    }
    return requested;
  }

  /** New opaque token value and its stored form. */
  issue(ttlSeconds: number): {
    value: string;
    stored: { hash: string; issuedAt: number; expiresAt: number; invalidated: false };
  } {
    const value = Hashing.token();
    const issuedAt = this.clock.now();
    return {
      value,
      stored: {
        hash: Hashing.sha256Hex(value),
        issuedAt,
        expiresAt: issuedAt + ttlSeconds * 1000,
        invalidated: false,
      },
    };
  }

  private async clientCredentials(
    client: RegisteredClient,
    form: URLSearchParams,
  ): Promise<TokenResponse> {
    const scopes = this.requestedScopes(client, form.get('scope'));
    const access = this.issue(TOKEN_SETTINGS.accessTokenTtlSeconds);
    const authorization: Authorization = {
      id: crypto.randomUUID(),
      registeredClientId: client.id,
      principalName: client.clientId,
      grantType: 'client_credentials',
      authorizedScopes: scopes,
      attributes: {},
      state: null,
      code: null,
      access: { ...access.stored, scopes },
      refresh: null,
      idToken: null,
    };
    await this.authorizations.save(authorization);
    return TokenService.response(access.value, scopes);
  }

  static response(accessToken: string, scopes: string[]): TokenResponse {
    const response: TokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: TOKEN_SETTINGS.accessTokenTtlSeconds,
    };
    if (scopes.length > 0) response.scope = scopes.join(' ');
    return response;
  }
}
