import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import type { Clock } from '../../shared/domain/clock.ts';
import {
  AUDIT,
  AUTHORIZATIONS,
  CLOCK,
  DIRECTORY,
  IDENTITY_SETTINGS,
  SIGNING_KEYS,
} from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import type { SigningKeys } from '../../shared/infrastructure/crypto/signing-keys.ts';
import type { IdentitySettings } from '../../shared/infrastructure/identity-settings.ts';
import {
  type Authorization,
  type AuthorizationRepository,
  OAuthError,
  type RegisteredClient,
  type StoredToken,
  TOKEN_SETTINGS,
} from '../domain/models.ts';
import { UserClaims } from './claims.ts';

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

/** Spring Authorization Server signs ID tokens for 30 minutes. */
export const ID_TOKEN_TTL_SECONDS = 30 * 60;

type Issued = { value: string; stored: StoredToken };

/**
 * `POST /oauth2/token`: `client_credentials`, `authorization_code` with PKCE, and `refresh_token`
 * with rotation. Access and refresh tokens are opaque and stored as SHA-256 hashes. A rotated-out
 * refresh token is remembered; presenting it again revokes the whole authorization
 * (`RefreshRotationAuthorizationService`).
 */
@Container()
export class TokenService {
  private readonly grants = new Map<string, GrantHandler>();

  constructor(
    @Component(AUTHORIZATIONS) private readonly authorizations: AuthorizationRepository,
    @Component(CLOCK) private readonly clock: Clock,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(SIGNING_KEYS) private readonly keys: SigningKeys,
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(UserClaims) private readonly claims: UserClaims,
    @Component(AUDIT) private readonly audit: AuditRepository,
  ) {
    this.grants.set('client_credentials', (client, form) => this.clientCredentials(client, form));
    this.grants.set('authorization_code', (client, form) => this.authorizationCode(client, form));
    this.grants.set('refresh_token', (client, form) => this.refreshToken(client, form));
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

  /** Requested scopes must be a subset of `allowed`. No `scope` means none (or all, for refresh). */
  requestedScopes(allowed: string[], raw: string | null): string[] {
    const requested = [...new Set((raw ?? '').split(' ').filter((scope) => scope.length > 0))];
    if (requested.some((scope) => !allowed.includes(scope))) throw new OAuthError('invalid_scope');
    return requested;
  }

  private issue(ttlSeconds: number): Issued {
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
    const scopes = this.requestedScopes(client.scopes, form.get('scope'));
    const access = this.issue(TOKEN_SETTINGS.accessTokenTtlSeconds);
    await this.authorizations.save({
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
    });
    return TokenService.response(access.value, scopes);
  }

  /**
   * Runs `fn` in one transaction. An `OAuthError` it returns is thrown after commit, so
   * revocations made before refusing (code replay, refresh reuse) are kept.
   */
  private async committed(fn: () => Promise<TokenResponse | OAuthError>): Promise<TokenResponse> {
    const result = await this.directory.transaction(fn);
    if (result instanceof OAuthError) throw result;
    return result;
  }

  private authorizationCode(
    client: RegisteredClient,
    form: URLSearchParams,
  ): Promise<TokenResponse> {
    return this.committed(async () => {
      const authorization = await this.authorizations.findByToken(
        'code',
        Hashing.sha256Hex(form.get('code') ?? ''),
        true,
      );
      const code = authorization?.code;
      if (!authorization || !code || authorization.registeredClientId !== client.id) {
        return new OAuthError('invalid_grant');
      }
      if (code.invalidated) {
        // A replayed code revokes what it issued, as Spring Authorization Server does.
        await this.authorizations.delete(authorization.id);
        return new OAuthError('invalid_grant');
      }
      if (code.expiresAt <= this.clock.now()) return new OAuthError('invalid_grant');
      const attributes = authorization.attributes as {
        redirect_uri: string;
        requested_redirect_uri: string | null;
        code_challenge: string | null;
        nonce: string | null;
        auth_time: number;
      };
      if (
        attributes.requested_redirect_uri !== null &&
        form.get('redirect_uri') !== attributes.redirect_uri
      ) {
        return new OAuthError('invalid_grant');
      }
      const verifier = form.get('code_verifier');
      const pkce = attributes.code_challenge
        ? Boolean(verifier) &&
          Hashing.equal(Hashing.pkceChallenge(verifier ?? ''), attributes.code_challenge)
        : !client.settings.requireProofKey && !verifier;
      if (!pkce) return new OAuthError('invalid_grant');
      const inactive = await this.refuseInactive(authorization);
      if (inactive) return inactive;
      return this.tokens(
        client,
        { ...authorization, code: { ...code, invalidated: true } },
        authorization.authorizedScopes,
        attributes,
      );
    });
  }

  private refreshToken(client: RegisteredClient, form: URLSearchParams): Promise<TokenResponse> {
    const hash = Hashing.sha256Hex(form.get('refresh_token') ?? '');
    return this.committed(async () => {
      const authorization = await this.authorizations.findByToken('refresh', hash, true);
      if (!authorization?.refresh) {
        await this.detectReplay(hash);
        return new OAuthError('invalid_grant');
      }
      const refresh = authorization.refresh;
      if (
        authorization.registeredClientId !== client.id ||
        refresh.invalidated ||
        refresh.expiresAt <= this.clock.now()
      ) {
        return new OAuthError('invalid_grant');
      }
      // Before the rotation is remembered: a refused token must not later look like a replay.
      const inactive = await this.refuseInactive(authorization);
      if (inactive) return inactive;
      const scopes = form.get('scope')
        ? this.requestedScopes(authorization.authorizedScopes, form.get('scope'))
        : authorization.authorizedScopes;
      await this.authorizations.rememberRefresh(refresh.hash, authorization.id, refresh.expiresAt);
      return this.tokens(
        client,
        authorization,
        scopes,
        authorization.attributes as {
          nonce: string | null;
          auth_time: number;
        },
        refresh.hash,
      );
    });
  }

  /** A remembered refresh token presented again: revoke the token family and audit it, unless within concurrency grace. */
  private async detectReplay(hash: string): Promise<void> {
    const now = this.clock.now();
    const authorizationId = await this.authorizations.lockReplayedRefresh(hash, now);
    if (!authorizationId) return;
    const current = await this.authorizations.findById(authorizationId);
    if (current?.refresh) {
      const GRACE_PERIOD_MS = 10_000;
      if (
        current.refresh.previousHash === hash &&
        current.refresh.rotatedAt &&
        now - current.refresh.rotatedAt < GRACE_PERIOD_MS
      ) {
        // Concurrent exchange of the immediately preceding token within grace window:
        // Reject the duplicate request without revoking the newly issued session.
        return;
      }
    }
    await this.authorizations.markRefreshReused(hash, now);
    await this.authorizations.delete(authorizationId);
    await this.audit.append({
      action: 'oauth.refresh_reuse_detected',
      actor: null,
      target: authorizationId,
      correlationId: null,
    });
  }

  /**
   * Only an active user gets tokens: for anyone else the authorization (and so its token family)
   * is deleted and the grant refused.
   */
  private async refuseInactive(authorization: Authorization): Promise<OAuthError | undefined> {
    if ((await this.directory.findUser(authorization.principalName))?.status === 'active') {
      return undefined;
    }
    await this.authorizations.delete(authorization.id);
    return new OAuthError('invalid_grant');
  }

  /** New access token, a rotated refresh token, and an ID token when `openid` was granted. */
  private async tokens(
    client: RegisteredClient,
    authorization: Authorization,
    scopes: string[],
    attributes: { nonce?: string | null; auth_time?: number },
    previousRefreshHash?: string,
  ): Promise<TokenResponse> {
    const access = this.issue(TOKEN_SETTINGS.accessTokenTtlSeconds);
    const refresh = client.grantTypes.includes('refresh_token')
      ? this.issue(TOKEN_SETTINGS.refreshTokenTtlSeconds)
      : undefined;
    const response = TokenService.response(access.value, scopes);
    let idToken: Authorization['idToken'] = null;
    if (scopes.includes('openid')) {
      const issuedAt = Math.floor(this.clock.now() / 1000);
      const claims: Record<string, unknown> = {
        iss: this.settings.issuer,
        sub: authorization.principalName,
        aud: [client.clientId],
        azp: client.clientId,
        iat: issuedAt,
        exp: issuedAt + ID_TOKEN_TTL_SECONDS,
        auth_time: Math.floor((attributes.auth_time ?? this.clock.now()) / 1000),
        ...(attributes.nonce ? { nonce: attributes.nonce } : {}),
        ...((await this.claims.forUser(authorization.principalName)) ?? {}),
      };
      const value = this.keys.sign(claims);
      response.id_token = value;
      idToken = {
        hash: Hashing.sha256Hex(value),
        issuedAt: issuedAt * 1000,
        expiresAt: (issuedAt + ID_TOKEN_TTL_SECONDS) * 1000,
        invalidated: false,
        claims,
      };
    }
    if (refresh) response.refresh_token = refresh.value;
    const now = this.clock.now();
    const storedRefresh: StoredToken | null = refresh
      ? {
          ...refresh.stored,
          ...(previousRefreshHash ? { previousHash: previousRefreshHash, rotatedAt: now } : {}),
        }
      : null;
    await this.authorizations.save({
      ...authorization,
      access: { ...access.stored, scopes },
      refresh: storedRefresh,
      idToken,
    });
    return response;
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
