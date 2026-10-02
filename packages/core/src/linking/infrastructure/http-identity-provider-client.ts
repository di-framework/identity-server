import { Component, Container } from '@di-framework/core/decorators';
import type { Clock } from '../../shared/domain/clock.ts';
import { CLOCK } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import { verifyJws } from '../../shared/infrastructure/crypto/signing-keys.ts';
import type { ResolvedProvider } from '../application/identity-providers.ts';
import type { LinkFlow } from '../domain/identity-link.ts';

export interface ExternalIdentity {
  issuer: string;
  subject: string;
  email: string | null;
}

/** Exchanges a provider authorization code for a verified external identity. */
export interface IdentityProviderClient {
  exchange(
    provider: ResolvedProvider,
    flow: LinkFlow,
    code: string,
    redirectUri: string,
  ): Promise<ExternalIdentity>;
}

/** Outbound HTTP used for the token and JWKS requests. */
export type HttpFetch = (url: string, init?: RequestInit) => Promise<Response>;

/** Clock skew allowed on `exp`, `nbf`, and `auth_time`, as Spring's JWT validators and the auth server. */
const SKEW_MS = 60_000;

/**
 * `HttpExternalIdentityProviderClient`: PKCE code exchange, then an RS256 ID token verified
 * against the provider JWKS with issuer, audience, expiry, nonce, and fresh `auth_time` checks.
 * Every failure is an Error with a generic message; callers show one generic page.
 */
@Container()
export class HttpIdentityProviderClient implements IdentityProviderClient {
  constructor(
    @Component(CLOCK) private readonly clock: Clock,
    private readonly http: HttpFetch = (url, init) => fetch(url, init),
  ) {}

  async exchange(
    provider: ResolvedProvider,
    flow: LinkFlow,
    code: string,
    redirectUri: string,
  ): Promise<ExternalIdentity> {
    if (!provider.tokenEndpoint || !provider.jwksUri) {
      throw new Error('The selected identity provider is not configured for callback verification');
    }
    if (!Hashing.equal(Hashing.pkceChallenge(flow.codeVerifier), flow.codeChallenge)) {
      throw new Error('The link transaction PKCE challenge is invalid');
    }
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: provider.clientId,
      code_verifier: flow.codeVerifier,
    });
    if (provider.clientSecret) form.set('client_secret', provider.clientSecret);
    const response = await this.http(provider.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: form,
    });
    if (!response.ok) throw new Error('External identity authorization could not be completed');
    const body = await this.object(response);
    const idToken = typeof body.id_token === 'string' ? body.id_token : '';
    if (!idToken)
      throw new Error('External identity provider did not return a signed identity token');
    const jwks = await this.object(
      await this.http(provider.jwksUri, { headers: { accept: 'application/json' } }),
    );
    const keys = Array.isArray(jwks.keys) ? (jwks.keys as Record<string, unknown>[]) : [];
    const claims = verifyJws(idToken, keys, ['RS256']);
    this.validate(provider, flow, claims);
    return {
      issuer: String(claims.iss),
      subject: String(claims.sub),
      email: typeof claims.email === 'string' && claims.email.trim() ? claims.email.trim() : null,
    };
  }

  private validate(
    provider: ResolvedProvider,
    flow: LinkFlow,
    claims: Record<string, unknown>,
  ): void {
    const now = this.clock.now();
    if (claims.iss !== provider.issuer)
      throw new Error('External identity token issuer is invalid');
    if (typeof claims.exp !== 'number' || claims.exp * 1000 + SKEW_MS <= now) {
      throw new Error('External identity token has expired');
    }
    if (typeof claims.nbf === 'number' && claims.nbf * 1000 - SKEW_MS > now) {
      throw new Error('External identity token is not yet valid');
    }
    if (typeof claims.sub !== 'string' || !claims.sub.trim()) {
      throw new Error('External identity token did not contain a subject');
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(provider.clientId)) {
      throw new Error('External identity token audience did not match the configured client');
    }
    if (claims.nonce !== flow.nonce) {
      throw new Error('External identity token nonce did not match the link transaction');
    }
    if (
      typeof claims.auth_time !== 'number' ||
      claims.auth_time * 1000 < flow.createdAt - SKEW_MS
    ) {
      throw new Error('External identity authentication was not fresh');
    }
  }

  private async object(response: Response): Promise<Record<string, unknown>> {
    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch {
      throw new Error('External identity provider returned an invalid token response');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('External identity provider returned an invalid token response');
    }
    return parsed as Record<string, unknown>;
  }
}
