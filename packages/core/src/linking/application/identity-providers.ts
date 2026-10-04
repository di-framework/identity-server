import { Component, Container } from '@di-framework/core/decorators';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import { IssuerCanonicalizer } from '../../shared/domain/issuer.ts';
import { IDENTITY_SETTINGS } from '../../shared/domain/tokens.ts';
import type { IdentitySettings } from '../../shared/infrastructure/identity-settings.ts';

/** An allowlisted provider, resolved and validated (`IdentityLinkProvider`). */
export interface ResolvedProvider {
  name: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientId: string;
  clientSecret?: string;
  scopes: string[];
  freshAuthenticationParameter: string;
}

const DEFAULT_SCOPES = ['openid', 'profile', 'email'];
const DEFAULT_FRESH = 'prompt=login';

/** Built-in providers used when `IDENTITY_IDENTITY_LINK__PROVIDERS` does not name one. */
const BUILT_IN: Record<string, Omit<ResolvedProvider, 'name' | 'clientId' | 'scopes'>> = {
  google: {
    issuer: 'https://accounts.google.com',
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    freshAuthenticationParameter: 'prompt=login&max_age=0',
  },
  github: {
    issuer: 'https://github.com',
    authorizationEndpoint: 'https://github.com/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    jwksUri: '',
    freshAuthenticationParameter: DEFAULT_FRESH,
  },
  gitlab: {
    issuer: 'https://gitlab.com',
    authorizationEndpoint: 'https://gitlab.com/oauth/authorize',
    tokenEndpoint: 'https://gitlab.com/oauth/token',
    jwksUri: 'https://gitlab.com/oauth/discovery/keys',
    freshAuthenticationParameter: DEFAULT_FRESH,
  },
  okta: {
    issuer: 'https://okta.com',
    authorizationEndpoint: 'https://okta.com/oauth2/v1/authorize',
    tokenEndpoint: 'https://okta.com/oauth2/v1/token',
    jwksUri: 'https://okta.com/oauth2/v1/keys',
    freshAuthenticationParameter: DEFAULT_FRESH,
  },
};

/** Provider allowlist (`IdentityLinkService.resolveProvider`). Endpoints must be HTTPS or loopback. */
@Container()
export class IdentityProviders {
  constructor(
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(IssuerCanonicalizer) private readonly issuers: IssuerCanonicalizer,
  ) {}

  resolve(providerName: string, rawIssuer?: string | null): ResolvedProvider {
    const key = providerName.trim().toLowerCase();
    if (!key) throw new IdentityError(400, 'Identity provider is required');
    const configured = this.settings.identityLink.providers[key];
    let provider: ResolvedProvider;
    if (configured) {
      if (!configured.issuer || !configured.authorizationEndpoint) {
        throw new IdentityError(400, 'Configured identity provider is incomplete');
      }
      provider = {
        name: providerName.trim(),
        issuer: this.issuers.canonicalize(configured.issuer),
        authorizationEndpoint: configured.authorizationEndpoint,
        tokenEndpoint: configured.tokenEndpoint ?? '',
        jwksUri: configured.jwksUri ?? '',
        clientId: configured.clientId ?? this.settings.identityLink.clientId,
        clientSecret: configured.clientSecret,
        scopes: configured.scopes ?? DEFAULT_SCOPES,
        freshAuthenticationParameter: configured.freshAuthenticationParameter ?? DEFAULT_FRESH,
      };
    } else {
      const builtIn = BUILT_IN[key];
      if (!builtIn) throw new IdentityError(400, 'Identity provider is not configured');
      provider = {
        ...builtIn,
        name: providerName.trim(),
        clientId: this.settings.identityLink.clientId,
        scopes: DEFAULT_SCOPES,
      };
    }
    if (rawIssuer?.trim() && this.issuers.canonicalize(rawIssuer) !== provider.issuer) {
      throw new IdentityError(
        400,
        'Identity provider issuer does not match its configured provider',
      );
    }
    for (const endpoint of [
      provider.authorizationEndpoint,
      provider.tokenEndpoint,
      provider.jwksUri,
    ]) {
      if (endpoint) this.checkEndpoint(endpoint);
    }
    return provider;
  }

  canonical(issuer: string): string {
    return this.issuers.canonicalize(issuer);
  }

  private checkEndpoint(endpoint: string): void {
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new IdentityError(400, 'Identity provider endpoint must contain a host');
    }
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname.toLowerCase());
    if (url.protocol !== 'https:' && !loopback) {
      throw new IdentityError(400, 'Identity provider endpoints must use HTTPS');
    }
    if (url.username || url.password || url.hash || endpoint.includes('#')) {
      throw new IdentityError(
        400,
        'Identity provider endpoints must not contain user information or fragments',
      );
    }
  }
}
