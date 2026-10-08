import { Component, Container } from '@di-framework/core/decorators';
import { IDENTITY_SETTINGS, SIGNING_KEYS } from '../../shared/domain/tokens.ts';
import type { SigningKeys } from '../../shared/infrastructure/crypto/signing-keys.ts';
import type { IdentitySettings } from '../../shared/infrastructure/identity-settings.ts';

const AUTH_METHODS = ['client_secret_basic', 'client_secret_post'];
/** Token and revocation also take a public client (`client_id` only, PKCE); introspection does not. */
const PUBLIC_AUTH_METHODS = [...AUTH_METHODS, 'none'];

/** `/.well-known/*` documents and JWKS, from the configured issuer and signing keys. */
@Container()
export class ServerMetadata {
  constructor(
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(SIGNING_KEYS) private readonly keys: SigningKeys,
  ) {}

  authorizationServer(): Record<string, unknown> {
    const issuer = this.settings.issuer;
    return {
      issuer,
      authorization_endpoint: `${issuer}/oauth2/authorize`,
      token_endpoint: `${issuer}/oauth2/token`,
      token_endpoint_auth_methods_supported: PUBLIC_AUTH_METHODS,
      jwks_uri: `${issuer}/oauth2/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
      revocation_endpoint: `${issuer}/oauth2/revoke`,
      revocation_endpoint_auth_methods_supported: PUBLIC_AUTH_METHODS,
      introspection_endpoint: `${issuer}/oauth2/introspect`,
      introspection_endpoint_auth_methods_supported: AUTH_METHODS,
      code_challenge_methods_supported: ['S256'],
    };
  }

  openidConfiguration(): Record<string, unknown> {
    return {
      ...this.authorizationServer(),
      userinfo_endpoint: `${this.settings.issuer}/userinfo`,
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: [this.keys.algorithm],
      scopes_supported: ['openid'],
    };
  }

  jwks(): Record<string, unknown> {
    return this.keys.jwks();
  }
}
