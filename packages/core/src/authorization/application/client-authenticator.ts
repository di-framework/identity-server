import { Component, Container } from '@di-framework/core/decorators';
import { REGISTERED_CLIENTS } from '../../shared/domain/tokens.ts';
import { PasswordHasher } from '../../shared/infrastructure/crypto/passwords.ts';
import {
  OAuthError,
  type RegisteredClient,
  type RegisteredClientRepository,
} from '../domain/models.ts';

/**
 * Client authentication for the token, introspection, and revocation endpoints:
 * `client_secret_basic` (RFC 6749 section 2.3.1 form-encoded credentials in Basic auth),
 * `client_secret_post`, or, where the endpoint allows it, `none` for a public client that sends
 * only `client_id` (RFC 8252 native apps; PKCE is what protects its grants). A revoked lifecycle
 * row rejects the client.
 */
@Container()
export class ClientAuthenticator {
  constructor(
    @Component(REGISTERED_CLIENTS) private readonly clients: RegisteredClientRepository,
    @Component(PasswordHasher) private readonly passwords: PasswordHasher,
  ) {}

  /**
   * `allowPublic` admits a `none` client (token and revocation endpoints); introspection stays
   * confidential-only, as RFC 7662 requires.
   */
  async authenticate(
    authorization: string | null,
    form: URLSearchParams,
    allowPublic = false,
  ): Promise<RegisteredClient> {
    const credentials = this.credentials(authorization, form, allowPublic);
    const client = await this.clients.find(credentials.clientId);
    if (!client?.authenticationMethods.includes(credentials.method)) {
      throw new OAuthError('invalid_client', 401);
    }
    if (credentials.method === 'none') {
      // A public client has no secret to check; it must be registered for PKCE.
      if (!client.settings.requireProofKey) throw new OAuthError('invalid_client', 401);
    } else if (!(await this.passwords.verify(credentials.secret, client.secretHash))) {
      throw new OAuthError('invalid_client', 401);
    }
    if (client.revokedAt !== null) throw new OAuthError('invalid_client', 401);
    return client;
  }

  private credentials(
    authorization: string | null,
    form: URLSearchParams,
    allowPublic: boolean,
  ): { clientId: string; secret: string; method: string } {
    if (authorization?.toLowerCase().startsWith('basic ')) {
      const decoded = Buffer.from(authorization.slice(6).trim(), 'base64').toString('utf8');
      const separator = decoded.indexOf(':');
      if (separator < 0) throw new OAuthError('invalid_client', 401);
      try {
        return {
          clientId: decodeURIComponent(decoded.slice(0, separator).replaceAll('+', ' ')),
          secret: decodeURIComponent(decoded.slice(separator + 1).replaceAll('+', ' ')),
          method: 'client_secret_basic',
        };
      } catch {
        throw new OAuthError('invalid_client', 401);
      }
    }
    const clientId = form.get('client_id');
    const secret = form.get('client_secret');
    if (!clientId) throw new OAuthError('invalid_client', 401);
    if (!secret) {
      if (!allowPublic) throw new OAuthError('invalid_client', 401);
      return { clientId, secret: '', method: 'none' };
    }
    return { clientId, secret, method: 'client_secret_post' };
  }
}
