import { Component, Container } from '@di-framework/core/decorators';
import { REGISTERED_CLIENTS } from '../../shared/domain/tokens.ts';
import { PasswordHasher } from '../../shared/infrastructure/crypto/passwords.ts';
import {
  OAuthError,
  type RegisteredClient,
  type RegisteredClientRepository,
} from '../domain/models.ts';

/**
 * Confidential-client authentication for the token, introspection, and revocation endpoints:
 * `client_secret_basic` (RFC 6749 section 2.3.1 form-encoded credentials in Basic auth) or
 * `client_secret_post`. A revoked lifecycle row rejects the client.
 */
@Container()
export class ClientAuthenticator {
  constructor(
    @Component(REGISTERED_CLIENTS) private readonly clients: RegisteredClientRepository,
    @Component(PasswordHasher) private readonly passwords: PasswordHasher,
  ) {}

  async authenticate(
    authorization: string | null,
    form: URLSearchParams,
  ): Promise<RegisteredClient> {
    const credentials = this.credentials(authorization, form);
    const client = await this.clients.find(credentials.clientId);
    if (!client || !client.authenticationMethods.includes(credentials.method)) {
      throw new OAuthError('invalid_client', 401);
    }
    if (!(await this.passwords.verify(credentials.secret, client.secretHash))) {
      throw new OAuthError('invalid_client', 401);
    }
    if (client.revokedAt !== null) throw new OAuthError('invalid_client', 401);
    return client;
  }

  private credentials(
    authorization: string | null,
    form: URLSearchParams,
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
    if (!clientId || !secret) throw new OAuthError('invalid_client', 401);
    return { clientId, secret, method: 'client_secret_post' };
  }
}
