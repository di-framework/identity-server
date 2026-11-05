import type { RegisteredClient } from './models.ts';

type Audienced = Pick<RegisteredClient, 'clientId' | 'audiences'>;

/**
 * `aud` of an access or refresh token, as introspection reports it (RFC 7662 section 2.2): the
 * audiences configured for the client, or the client id alone when none are.
 */
export function tokenAudience(client: Audienced): string[] {
  return client.audiences.length > 0 ? [...client.audiences] : [client.clientId];
}

/**
 * `aud` of an ID token: the client id first, because OpenID Connect Core section 2 requires the
 * relying party among the audiences, then the configured audiences.
 */
export function idTokenAudience(client: Audienced): string[] {
  return [...new Set([client.clientId, ...client.audiences])];
}
