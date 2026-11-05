/** How a client authenticates at the token endpoint; `none` is a public PKCE client. */
export type TokenEndpointAuthMethod = 'client_secret_basic' | 'none';

export const TOKEN_ENDPOINT_AUTH_METHODS: readonly TokenEndpointAuthMethod[] = [
  'client_secret_basic',
  'none',
];

export function isTokenEndpointAuthMethod(value: string): value is TokenEndpointAuthMethod {
  return (TOKEN_ENDPOINT_AUTH_METHODS as readonly string[]).includes(value);
}

/** An admin-registered client: its `oauth2_registered_client` row plus its lifecycle row. */
export interface OAuthClient {
  clientId: string;
  /** Null only for bootstrap clients; the admin API requires a slug. */
  organizationSlug: string | null;
  redirectUris: string[];
  scopes: string[];
  /** Token audiences; empty means tokens carry the client id alone. */
  audiences: string[];
  /** Authorization code with refresh tokens, PKCE, and consent, instead of client credentials. */
  browser: boolean;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  revokedAt: string | null;
  createdAt: string;
}

/** The metadata of a client to register or replace. */
export type OAuthClientMetadata = Omit<OAuthClient, 'revokedAt' | 'createdAt'>;

export interface NewOAuthClient extends OAuthClientMetadata {
  /** Null for a public client (`tokenEndpointAuthMethod` is `none`). */
  secretHash: string | null;
}

export interface OAuthRepository {
  list(): Promise<OAuthClient[]>;
  find(clientId: string): Promise<OAuthClient | undefined>;
  insert(client: NewOAuthClient): Promise<void>;
  update(client: OAuthClientMetadata): Promise<void>;
  rotateSecret(clientId: string, secretHash: string): Promise<void>;
  revoke(clientId: string): Promise<void>;
  countActive(slug: string): Promise<number>;
  /** Runs `fn` in one transaction where the database offers one; statements inside it join it. */
  transaction<T>(fn: () => Promise<T>): Promise<T>;
}
