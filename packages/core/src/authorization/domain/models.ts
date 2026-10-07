/** Token lifetimes every client gets (`SecurityConfiguration.standardTokenSettings`). */
export const TOKEN_SETTINGS = {
  authorizationCodeTtlSeconds: 60,
  accessTokenTtlSeconds: 600,
  refreshTokenTtlSeconds: 30 * 24 * 60 * 60,
  reuseRefreshTokens: false,
  accessTokenFormat: 'reference',
} as const;

export type TokenSettings = typeof TOKEN_SETTINGS;

export interface ClientSettings {
  requireProofKey: boolean;
  requireAuthorizationConsent: boolean;
}

/** One `oauth2_registered_client` row joined with its `oauth_client_lifecycle` row. */
export interface RegisteredClient {
  /** Row id, which `oauth2_authorization.registered_client_id` references. */
  id: string;
  clientId: string;
  clientName: string;
  secretHash: string | null;
  authenticationMethods: string[];
  grantTypes: string[];
  redirectUris: string[];
  scopes: string[];
  settings: ClientSettings;
  organizationSlug: string | null;
  revokedAt: number | null;
  createdAt: number;
}

/** A stored token. Only the SHA-256 hex of the value is persisted. */
export interface StoredToken {
  hash: string;
  issuedAt: number;
  expiresAt: number;
  invalidated: boolean;
}

export interface Authorization {
  id: string;
  registeredClientId: string;
  principalName: string;
  grantType: string;
  authorizedScopes: string[];
  /** Request context: redirect URI, PKCE challenge, nonce, auth time, requested scopes. */
  attributes: Record<string, unknown>;
  /** SHA-256 of the `state` parameter while the request waits for consent. */
  state: string | null;
  code: StoredToken | null;
  access: (StoredToken & { scopes: string[] }) | null;
  refresh: StoredToken | null;
  idToken: (StoredToken & { claims: Record<string, unknown> }) | null;
}

export type TokenKind = 'code' | 'access' | 'refresh';

export interface AuthorizationRepository {
  save(authorization: Authorization): Promise<void>;
  findById(id: string): Promise<Authorization | undefined>;
  /** Finds by token hash. `lock` takes `FOR UPDATE` inside the caller's transaction. */
  findByToken(kind: TokenKind, hash: string, lock?: boolean): Promise<Authorization | undefined>;
  /** Pending authorization waiting for consent, by the SHA-256 of its consent `state`. */
  findByState(hash: string): Promise<Authorization | undefined>;
  delete(id: string): Promise<void>;
  /** Deletes every authorization (and so every token) for a principal. */
  deleteByPrincipal(principalName: string): Promise<number>;
  findConsent(registeredClientId: string, principalName: string): Promise<string[]>;
  saveConsent(registeredClientId: string, principalName: string, scopes: string[]): Promise<void>;
  /** `ON CONFLICT DO NOTHING` insert of a rotated refresh token hash. */
  rememberRefresh(hash: string, authorizationId: string, expiresAt: number): Promise<void>;
  /** Locks an unexpired, unused history row and returns its authorization id. */
  lockReplayedRefresh(hash: string, now: number): Promise<string | undefined>;
  markRefreshReused(hash: string, now: number): Promise<void>;
}

export interface NewRegisteredClient {
  clientId: string;
  clientName: string;
  secretHash: string;
  authenticationMethods: string[];
  grantTypes: string[];
  redirectUris: string[];
  scopes: string[];
  settings: ClientSettings;
  organizationSlug: string | null;
}

export interface RegisteredClientRepository {
  find(clientId: string): Promise<RegisteredClient | undefined>;
  /** Clients with a lifecycle row, by client id; only one organization's when a slug is given. */
  list(organizationSlug?: string): Promise<RegisteredClient[]>;
  findById(id: string): Promise<RegisteredClient | undefined>;
  insert(client: NewRegisteredClient): Promise<void>;
  /** Replaces metadata and, when `secretHash` is set, the secret. */
  update(clientId: string, changes: Partial<Omit<NewRegisteredClient, 'clientId'>>): Promise<void>;
  ensureLifecycle(clientId: string, organizationSlug: string | null): Promise<void>;
}

/** Error codes from RFC 6749 section 5.2. */
export class OAuthError extends Error {
  constructor(
    readonly code: string,
    readonly status = 400,
    readonly description?: string,
  ) {
    super(code);
    this.name = 'OAuthError';
  }
}
