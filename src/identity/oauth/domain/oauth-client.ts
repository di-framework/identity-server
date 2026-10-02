export class OAuthClient {
  constructor(
    readonly clientId: string,
    readonly organizationSlug: string | null,
    readonly redirectUris: string[],
    readonly scopes: string[],
    readonly browser: boolean,
    readonly revokedAt: string | null,
    readonly createdAt: string,
  ) {}
}

export interface NewOAuthClient {
  clientId: string;
  organizationSlug: string | null;
  redirectUris: string[];
  scopes: string[];
  browser: boolean;
  secretHash: string;
}

export interface OAuthRepository {
  list(): Promise<OAuthClient[]>;
  find(clientId: string): Promise<OAuthClient | undefined>;
  insert(client: NewOAuthClient): Promise<void>;
  update(client: Omit<NewOAuthClient, 'secretHash'>): Promise<void>;
  rotateSecret(clientId: string, secretHash: string): Promise<void>;
  revoke(clientId: string): Promise<void>;
  countActive(slug: string): Promise<number>;
}
