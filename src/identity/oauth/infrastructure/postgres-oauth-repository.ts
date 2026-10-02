import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import type { NewOAuthClient, OAuthRepository } from '../domain/oauth-client.ts';
import { OAuthClient } from '../domain/oauth-client.ts';

interface ClientRow {
  client_id: string;
  organization_slug: string | null;
  redirect_uris: string | null;
  scopes: string | null;
  authorization_grant_types: string;
  revoked_at: unknown;
  created_at: unknown;
}

@Container()
export class PostgresOAuthRepository implements OAuthRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  async list(): Promise<OAuthClient[]> {
    const rows = await this.db.query<ClientRow>(
      `SELECT c.client_id, l.organization_slug, c.redirect_uris, c.scopes, c.authorization_grant_types,
              l.revoked_at, l.created_at
       FROM oauth_client_lifecycle l
       JOIN oauth2_registered_client c ON c.client_id = l.client_id
       ORDER BY c.client_id`,
    );
    return rows.map((row) => this.client(row));
  }

  async find(clientId: string): Promise<OAuthClient | undefined> {
    const row = await this.db.one<ClientRow>(
      `SELECT c.client_id, l.organization_slug, c.redirect_uris, c.scopes, c.authorization_grant_types,
              l.revoked_at, l.created_at
       FROM oauth_client_lifecycle l
       JOIN oauth2_registered_client c ON c.client_id = l.client_id
       WHERE l.client_id = ?`,
      [clientId],
    );
    return row ? this.client(row) : undefined;
  }

  async insert(client: NewOAuthClient): Promise<void> {
    await this.db.write(
      `INSERT INTO oauth2_registered_client (
         id, client_id, client_secret, client_name, client_authentication_methods,
         authorization_grant_types, redirect_uris, scopes, client_settings, token_settings
       ) VALUES (?, ?, ?, ?, 'client_secret_basic', ?, ?, ?, '{}', '{}')`,
      [
        crypto.randomUUID(),
        client.clientId,
        client.secretHash,
        client.clientId,
        this.grants(client.browser),
        client.redirectUris.join(','),
        client.scopes.join(','),
      ],
    );
    await this.db.write(
      `INSERT INTO oauth_client_lifecycle (client_id, organization_slug) VALUES (?, ?)`,
      [client.clientId, client.organizationSlug],
    );
  }

  update(client: Omit<NewOAuthClient, 'secretHash'>): Promise<void> {
    return this.db.transaction(async () => {
      await this.db.write(
        `UPDATE oauth2_registered_client
         SET authorization_grant_types = ?, redirect_uris = ?, scopes = ?
         WHERE client_id = ?`,
        [
          this.grants(client.browser),
          client.redirectUris.join(','),
          client.scopes.join(','),
          client.clientId,
        ],
      );
      await this.db.write(
        `UPDATE oauth_client_lifecycle SET organization_slug = ? WHERE client_id = ?`,
        [client.organizationSlug, client.clientId],
      );
    });
  }

  rotateSecret(clientId: string, secretHash: string): Promise<void> {
    return this.db.write(
      `UPDATE oauth2_registered_client SET client_secret = ? WHERE client_id = ?`,
      [secretHash, clientId],
    );
  }

  revoke(clientId: string): Promise<void> {
    return this.db.write(
      `UPDATE oauth_client_lifecycle SET revoked_at = now() WHERE client_id = ? AND revoked_at IS NULL`,
      [clientId],
    );
  }

  countActive(slug: string): Promise<number> {
    return this.db.count(
      `SELECT count(*)::int AS count FROM oauth_client_lifecycle
       WHERE organization_slug = ? AND revoked_at IS NULL`,
      [slug],
    );
  }

  private grants(browser: boolean): string {
    return browser ? 'authorization_code,refresh_token' : 'client_credentials';
  }

  private client(row: ClientRow): OAuthClient {
    return new OAuthClient(
      row.client_id,
      row.organization_slug,
      this.csv(row.redirect_uris),
      this.csv(row.scopes),
      row.authorization_grant_types.split(',').includes('authorization_code'),
      row.revoked_at == null ? null : Timestamps.iso(row.revoked_at),
      Timestamps.iso(row.created_at),
    );
  }

  private csv(value: string | null): string[] {
    if (!value) return [];
    return value.split(',').filter((item) => item.length > 0);
  }
}
