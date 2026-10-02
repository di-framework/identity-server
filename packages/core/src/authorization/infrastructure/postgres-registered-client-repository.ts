import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import {
  type ClientSettings,
  type NewRegisteredClient,
  type RegisteredClient,
  type RegisteredClientRepository,
  TOKEN_SETTINGS,
} from '../domain/models.ts';

interface Row {
  id: string;
  client_id: string;
  client_name: string;
  client_secret: string | null;
  client_authentication_methods: string;
  authorization_grant_types: string;
  redirect_uris: string | null;
  scopes: string;
  client_settings: string;
  organization_slug: string | null;
  revoked_at: unknown;
  created_at: unknown;
}

const SELECT = `SELECT c.id, c.client_id, c.client_name, c.client_secret, c.client_authentication_methods,
         c.authorization_grant_types, c.redirect_uris, c.scopes, c.client_settings,
         l.organization_slug, l.revoked_at, COALESCE(l.created_at, c.client_id_issued_at) AS created_at
  FROM oauth2_registered_client c
  LEFT JOIN oauth_client_lifecycle l ON l.client_id = c.client_id`;

/** Comma-separated list columns and JSON settings columns of `oauth2_registered_client`. */
export class ClientColumns {
  static list(value: readonly string[]): string {
    return value.join(',');
  }

  static parse(value: string | null): string[] {
    if (!value) return [];
    return value
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }

  static settings(settings: ClientSettings): string {
    return JSON.stringify(settings);
  }

  static tokenSettings(): string {
    return JSON.stringify(TOKEN_SETTINGS);
  }

  static readSettings(value: string): ClientSettings {
    let parsed: Record<string, unknown> = {};
    try {
      const candidate: unknown = JSON.parse(value);
      if (typeof candidate === 'object' && candidate !== null) {
        parsed = candidate as Record<string, unknown>;
      }
    } catch {
      parsed = {};
    }
    return {
      requireProofKey: parsed.requireProofKey === true,
      requireAuthorizationConsent: parsed.requireAuthorizationConsent === true,
    };
  }
}

@Container()
export class PostgresRegisteredClientRepository implements RegisteredClientRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  async find(clientId: string): Promise<RegisteredClient | undefined> {
    const row = await this.db.one<Row>(`${SELECT} WHERE c.client_id = ?`, [clientId]);
    return row ? this.client(row) : undefined;
  }

  async list(organizationSlug?: string): Promise<RegisteredClient[]> {
    const rows =
      organizationSlug === undefined
        ? await this.db.query<Row>(`${SELECT} WHERE l.client_id IS NOT NULL ORDER BY c.client_id`)
        : await this.db.query<Row>(`${SELECT} WHERE l.organization_slug = ? ORDER BY c.client_id`, [
            organizationSlug,
          ]);
    return rows.map((row) => this.client(row));
  }

  async findById(id: string): Promise<RegisteredClient | undefined> {
    const row = await this.db.one<Row>(`${SELECT} WHERE c.id = ?`, [id]);
    return row ? this.client(row) : undefined;
  }

  insert(client: NewRegisteredClient): Promise<void> {
    return this.db.transaction(async () => {
      await this.db.write(
        `INSERT INTO oauth2_registered_client (
           id, client_id, client_secret, client_name, client_authentication_methods,
           authorization_grant_types, redirect_uris, scopes, client_settings, token_settings
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          crypto.randomUUID(),
          client.clientId,
          client.secretHash,
          client.clientName,
          ClientColumns.list(client.authenticationMethods),
          ClientColumns.list(client.grantTypes),
          ClientColumns.list(client.redirectUris),
          ClientColumns.list(client.scopes),
          ClientColumns.settings(client.settings),
          ClientColumns.tokenSettings(),
        ],
      );
      await this.db.write(
        `INSERT INTO oauth_client_lifecycle (client_id, organization_slug) VALUES (?, ?)`,
        [client.clientId, client.organizationSlug],
      );
    });
  }

  async update(
    clientId: string,
    changes: Partial<Omit<NewRegisteredClient, 'clientId'>>,
  ): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];
    const add = (column: string, value: unknown) => {
      sets.push(`${column} = ?`);
      params.push(value);
    };
    if (changes.secretHash !== undefined) add('client_secret', changes.secretHash);
    if (changes.clientName !== undefined) add('client_name', changes.clientName);
    if (changes.authenticationMethods !== undefined) {
      add('client_authentication_methods', ClientColumns.list(changes.authenticationMethods));
    }
    if (changes.grantTypes !== undefined) {
      add('authorization_grant_types', ClientColumns.list(changes.grantTypes));
    }
    if (changes.redirectUris !== undefined) {
      add('redirect_uris', ClientColumns.list(changes.redirectUris));
    }
    if (changes.scopes !== undefined) add('scopes', ClientColumns.list(changes.scopes));
    if (changes.settings !== undefined)
      add('client_settings', ClientColumns.settings(changes.settings));
    await this.db.transaction(async () => {
      if (sets.length > 0) {
        await this.db.write(
          `UPDATE oauth2_registered_client SET ${sets.join(', ')} WHERE client_id = ?`,
          [...params, clientId],
        );
      }
      if (changes.organizationSlug !== undefined) {
        await this.db.write(
          `UPDATE oauth_client_lifecycle SET organization_slug = ? WHERE client_id = ?`,
          [changes.organizationSlug, clientId],
        );
      }
    });
  }

  ensureLifecycle(clientId: string, organizationSlug: string | null): Promise<void> {
    return this.db.write(
      `INSERT INTO oauth_client_lifecycle (client_id, organization_slug) VALUES (?, ?)
       ON CONFLICT (client_id) DO NOTHING`,
      [clientId, organizationSlug],
    );
  }

  private client(row: Row): RegisteredClient {
    return {
      id: row.id,
      clientId: row.client_id,
      clientName: row.client_name,
      secretHash: row.client_secret,
      authenticationMethods: ClientColumns.parse(row.client_authentication_methods),
      grantTypes: ClientColumns.parse(row.authorization_grant_types),
      redirectUris: ClientColumns.parse(row.redirect_uris),
      scopes: ClientColumns.parse(row.scopes),
      settings: ClientColumns.readSettings(row.client_settings),
      organizationSlug: row.organization_slug,
      revokedAt: row.revoked_at == null ? null : Timestamps.ms(row.revoked_at),
      createdAt: Timestamps.ms(row.created_at),
    };
  }
}
