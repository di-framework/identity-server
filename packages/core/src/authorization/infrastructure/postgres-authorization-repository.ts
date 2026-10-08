import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import type {
  Authorization,
  AuthorizationRepository,
  ConsumedToken,
  StoredToken,
  TokenKind,
} from '../domain/models.ts';

/**
 * `oauth2_authorization`, `oauth2_authorization_consent`, and `oauth_refresh_token_history`.
 *
 * Column names are Spring Authorization Server's, but this repository is the only reader:
 * token columns hold the SHA-256 hex of the token, and `attributes`/`*_metadata` hold JSON this
 * code defines. Rows are not interchangeable with Spring's `JdbcOAuth2AuthorizationService`.
 */
interface Row {
  id: string;
  registered_client_id: string;
  principal_name: string;
  authorization_grant_type: string;
  authorized_scopes: string | null;
  attributes: string | null;
  state: string | null;
  authorization_code_value: string | null;
  authorization_code_issued_at: unknown;
  authorization_code_expires_at: unknown;
  authorization_code_metadata: string | null;
  access_token_value: string | null;
  access_token_issued_at: unknown;
  access_token_expires_at: unknown;
  access_token_metadata: string | null;
  access_token_scopes: string | null;
  oidc_id_token_value: string | null;
  oidc_id_token_issued_at: unknown;
  oidc_id_token_expires_at: unknown;
  oidc_id_token_metadata: string | null;
  oidc_id_token_claims: string | null;
  refresh_token_value: string | null;
  refresh_token_issued_at: unknown;
  refresh_token_expires_at: unknown;
  refresh_token_metadata: string | null;
}

const COLUMNS: Record<TokenKind, string> = {
  code: 'authorization_code_value',
  access: 'access_token_value',
  refresh: 'refresh_token_value',
};

/** Columns `save` and `commitGrant` both write, in the order `tokenColumns` lists the values. */
const TOKEN_COLUMNS = [
  'authorized_scopes',
  'attributes',
  'state',
  'authorization_code_value',
  'authorization_code_issued_at',
  'authorization_code_expires_at',
  'authorization_code_metadata',
  'access_token_value',
  'access_token_issued_at',
  'access_token_expires_at',
  'access_token_metadata',
  'access_token_type',
  'access_token_scopes',
  'refresh_token_value',
  'refresh_token_issued_at',
  'refresh_token_expires_at',
  'refresh_token_metadata',
  'oidc_id_token_value',
  'oidc_id_token_issued_at',
  'oidc_id_token_expires_at',
  'oidc_id_token_metadata',
  'oidc_id_token_claims',
] as const;

function tokenColumns(authorization: Authorization): unknown[] {
  const token = (value: StoredToken | null) => [
    value?.hash ?? null,
    value ? new Date(value.issuedAt) : null,
    value ? new Date(value.expiresAt) : null,
    value ? JSON.stringify({ invalidated: value.invalidated }) : null,
  ];
  return [
    authorization.authorizedScopes.join(' '),
    JSON.stringify(authorization.attributes),
    authorization.state,
    ...token(authorization.code),
    ...token(authorization.access),
    authorization.access ? 'Bearer' : null,
    authorization.access ? authorization.access.scopes.join(' ') : null,
    ...token(authorization.refresh),
    ...token(authorization.idToken),
    authorization.idToken ? JSON.stringify(authorization.idToken.claims) : null,
  ];
}

@Container()
export class PostgresAuthorizationRepository implements AuthorizationRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  save(authorization: Authorization): Promise<void> {
    return this.db.write(
      `INSERT INTO oauth2_authorization (
         id, registered_client_id, principal_name, authorization_grant_type, ${TOKEN_COLUMNS.join(', ')}
       ) VALUES (?, ?, ?, ?, ${TOKEN_COLUMNS.map(() => '?').join(', ')})
       ON CONFLICT (id) DO UPDATE SET
         ${TOKEN_COLUMNS.map((column) => `${column} = EXCLUDED.${column}`).join(',\n         ')}`,
      [
        authorization.id,
        authorization.registeredClientId,
        authorization.principalName,
        authorization.grantType,
        ...tokenColumns(authorization),
      ],
    );
  }

  /**
   * The metadata column holds the JSON `save` writes, so an unused code is one whose metadata
   * does not say `"invalidated":true`. A rotated refresh token is one whose hash is no longer
   * the row's `refresh_token_value`.
   */
  async commitGrant(authorization: Authorization, consumed: ConsumedToken): Promise<boolean> {
    const guard =
      'code' in consumed
        ? `authorization_code_value = ?
           AND position('"invalidated":true' IN COALESCE(authorization_code_metadata, '')) = 0`
        : 'refresh_token_value = ?';
    const result = await this.db.run(
      `UPDATE oauth2_authorization SET
         ${TOKEN_COLUMNS.map((column) => `${column} = ?`).join(',\n         ')}
       WHERE id = ? AND ${guard}
       RETURNING 1`,
      [
        ...tokenColumns(authorization),
        authorization.id,
        'code' in consumed ? consumed.code : consumed.refresh,
      ],
    );
    return (result.changes ?? 0) > 0;
  }

  async findById(id: string): Promise<Authorization | undefined> {
    const row = await this.db.one<Row>(`SELECT * FROM oauth2_authorization WHERE id = ?`, [id]);
    return row ? this.authorization(row) : undefined;
  }

  async findByToken(
    kind: TokenKind,
    hash: string,
    lock = false,
  ): Promise<Authorization | undefined> {
    const row = await this.db.one<Row>(
      `SELECT * FROM oauth2_authorization WHERE ${COLUMNS[kind]} = ?${lock ? ' FOR UPDATE' : ''}`,
      [hash],
    );
    return row ? this.authorization(row) : undefined;
  }

  async findByState(hash: string): Promise<Authorization | undefined> {
    const row = await this.db.one<Row>(`SELECT * FROM oauth2_authorization WHERE state = ?`, [
      hash,
    ]);
    return row ? this.authorization(row) : undefined;
  }

  delete(id: string): Promise<void> {
    return this.db.write(`DELETE FROM oauth2_authorization WHERE id = ?`, [id]);
  }

  async deleteByPrincipal(principalName: string): Promise<number> {
    const result = await this.db.run(
      `DELETE FROM oauth2_authorization WHERE principal_name = ? RETURNING 1`,
      [principalName],
    );
    return result.changes ?? 0;
  }

  async findConsent(registeredClientId: string, principalName: string): Promise<string[]> {
    const row = await this.db.one<{ authorities: string }>(
      `SELECT authorities FROM oauth2_authorization_consent
       WHERE registered_client_id = ? AND principal_name = ?`,
      [registeredClientId, principalName],
    );
    if (!row) return [];
    return row.authorities
      .split(',')
      .filter((authority) => authority.startsWith('SCOPE_'))
      .map((authority) => authority.slice('SCOPE_'.length));
  }

  saveConsent(registeredClientId: string, principalName: string, scopes: string[]): Promise<void> {
    return this.db.write(
      `INSERT INTO oauth2_authorization_consent (registered_client_id, principal_name, authorities)
       VALUES (?, ?, ?)
       ON CONFLICT (registered_client_id, principal_name) DO UPDATE SET authorities = EXCLUDED.authorities`,
      [registeredClientId, principalName, scopes.map((scope) => `SCOPE_${scope}`).join(',')],
    );
  }

  rememberRefresh(hash: string, authorizationId: string, expiresAt: number): Promise<void> {
    return this.db.write(
      `INSERT INTO oauth_refresh_token_history (token_hash, authorization_id, expires_at)
       VALUES (?, ?, ?) ON CONFLICT (token_hash) DO NOTHING`,
      [hash, authorizationId, new Date(expiresAt)],
    );
  }

  async claimReplayedRefresh(hash: string, now: number): Promise<string | undefined> {
    const row = await this.db.one<{ authorization_id: string }>(
      `UPDATE oauth_refresh_token_history SET reused_at = ?
       WHERE token_hash = ? AND reused_at IS NULL AND expires_at > ?
       RETURNING authorization_id`,
      [new Date(now), hash, new Date(now)],
    );
    return row?.authorization_id;
  }

  private authorization(row: Row): Authorization {
    const token = (
      value: string | null,
      issued: unknown,
      expires: unknown,
      metadata: string | null,
    ): StoredToken | null =>
      value
        ? {
            hash: value,
            issuedAt: Timestamps.ms(issued),
            expiresAt: Timestamps.ms(expires),
            invalidated: this.json(metadata).invalidated === true,
          }
        : null;

    const access = token(
      row.access_token_value,
      row.access_token_issued_at,
      row.access_token_expires_at,
      row.access_token_metadata,
    );
    const idToken = token(
      row.oidc_id_token_value,
      row.oidc_id_token_issued_at,
      row.oidc_id_token_expires_at,
      row.oidc_id_token_metadata,
    );
    return {
      id: row.id,
      registeredClientId: row.registered_client_id,
      principalName: row.principal_name,
      grantType: row.authorization_grant_type,
      authorizedScopes: this.scopes(row.authorized_scopes),
      attributes: this.json(row.attributes),
      state: row.state,
      code: token(
        row.authorization_code_value,
        row.authorization_code_issued_at,
        row.authorization_code_expires_at,
        row.authorization_code_metadata,
      ),
      access: access ? { ...access, scopes: this.scopes(row.access_token_scopes) } : null,
      refresh: token(
        row.refresh_token_value,
        row.refresh_token_issued_at,
        row.refresh_token_expires_at,
        row.refresh_token_metadata,
      ),
      idToken: idToken ? { ...idToken, claims: this.json(row.oidc_id_token_claims) } : null,
    };
  }

  private scopes(value: string | null): string[] {
    return (value ?? '').split(' ').filter((scope) => scope.length > 0);
  }

  private json(value: string | null): Record<string, unknown> {
    if (!value) return {};
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  }
}
