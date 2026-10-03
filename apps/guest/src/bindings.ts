import { Config, OutgoingHttp, Postgres, WasmCloudBinding } from '@di-framework/bindings';
import { Container } from '@di-framework/core/decorators';
import { assertBatch, type PgText, postgresError, readRows } from './pg.ts';

@WasmCloudBinding('identity-database', {
  serviceName: 'directory',
})
@Container()
export class IdentityDatabase extends Postgres {
  async batch(sql: string): Promise<void> {
    try {
      assertBatch(await this.queryBatch(sql));
    } catch (error) {
      throw postgresError(error);
    }
  }

  async rows(sql: string, params: readonly PgText[] = []): Promise<Record<string, unknown>[]> {
    try {
      return await readRows(await this.query(sql, params));
    } catch (error) {
      throw postgresError(error);
    }
  }
}

/** Non-secret settings. URLs and passwords stay in `identity_runtime_secret`. */
@WasmCloudBinding('identity-config', {
  config: {
    AUTH_SIGNING_ALGORITHM: 'RS256',
    SMTP_PORT: '1025',
    SMTP_FROM: 'no-reply@identity.local',
    SMTP_AUTH: 'false',
    SMTP_STARTTLS: 'false',
    SMTP_SSL_ENABLE: 'false',
    SERVER_SERVLET_SESSION_COOKIE_SECURE: 'false',
    AUTH_BOOTSTRAP_ORGANIZATION_SLUG: 'platform',
    AUTH_BOOTSTRAP_ORGANIZATION_NAME: 'Platform',
    AUTH_BOOTSTRAP_OWNER_EMAIL: 'owner@identity.local',
    AUTH_BOOTSTRAP_OWNER_LOGIN: 'owner',
    AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME: 'Owner',
    AUTH_BOOTSTRAP_VIEWER_EMAIL: 'viewer@identity.local',
    AUTH_BOOTSTRAP_VIEWER_LOGIN: 'viewer',
    AUTH_BOOTSTRAP_VIEWER_DISPLAY_NAME: 'Viewer',
    AUTH_ACCESS_CLIENT_ID: 'access',
    AUTH_DIRECTORY_CLIENT_ID: 'directory',
    AUTH_PROVISIONER_CLIENT_ID: 'provisioner',
    AUTH_IDENTITY_LINK_CLIENT_ID: 'gsio-auth-client',
    GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED: 'true',
    GSIO_IDENTITY_NOTIFICATION_DELAY_MS: '5000',
  },
})
@Container()
export class IdentityConfig extends Config {}

/** Outbound HTTPS for identity-provider token and JWKS requests. */
@WasmCloudBinding('identity-http')
@Container()
export class IdentityHttp extends OutgoingHttp {}
