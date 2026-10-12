import { Config, OutgoingHttp, WasmCloudBinding } from '@di-framework/bindings';
import { Container } from '@di-framework/core/decorators';

/**
 * Non-secret settings. URLs, keys and passwords come from the `identity-control` Secret through
 * the WASI environment (see `settings.ts`). The database is the composed pglite provider
 * (`database.ts`), not a binding.
 */
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
