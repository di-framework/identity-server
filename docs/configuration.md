# Configuration and operations

The server reads the same environment names as the GSIO Auth Server's `application.yml`, so a
deployment's encrypted Pulumi or Compose inputs carry over. Any value can also be set with an
`IDENTITY_` double-underscore key (for example `IDENTITY_SERVER__HOST=127.0.0.1`), which wins over
the plain name.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `PORT` | `4180` | Listen port. `IDENTITY_SERVER__HOST` sets the listen address (default `0.0.0.0`). |
| `ISSUER_URL` | `http://localhost:4180` | OIDC issuer: discovery, token `iss`, and directory member `issuer`. |
| `AUTH_PUBLIC_ORIGIN` | the issuer | Browser-visible origin for passwordless links and the identity-link callback. |
| `SERVER_SERVLET_SESSION_COOKIE_SECURE` | `true` | Sets `Secure` on the session and passwordless cookies. Use `false` only for local HTTP. |
| `DATABASE_URL` | `postgres://identity:identity@127.0.0.1:5432/identity` | Postgres URL (`IDENTITY_DATABASE__URL` also works). `IDENTITY_DATABASE__POOL_MAX` sets the pool size (8). |
| `AUTH_ACTIVE_PRIVATE_JWK` | required | Private signing JWK with a `kid`. Startup fails without it. |
| `AUTH_PREVIOUS_PUBLIC_JWK_SET` | empty | `{"keys":[...]}` of public keys kept on JWKS during rotation. Private material fails startup. |
| `AUTH_SIGNING_ALGORITHM` | `RS256` | `RS256` (RSA key) or `ML-DSA-65` (RFC 9964 AKP key). |
| `SMTP_HOST`, `SMTP_PORT` (587), `SMTP_USERNAME`, `SMTP_PASSWORD` | empty | Mail relay. Without a host, every send fails and `/ready` reports `smtp: false`. |
| `SMTP_AUTH` (`true`), `SMTP_STARTTLS` (`true`), `SMTP_SSL_ENABLE` (`false`) | | AUTH when a username is set; STARTTLS when offered; implicit TLS. |
| `SMTP_FROM` | empty | Sender address. Required for `/ready`. |
| `AUTH_BOOTSTRAP_OWNER_EMAIL`, `_LOGIN`, `_DISPLAY_NAME`, `_PASSWORD` | required | First owner, created as an active platform admin. |
| `AUTH_BOOTSTRAP_VIEWER_EMAIL`, `_LOGIN`, `_DISPLAY_NAME`, `_PASSWORD` | optional | Journey member of the bootstrap organization. |
| `AUTH_BOOTSTRAP_ORGANIZATION_SLUG`, `_NAME` | required | Bootstrap organization. |
| `AUTH_ACCESS_CLIENT_ID`, `_SECRET`, `AUTH_ACCESS_REDIRECT_URIS` | required | Browser relying party (code + PKCE + consent, `openid profile email offline_access`). |
| `AUTH_DIRECTORY_CLIENT_ID`, `_SECRET` | required | `directory:read` machine client. |
| `AUTH_PROVISIONER_CLIENT_ID`, `_SECRET` | required | `admin:read admin:write directory:read` machine client used by the `gas` provider. |
| `AUTH_CLI_CLIENT_ID`, `AUTH_CLI_REDIRECT_URIS` | optional, `http://127.0.0.1/callback` | Public native client for CLIs (`none` authentication, PKCE required, `openid profile email offline_access`, refresh tokens). Registered only when the id is set. Loopback redirect URIs match on any port (RFC 8252). |
| `AUTH_IDENTITY_LINK_CLIENT_ID` | `gsio-auth-client` | Default client id at external identity providers. |
| `IDENTITY_IDENTITY_LINK__PROVIDERS` | `{}` | JSON map of allowlisted providers: `{"acme":{"issuer","authorizationEndpoint","tokenEndpoint","jwksUri","clientId","clientSecret","scopes","freshAuthenticationParameter"}}`. `google`, `github`, `gitlab`, and `okta` have built-in endpoints. |
| `GSIO_IDENTITY_NOTIFICATION_DELAY_MS` | `5000` | Security-notification worker delay. `GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED=false` turns it off. |

Generate a signing key with:

```bash
bun scripts/generate-jwk.ts            # RS256
bun scripts/generate-jwk.ts ML-DSA-65  # only after relying parties accept ML-DSA-65
```

## Startup

`apps/server` connects Postgres, applies the migrations, validates the signing keys, reconciles the
bootstrap owner, organization, and the three clients, starts the notification worker, then
listens. Any failure exits the process before it accepts traffic. Bootstrap is safe on every start:
it creates what is missing, re-hashes the client secrets, and never renames the organization.

## Endpoints

| Path | Purpose |
| --- | --- |
| `/health`, `/ready` | Liveness (`{"ok":true}`) and readiness (database, signing key, SMTP, bootstrap; 503 when any fails). |
| `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/oauth2/jwks` | Discovery and public keys. |
| `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, `/userinfo` | Authorization server. |
| `/api/admin/**` | Admin API; opaque bearer token with `admin:read` (reads) or `admin:write` (writes). |
| `/api/v1/organizations/{slug}/members` | Directory API; `directory:read`. |
| `/api/v1/account/identity-links` | Account API; the browser session or a user bearer token. |
| `/login`, `/passwordless`, `/account/**`, `/admin/**` | Browser pages. |

## Local stack

```bash
podman compose up -d   # Postgres on 5432, Mailpit SMTP on 1025 with its UI on 8025
SMTP_HOST=127.0.0.1 SMTP_PORT=1025 SMTP_AUTH=false SMTP_FROM=no-reply@identity.local \
SERVER_SERVLET_SESSION_COOKIE_SECURE=false \
AUTH_ACTIVE_PRIVATE_JWK="$(bun scripts/generate-jwk.ts)" \
AUTH_BOOTSTRAP_OWNER_EMAIL=owner@identity.local AUTH_BOOTSTRAP_OWNER_LOGIN=owner \
AUTH_BOOTSTRAP_OWNER_PASSWORD=change-me-please AUTH_BOOTSTRAP_ORGANIZATION_SLUG=local \
AUTH_BOOTSTRAP_ORGANIZATION_NAME=Local AUTH_ACCESS_CLIENT_ID=access AUTH_ACCESS_CLIENT_SECRET=access-secret \
AUTH_ACCESS_REDIRECT_URIS=http://localhost:3000/callback AUTH_DIRECTORY_CLIENT_ID=directory \
AUTH_DIRECTORY_CLIENT_SECRET=directory-secret AUTH_PROVISIONER_CLIENT_ID=provisioner \
AUTH_PROVISIONER_CLIENT_SECRET=provisioner-secret \
bun start
```

Then sign in at `http://localhost:4180/login` as `owner`, and read passwordless and security mail
in Mailpit at `http://localhost:8025`.

## wasmCloud guest

`apps/guest` is the same service as a wasmCloud component. It reads the settings above from two
places and never from its database:

- **wasi:config** (`IdentityConfig` in `apps/guest/src/bindings.ts`): the non-secret values
  compiled into the guest (signing algorithm, SMTP port and sender, bootstrap ids and names,
  client ids, notification flags).
- **The WASI environment**, which the platform fills from the workload's `identity-control`
  Kubernetes Secret: `ISSUER_URL`, `AUTH_PUBLIC_ORIGIN`, `AUTH_ACTIVE_PRIVATE_JWK`,
  `AUTH_PREVIOUS_PUBLIC_JWK_SET`, `SMTP_HOST`, `SMTP_USERNAME`, `SMTP_PASSWORD`,
  `AUTH_ACCESS_REDIRECT_URIS`, `AUTH_BOOTSTRAP_OWNER_PASSWORD`, `AUTH_BOOTSTRAP_VIEWER_PASSWORD`,
  `AUTH_ACCESS_CLIENT_SECRET`, `AUTH_DIRECTORY_CLIENT_SECRET`, `AUTH_PROVISIONER_CLIENT_SECRET`,
  `AUTH_CLI_CLIENT_ID`, `AUTH_CLI_REDIRECT_URIS` (`RUNTIME_SECRET_SETTINGS` in
  `apps/guest/src/settings.ts`). An environment value wins over wasi:config.

wasi:config cannot carry secrets or URLs (the platform rejects them), and tenant admission lets a
workload without an environment label reference only its `<workload>-control` Secret, which
cli-plugin-platform creates for the control token. The guest refuses to boot without
`ISSUER_URL`, `AUTH_PUBLIC_ORIGIN` and `AUTH_ACTIVE_PRIVATE_JWK`: every request answers 503 with
`runtime settings missing from the identity-control Secret: <names>`.

`di-framework platform deploy` (cli-plugin-platform 6.1.2) rewrites `identity-control` on each
deploy with only `DI_CONTROL_TOKEN` and `DI_CONTROL_IDENTITY`. As a tenant developer it cannot
replace a copy that holds more keys (the platform's `tenant-secret-update` policy refuses a replace
that drops a key), and as an administrator it silently drops them. A deploy is therefore three
steps, which `deploy/guest/deploy.sh <instance> <values-file>` runs:

1. delete `identity-control`;
2. `di-framework platform deploy identity --target identity`;
3. `bun deploy/guest/runtime-secrets.ts apply`, which writes the whole Secret (a fresh control
   token, the identity, and the values; the guest has no cron or queue invokers that use the
   token) through kubectl's raw create/replace, which tenant developers may use without reading
   Secrets, and rolls the workload by setting `IDENTITY_RUNTIME_REVISION` in its environment
   config.

`bun deploy/guest/runtime-secrets.ts generate --out <file> --origin <url> --smtp-host <host>`
creates a values file (mode 0600) for a new instance. The `deploy/platform` Pulumi program does
the same with values it keeps in stack state.

The database is embedded PostgreSQL 17, the `di-framework:pglite` provider composed into the
component at build time (`pglite` in `apps/guest/di-framework.config.json`, pinned by GHCR
digest). Its root is `DI_PGLITE_DATA_DIR` (default `/data/pglite`), inside the workload's
persistent `/data` directory. The tenant host must run the exclusive-instance wash build
(`ghcr.io/di-framework/wash:2.8.0-wasi-tls-exclusive`), which serves the workload from one
component instance so the database has one opener.

## Provisioning with Pulumi

`packages/provider` is the `gas` provider in TypeScript. See its README for resources and
configuration. It authenticates as the provisioner client and sends each mutation with an
`Idempotency-Key` equal to the resource URN.
