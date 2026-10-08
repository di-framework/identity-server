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

## Provisioning with Pulumi

`packages/provider` is the `gas` provider in TypeScript. See its README for resources and
configuration. It authenticates as the provisioner client and sends each mutation with an
`Idempotency-Key` equal to the resource URN.
