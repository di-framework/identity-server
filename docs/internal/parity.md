# Parity: `@di-framework/identity` and GSIO Auth Server

Status date: 2026-10-02.

This document records behavioral parity between this repository and the GSIO Auth Server at `/Volumes/safe-vol/workspace/orgs/global-scale-insights-org/auth-server`. It is a tracker. A row changes only when the implementation changes.

Auth-server already has two surfaces that disagree with each other. The JSON control plane and the server-rendered HTML admin are both in scope here, and a match on one is not a match on the other.

## Status words

| Status | Meaning |
| --- | --- |
| Match | The compared surface behaves the same. |
| Partial | The operation, page, or table exists on both sides, and a named behavior differs. |
| Missing | Auth-server has it. This repository does not. |
| Local | This repository has a stand-in that does not survive process restart and does not use Postgres. |
| Split | Auth-server's JSON API and HTML admin already differ. The identity row is scored against each surface separately. |

## Sources

| System | What was compared |
| --- | --- |
| Auth-server | Kotlin controllers under `src/main/kotlin/org/gsio/auth` (JSON `ApiController.kt`, HTML `Admin*Controller.kt`, `WebController.kt`, `IdentityLink*.kt`), `src/main/resources/application.yml`, Flyway SQL, `api/v1/openapi.yaml`, and the `pulumi-provider-gas` Go provider |
| This repository | `packages/core`, `packages/migrations`, `apps/api` manifests and generated OpenAPI, `apps/client`, `apps/server`, `examples/app` |

`TODO.md` and `apps/client/TODO.md` were gap notes; they now live untracked as `.archive/TODO-1.md` and `.archive/TODO-client.md`. They are not this tracker. Several of their items describe work that would diverge from auth-server; those items are called out below and were left out of the parity work.

## Summary

| Area | Status |
| --- | --- |
| JSON control-plane routes | Match. Admin, directory, and account link operations persist to Postgres behind the auth server's authentication. |
| HTML admin and account pages | Match. Every page runs on Postgres. |
| OAuth 2 / OIDC authorization server | Match. Authorization code with PKCE and consent, refresh rotation with replay detection, client credentials, introspection, revocation, UserInfo, JWKS, and discovery. |
| Schema | Match. `V1`–`V10` are auth-server's tables and every one has a reader and writer. `V11` adds `browser_sessions`, which auth-server keeps in the servlet session. |
| Deployment companions | Match. Bootstrap, `/health`, `/ready`, and the `gas` provider (TypeScript, `packages/provider`). |

## JSON control plane

Routes below are the auth-server admin and account API. Identity generates the same paths from `apps/api/src/contracts` and serves them from Postgres.

Authentication on every auth-server `/api/admin/**` call is an opaque access token with `admin:read` (reads) or `admin:write` (mutations). `GET /api/v1/organizations/{slug}/members` requires `directory:read`. Account link routes require the signed-in user. Identity enforces the same token scopes in `apps/api/src/guards/bearer-guard.ts` before routing: 401 with `WWW-Authenticate` for a missing or invalid token, 403 for a missing scope, both with empty bodies. The audit actor is the token's principal name; the `x-actor-id` header is ignored. Account link routes still take `x-user-id` and `x-session-id` headers until the browser session lands.

| Operation | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET/POST /api/admin/users`, `GET/PATCH/DELETE /api/admin/users/{userId}` | Scope-gated. Create yields `pending` and mails a passwordless message with purpose `invite`. Delete archives, and returns 409 when a non-archived user has any membership. The JSON API has no last-admin or last-owner block (`ApiController.kt:175-238`). User payload is id, login, email, display name, email verified, status. | Same payload, archive-on-delete, membership 409, scopes, and the `invite` mail on create (not on an idempotent replay). | Match |
| System role on the user JSON payload | Omitted. `system_role` is stored and shown on the HTML user pages. | Omitted. The column exists in `V6` and is not mapped on `UserAccount`. | Match |
| `GET/POST /api/admin/organizations`, `GET/PATCH/DELETE /api/admin/organizations/{slug}` | Scope-gated. Delete is a hard delete and returns 409 when the organization has a membership or an active client. The JSON organization has no archive field. Blank names are rejected on update. | Same delete rule, payload, and scopes. | Match |
| Organization archive | HTML only (`archived_at`). The JSON API does not archive. | The HTML admin archives by `archived_at`; the JSON API hard-deletes. Both surfaces match. | Match |
| Membership get, put, delete | Scope-gated. No last-owner block on the JSON API; the block is HTML-only (`ApiController.kt:326-383`). | Same routes, scopes, and the same absence of a last-owner block. | Match |
| `GET /api/v1/organizations/{slug}/members` | `directory:read`, cursor, limit. | Same paging, scope, and configured issuer on each item. | Match |
| OAuth client list, get, create, update, rotate, revoke | Caller supplies `clientId`. Stored client name is that id. Grant types come from the `browser` flag: authorization code plus refresh token, or client credentials; the flag also sets PKCE and consent. Secret is Argon2 (the password encoder). Idempotent create and rotate derive the secret as HMAC-SHA256 over `key\0operation` keyed by `SHA-256("gsio-oauth-idempotency-v1\0" + active private JWK)` (`ApiController.kt:533-544`). Revoke sets `revoked_at`. | Same route shape, `browser` grant split with PKCE and consent settings, Argon2 secret, derivation key, and scopes. | Match |
| `GET /api/admin/audit` | `admin:read`. Newest 500. No query filters. Metadata is returned as stored. | Newest 500, `admin:read`, no query filters. | Match |
| `GET/DELETE /api/v1/account/identity-links`, `POST .../unlink/prepare` | Bound to the authenticated user and session. Prepare requires the session's last authentication within 15 minutes; a bearer-only caller has no session and always fails it. Delete relies on the session-bound confirmation. Unlink refuses the last usable sign-in method, revokes persisted access and refresh tokens, and enqueues a security notification (`IdentityLinkController.kt:114-180,485-492`). | Bound to the browser session cookie or a user bearer token (`AccountGuard`). Prepare requires a sign-in within 15 minutes and a session; confirmations are 5-minute, single-use, and session-bound; unlink refuses the final method (password, verified email on an active account, or another link), deletes the account's `oauth2_authorization` rows, and queues a notification. Client errors are 4xx where auth-server surfaces 500 from unhandled exceptions. | Match |
| `Idempotency-Key` | Mutations used by the Pulumi provider. Create paths replay from the earliest audit row with that action and correlation id (V5 index). Rotate replays by derivation only. | Same replay, derivation, and scopes. | Match |
| Restore user, send password reset | HTML only. No JSON operation. | HTML admin actions on Postgres; no JSON operation. Both surfaces match. | Match |

`TODO.md` asks to return system role on the user API and to model organization status on the API. Doing either one moves the JSON API away from auth-server. The HTML admin is the surface that has those fields.

## Browser admin and account

Auth-server renders these with kotlinx.html. This repository renders PatternFly pages from `apps/client`; `apps/client/src/server/web-app.ts` serves every page from the core services on Postgres, with sessions in `browser_sessions` (`V11`). Form field names, redirect targets, banners, and error text follow the auth-server pages. A form post that fails renders its page with the auth server's status code (the page model is embedded in the HTML shell). The in-memory store and `bun run client` are gone.

| Page or action | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET/POST /login` | Form login. The page shows no error and no signed-out message. `POST /admin/logout` clears the session and redirects to `/login?logout=1`. | `AccountService` checks the Argon2 hash of an active user by normalized login or email; success rotates the session and returns to the saved page; failure redirects to `/login?error` and the page shows no message. `POST /admin/logout` deletes the session and redirects to `/login?logout=1`. CSRF is required as in auth-server. | Match |
| Password storage | Argon2 (`Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8`). Minimum length 12 on `POST /account/password`. | Argon2id with the same parameters; `POST /account/password` rejects fewer than 12 characters with 400 and saves only for an active user. | Match |
| `GET/POST /passwordless`, `GET/POST /passwordless/confirm` | Pending accounts are mailed purpose `activation`, active accounts purpose `sign_in`. Pending and active accounts can be mailed. Archived and unknown addresses get the same page and no mail. One challenge per email and purpose per minute. Link lifetime 15 minutes. `GET` stores a 43-character token in the `gsio_passwordless_challenge` cookie and does not sign in. `POST` consumes it, activates the user, marks the email verified, and redirects to `/account/password`. A malformed token renders "Link unavailable". A failed consume redirects to `/passwordless/confirm?error=invalid`, and that page still shows the confirm form. Mail failure consumes the challenge and audits `passwordless.delivery_failed`. | `PasswordlessService` and the pages implement each step, cookie attributes, and redirect listed here, with mail through `SmtpMailSender`. | Match |
| `GET /oauth2/consent` | Title "Review access". Copy is "This application is requesting access to your GSIO identity." `openid` is a hidden field. Other scopes are checked boxes. Allow posts to `/oauth2/authorize`. The client is not named. | The page is built from `client_id`, `scope`, and the consent `state` with the same title, copy, hidden `openid`, checked scopes, and no client name or deny button. Allow posts to `/oauth2/authorize`. | Match |
| Users, invite, archive, restore, password reset | Postgres. Platform admin sees every user. An owner sees self and users who share an owned organization. Archive blocks the last active platform admin and the sole owner of an active organization. Invite and password reset call `requestSignIn`, so the mail purpose is `activation` for a pending user and `sign_in` for an active one (`AdminUserController.kt:115-187,301-329`). | `UserAdminService` behind the pages, with owner scoping, the archive blocks, restore, and password reset. | Match |
| Organizations | HTML archive sets `archived_at`. Create, settings, and archive follow `AdminPolicy`. Member count is every membership. Client count is clients with `revoked_at` null. Slug matches lowercase letters, digits, and hyphens. A blank name falls back to the slug. | `OrganizationAdminService` behind the pages; archive sets `archived_at` and the status filter reads it. | Match |
| Memberships | Add, role change, and remove. Demote and remove block the last owner. | `MembershipAdminService` behind the pages, with the last-owner blocks. | Match |
| OAuth clients | HTML registration assigns `cli_` plus 16 hex characters from a UUID, shows the secret once, and stores the typed name and grant types. | `ClientAdminService` behind the pages assigns `cli_` plus 16 hex characters and stores the typed name and grant types. The secret is shown once from the session rather than from the redirect URL. | Match |
| Audit HTML | Filters by action, actor, target, and from/to. Owners see a row only when the target or the before/after metadata contains an owned organization slug. Detail outside that scope is denied. Sensitive metadata is redacted. Newest 500. | `AuditAdminService` behind the pages, with the filters, owner scoping, detail denial, and redaction. | Match |
| Linked identities | Start redirects to an allowlisted OIDC provider (PKCE, nonce, `prompt=login`). Callback stages a pending link. Confirm writes `(issuer, subject)`. Unlink requires authentication within 15 minutes, a 5-minute session-bound confirmation, and a remaining sign-in method (password, verified email, or another link). Success revokes that account's access and refresh tokens. The current browser session stays. | `LinkFlowService` and `LinkService` behind the account pages, with the auth-server copy and redirects. | Match |
| Access rules | Active platform admin: every admin action. Owner: owned organizations only. Create organization, archive organization, and platform-admin management are platform-admin only. An inactive user is denied. A non-owner member has no admin pages. | `AdminAccessPolicy` (a `@di-framework/authz` policy) and `AdminPolicy` in `packages/core/src/admin`; denials render a 403 page. | Match |

`apps/client/TODO.md` says the consent page names the client, and that organization rows show an active member count. Auth-server does neither. It also says every bad or expired email token shows "Link unavailable". That page is used for a malformed `GET` token. A failed consume uses the confirm form.

## Authorization server

`@di-framework/auth` in `examples/app` is a local password and session integration. It is not a client of this identity server, and it is not an authorization server. `@di-framework/authz` documents OAuth 2 / OIDC authorization-server support as future work.

| Capability | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET/POST /oauth2/authorize` | Spring Authorization Server, consent page `/oauth2/consent` | `AuthorizeService` behind the browser routes: code flow only, exact redirect URI match, scope subset, PKCE S256 when the client requires it, login redirect that returns to the request, consent stored per client and user, 60-second codes. Invalid client or redirect URI renders an error; other errors redirect to the client with `error` and `state`. Device authorization endpoints are not served | Match |
| `POST /oauth2/token`, `/oauth2/jwks`, `/.well-known/**` | Public. Issuer from `gsio.issuer` | `apps/api/src/authorization/endpoints.ts` serves token (`client_credentials`, `authorization_code` with PKCE, `refresh_token`), introspection, revocation, JWKS, and both discovery documents from the configured issuer, with `client_secret_basic` and `client_secret_post` | Match |
| UserInfo | `sub`, `preferred_username`, `name`, `email`, `email_verified`, `picture`, organization roles | `GET`/`POST /userinfo` with an `openid` access token returns the same claims; an inactive user gets 401 | Match |
| Access tokens | Opaque references. Access TTL 10 minutes. Authorization code TTL 60 seconds. Refresh TTL 30 days. Refresh reuse disabled. | Opaque references with the same TTLs for every grant, stored as SHA-256 hashes in `oauth2_authorization`; refresh tokens rotate on every use. Introspection rejects unknown, invalidated, expired, orphaned, and lifecycle-revoked tokens in the auth server's order | Match |
| ID tokens | Signed with the active `kid` using `RS256` or, when `AUTH_SIGNING_ALGORITHM=ML-DSA-65`, an RFC 9964 AKP key. Claims include login, display name, email, email verified, picture, and organization roles | Issued on code exchange and refresh when `openid` was granted, signed by `SigningKeys` with the active `kid`, 30-minute lifetime, `nonce` and `auth_time`, and the same profile claims for active users | Match |
| Consent storage | `oauth2_authorization_consent` | Written by the consent submission as `SCOPE_` authorities and read on later requests | Match |
| Refresh replay | `RefreshRotationAuthorizationService` inserts a hash under a row lock | Each rotation records the old hash; presenting it again locks the history row, marks it reused, deletes the authorization, audits `oauth.refresh_reuse_detected`, and answers `invalid_grant`. A replayed authorization code also deletes what it issued | Match |
| Signing keys | `RS256` RSA, or feature-gated `ML-DSA-65` AKP. Previous public JWKs stay on JWKS. Missing or private-in-public keys fail startup | `SigningKeys` loads and validates the same inputs, fails startup the same way, signs ID tokens with either algorithm, and publishes the active and previous public keys on JWKS | Match |
| Registered clients used as an authorization server | `JdbcRegisteredClientRepository` on `oauth2_registered_client` | `PostgresRegisteredClientRepository` reads the same rows, including auth methods, grant types, and client settings, and the token endpoint authenticates against them with Argon2. Rows are this repository's JSON settings, not Spring's serialized form | Match |

## Schema

`packages/migrations/migrations/V1`–`V10` are the auth-server tables, including the Spring Authorization Server JDBC names.

| Table | Written by this repository's services |
| --- | --- |
| `users`, `organizations`, `organization_memberships` | Yes. `users.system_role` and `organizations.archived_at` are mapped and read by the HTML admin services; the JSON payloads still omit them. |
| `auth_audit_records` | Yes. Metadata is stored as a JSON object (an earlier version stored a JSON string scalar). |
| `oauth2_registered_client`, `oauth_client_lifecycle` | Yes. Admin registration writes both rows in one transaction, with client and token settings. |
| `identity_links`, `identity_unlink_confirmations` | Yes: list, link insert under a row lock, prepare, and unlink. |
| `email_challenges` | Yes, through `PasswordlessService`: issue (rate-limited per email and purpose), consume under a row lock, and delivery-failure consumption. |
| `identity_link_flows` | Yes, through `LinkFlowService` (start writes it, callback deletes it first). Pending links stay in process memory, as auth-server's `stagePendingLink` does. |
| `oauth2_authorization`, `oauth2_authorization_consent`, `oauth_refresh_token_history` | Yes, through `PostgresAuthorizationRepository`. Only `client_credentials` writes `oauth2_authorization` so far. Token columns hold SHA-256 hashes; `attributes` and `*_metadata` hold this repository's JSON. |
| `identity_security_notifications` | Yes, through `SecurityNotificationService`. |
| `browser_sessions` (`V11`, this repository only) | Yes, through `SessionService`. Auth-server keeps the same state in the servlet session; the table holds the SHA-256 of the cookie value, the user, the CSRF token, the last authentication time, and session attributes. |

## Operations outside the request path

| Capability | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET /health` | `{ "ok": true }` | `apps/api/src/operations/health.ts` returns the same body. | Match |
| `GET /ready` | 200 when every check passes, otherwise 503. Body keys in order: `database` (connection valid within 2 s), `signing_key` (always true; the key is validated at startup), `smtp` (host and from address configured), `bootstrap` (reconciler finished), `ok` (`WebController.kt:51-64`). | `Readiness` runs the same four checks in the same key order with a 2-second database probe, and `/ready` answers 200 or 503. | Match |
| Bootstrap | First owner (active platform admin), optional viewer, organization, and the `access` browser client, `directory` client, and provisioner client from encrypted configuration. Provisioner scopes are `admin:read`, `admin:write`, and `directory:read`. Secrets are re-hashed on every start. No audit rows (`BootstrapReconciler.kt:57-209`). | `BootstrapReconciler` runs at startup with the same required settings, messages, create rules, repair rules, and client registrations, in one transaction. `apps/server` exits on failure. | Match |
| SMTP | Passwordless mail and the security-notification worker | `SmtpMailSender` (EHLO, STARTTLS when offered, implicit TLS, AUTH PLAIN or LOGIN, certificate verification on) sends passwordless, invite, and security-notification mail with the auth server's subjects and bodies | Match |
| Security notifications | Link and unlink enqueue one outbox row per event, keyed `sha256(action\|userId\|issuer\|subject)`. Delivery goes to a verified contact on an active account. Failures retry with backoff `min(30s·2^min(attempts−1,7), 1h)` and no attempt limit. The message omits tokens and claims. | `SecurityNotificationService` and `NotificationWorker` (started by `apps/server` on `GSIO_IDENTITY_NOTIFICATION_DELAY_MS`) with the same key, recipient rule, mail text, backoff, and audits. The unlink correlation id is the stored session hash rather than the raw session id auth-server records | Match |
| External identity providers | Allowlist of issuer, endpoints, client id, and optional secret. Callback failures use a generic message. Audit correlation values are hashes. | `IdentityProviders` (configured entries plus the google, github, gitlab, and okta defaults, HTTPS or loopback endpoints) and `HttpIdentityProviderClient` (PKCE exchange, RS256 ID token checked for issuer, audience, expiry, nonce, and fresh `auth_time`). The callback URI is built from `AUTH_PUBLIC_ORIGIN` instead of the request's host and port | Match |
| Pulumi `gas` provider | Organizations, users, memberships, OAuth clients, and audit reads through the admin API, with `Idempotency-Key` set to the resource URN. Each request runs discovery and a client-credentials token request; idempotent requests retry three times on 408/429/5xx; delete treats 404 and 410 as success; preview makes no calls (`pulumi-provider-gas/main.go`, `provider_support.go`) | `packages/provider` is a TypeScript dynamic Pulumi provider with the same resources (Bootstrap, Organization, User, Membership, OAuthClient), audit function, discovery and token per request, retries, error messages, replace/update rules, and URN `Idempotency-Key` (computed with `pulumi.createUrn`, because dynamic providers are not handed the URN). Resource logic is tested against the in-process server; the Pulumi wrapper itself needs the engine | Match |
| Listen address, port, public origin | `PORT`, `ISSUER_URL`, and `AUTH_PUBLIC_ORIGIN` (falls back to the issuer), injected by Fly and Pulumi. No listen-address setting (`application.yml:2,34,42`) | `loadIdentitySettings` reads the same names; `apps/server` listens on `PORT`. `IDENTITY_SERVER__HOST` sets the listen address, which auth-server does not have | Match |
| Native image | Jib image of the Spring process | `apps/server/build.ts` compiles one Bun binary with the pages, the authorization server, the API, the client assets, and the migrations (`V1`–`V11`); `apps/server/Dockerfile` runs it. Verified by booting the binary against a fresh database with bootstrap settings | Match |

## Identity notes that are not parity items

These `TODO.md` lines are about this repository's own wiring. Completing them does not, by itself, match auth-server:

| Note | Why it is not a parity row |
| --- | --- |
| Return system role on the user API | Auth-server's JSON user payload omits it. |
| Model organization status on the API | Auth-server archives only through the HTML admin. The JSON API hard-deletes an empty organization. |
| Register `/login`, `/passwordless`, `/oauth2/consent`, `/health`, and `/ready` because the OpenAPI document lists them | `apps/api/api/v1/openapi.yaml` does not list them, and `apps/client/src/api/schema.d.ts` is now regenerated from it. Auth-server's springdoc output lists them because it documents every controller. |
| Persist consent by registering an authorization with the control-plane API | Auth-server writes consent from `POST /oauth2/authorize` into `oauth2_authorization_consent`. |
| Point `examples/app` at this identity server | Required for a demonstration. The example is not part of auth-server. |
| Blank-field 400s and unique-violation 409s on JSON create | Deliberate. Auth-server surfaces a 500 from Jackson or the database for these inputs; this repository rejects them cleanly. |
| Generated JSON routes reject a body-less POST without `Content-Type` (415) | `@di-framework/codegen` 6.0.3 route parsing. Spring accepts such a POST; `unlink/prepare` callers should send `Content-Type: application/json`. |
| Browser forms and session cookie | The session cookie is `identity_session`, not `JSESSIONID`. The admin and account pages are a PatternFly application that loads JSON page models; the routes, form fields, statuses, and redirects match the kotlinx.html pages. |
| HTML client registration secret delivery | Deliberate. Auth-server puts the new plain secret in the redirect URL; this repository reveals it once in the page model. |

## Updating this document

Change a row in the same change that changes the behavior. Keep the status date at the top equal to that change. Leave auth-server paths cited against `src/main/kotlin/org/gsio/auth` so a later reader can re-check a row without trusting the status word.
