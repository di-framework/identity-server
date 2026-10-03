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

`TODO.md` and `apps/client/TODO.md` are gap notes. They are not this tracker. Several of their items describe work that would diverge from auth-server; those items are called out below.

## Summary

| Area | Status |
| --- | --- |
| JSON control-plane routes | Partial. The same operations exist and persist to Postgres. Callers are unauthenticated, and several lifecycle rules stop at the repository boundary. |
| HTML admin and account pages | Local. PatternFly screens cover the page inventory. Sessions, passwords, passwordless tokens, consent, and link start/callback live in memory. |
| OAuth 2 / OIDC authorization server | Missing. |
| Schema | The Flyway scripts `V1`–`V10` match auth-server's tables. Several of those tables have no TypeScript reader or writer. |
| Deployment companions | Missing. Bootstrap, encrypted Pulumi inputs, and the `gas` provider are not in this repository. |

## JSON control plane

Routes below are the auth-server admin and account API. Identity generates the same paths from `apps/api/src/contracts` and serves them from Postgres.

Authentication on every auth-server `/api/admin/**` call is an opaque access token with `admin:read` or `admin:write`. `GET /api/v1/organizations/{slug}/members` requires `directory:read`. Account link routes require the signed-in user. Identity accepts those calls with no session and no scope.

| Operation | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET/POST /api/admin/users`, `GET/PATCH/DELETE /api/admin/users/{userId}` | Scope-gated. Create yields `pending` and mails a passwordless message with purpose `invite`. Delete archives, and returns 409 when a non-archived user has any membership. The JSON API has no last-admin or last-owner block (`ApiController.kt:175-238`). User payload is id, login, email, display name, email verified, status. | Same payload, archive-on-delete, and membership 409. No caller check. Create does not send the invite mail. | Partial |
| System role on the user JSON payload | Omitted. `system_role` is stored and shown on the HTML user pages. | Omitted. The column exists in `V6` and is not mapped on `UserAccount`. | Match |
| `GET/POST /api/admin/organizations`, `GET/PATCH/DELETE /api/admin/organizations/{slug}` | Scope-gated. Delete is a hard delete and returns 409 when the organization has a membership or an active client. The JSON organization has no archive field. Blank names are rejected on update. | Same delete rule and payload. No caller check. | Partial |
| Organization archive | HTML only (`archived_at`). The JSON API does not archive. | HTML screens filter active and archived organizations. The API hard-deletes. | Split |
| Membership get, put, delete | Scope-gated. No last-owner block on the JSON API; the block is HTML-only (`ApiController.kt:326-383`). | Same routes and the same absence of a last-owner block. No caller check. | Partial |
| `GET /api/v1/organizations/{slug}/members` | `directory:read`, cursor, limit. | Same paging. No caller check. | Partial |
| OAuth client list, get, create, update, rotate, revoke | Caller supplies `clientId`. Stored client name is that id. Grant types come from the `browser` flag: authorization code plus refresh token, or client credentials; the flag also sets PKCE and consent. Secret is Argon2 (the password encoder). Idempotent create and rotate derive the secret as HMAC-SHA256 over `key\0operation` keyed by `SHA-256("gsio-oauth-idempotency-v1\0" + active private JWK)` (`ApiController.kt:533-544`). Revoke sets `revoked_at`. | Same route shape, `browser` grant split with PKCE and consent settings, Argon2 secret, and derivation key. No caller check. | Partial |
| `GET /api/admin/audit` | `admin:read`. Newest 500. No query filters. Metadata is returned as stored. | Newest 500. No caller check. No query filters. | Partial |
| `GET/DELETE /api/v1/account/identity-links`, `POST .../unlink/prepare` | Bound to the authenticated user and session. Prepare requires the session's last authentication within 15 minutes; a bearer-only caller has no session and always fails it. Delete relies on the session-bound confirmation. Unlink refuses the last usable sign-in method, revokes persisted access and refresh tokens, and enqueues a security notification (`IdentityLinkController.kt:114-180,485-492`). | List, prepare, and unlink persist. Prepare and unlink need a user id and session id that the control plane does not establish. Token revoke and the notification outbox are unused. The last-method check is present in `LinkService`. | Partial |
| `Idempotency-Key` | Mutations used by the Pulumi provider. Create paths replay from the earliest audit row with that action and correlation id (V5 index). Rotate replays by derivation only. | Same replay and derivation. No caller check. | Partial |
| Restore user, send password reset | HTML only. No JSON operation. | No JSON operation. The screens fall through to the in-memory directory. | Split |

`TODO.md` asks to return system role on the user API and to model organization status on the API. Doing either one moves the JSON API away from auth-server. The HTML admin is the surface that has those fields.

## Browser admin and account

Auth-server renders these with kotlinx.html. This repository renders PatternFly pages from `apps/client`. `bun run client` uses only the in-memory directory. `bun run start` serves the pages and the JSON API together. Sign-in still comes from the in-memory store, so a browser session and a Postgres user are the same person only when both records were created.

| Page or action | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET/POST /login` | Form login. The page shows no error and no signed-out message. `POST /admin/logout` clears the session and redirects to `/login?logout=1`. | In-memory password check. Logout redirect matches. | Local |
| Password storage | Argon2 (`Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8`). Minimum length 12 on `POST /account/password`. | In-memory hash. The length check exists in the client domain. | Local |
| `GET/POST /passwordless`, `GET/POST /passwordless/confirm` | Pending accounts are mailed purpose `activation`, active accounts purpose `sign_in`. Pending and active accounts can be mailed. Archived and unknown addresses get the same page and no mail. One challenge per email and purpose per minute. Link lifetime 15 minutes. `GET` stores a 43-character token in the `gsio_passwordless_challenge` cookie and does not sign in. `POST` consumes it, activates the user, marks the email verified, and redirects to `/account/password`. A malformed token renders "Link unavailable". A failed consume redirects to `/passwordless/confirm?error=invalid`, and that page still shows the confirm form. Mail failure consumes the challenge and audits `passwordless.delivery_failed`. | The page copy and rate limit exist in memory. No mail is sent. Failed consume does not follow the auth-server redirect. | Local |
| `GET /oauth2/consent` | Title "Review access". Copy is "This application is requesting access to your GSIO identity." `openid` is a hidden field. Other scopes are checked boxes. Allow posts to `/oauth2/authorize`. The client is not named. | In-memory consent page. Allow does not reach an authorization server. | Local |
| Users, invite, archive, restore, password reset | Postgres. Platform admin sees every user. An owner sees self and users who share an owned organization. Archive blocks the last active platform admin and the sole owner of an active organization. Invite and password reset call `requestSignIn`, so the mail purpose is `activation` for a pending user and `sign_in` for an active one (`AdminUserController.kt:115-187,301-329`). | Screen rules exist in memory. Invite, archive, and some edits call the JSON API when `bun run start` is used. Restore and password reset stay in memory. The API user list is unscoped, so an owner's screen shows every API row. | Local |
| Organizations | HTML archive sets `archived_at`. Create, settings, and archive follow `AdminPolicy`. Member count is every membership. Client count is clients with `revoked_at` null. Slug matches lowercase letters, digits, and hyphens. A blank name falls back to the slug. | Screens implement the filters. The API deletes instead of archiving, so the archived filter cannot be filled from Postgres. | Local |
| Memberships | Add, role change, and remove. Demote and remove block the last owner. | Screen rules exist in memory. API writes do not enforce the last owner. | Local |
| OAuth clients | HTML registration assigns `cli_` plus 16 hex characters from a UUID, shows the secret once, and stores the typed name and grant types. | The register form sends the typed name as `clientId`. Grant types are not on the API. The API requires the caller to supply `clientId`. | Local |
| Audit HTML | Filters by action, actor, target, and from/to. Owners see a row only when the target or the before/after metadata contains an owned organization slug. Detail outside that scope is denied. Sensitive metadata is redacted. Newest 500. | In-memory list and detail. API list has no filters and no owner scope. | Local |
| Linked identities | Start redirects to an allowlisted OIDC provider (PKCE, nonce, `prompt=login`). Callback stages a pending link. Confirm writes `(issuer, subject)`. Unlink requires authentication within 15 minutes, a 5-minute session-bound confirmation, and a remaining sign-in method (password, verified email, or another link). Success revokes that account's access and refresh tokens. The current browser session stays. | List and unlink can call the API for a user that already exists in Postgres. Start, callback, and confirm stay in memory. Unlink does not revoke tokens. | Local |
| Access rules | Active platform admin: every admin action. Owner: owned organizations only. Create organization, archive organization, and platform-admin management are platform-admin only. An inactive user is denied. A non-owner member has no admin pages. | Implemented against the in-memory store. API reads ignore the actor. | Local |

`apps/client/TODO.md` says the consent page names the client, and that organization rows show an active member count. Auth-server does neither. It also says every bad or expired email token shows "Link unavailable". That page is used for a malformed `GET` token. A failed consume uses the confirm form.

## Authorization server

`@di-framework/auth` in `examples/app` is a local password and session integration. It is not a client of this identity server, and it is not an authorization server. `@di-framework/authz` documents OAuth 2 / OIDC authorization-server support as future work.

| Capability | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET/POST /oauth2/authorize` | Spring Authorization Server, consent page `/oauth2/consent` | Absent | Missing |
| `POST /oauth2/token`, `/oauth2/jwks`, `/.well-known/**` | Public. Issuer from `gsio.issuer` | `apps/api/src/authorization/endpoints.ts` serves token (`client_credentials`), introspection, revocation, JWKS, and both discovery documents from the configured issuer. `client_secret_basic` and `client_secret_post`. Authorization-code and refresh grants return `unsupported_grant_type` | Partial |
| UserInfo | `sub`, `preferred_username`, `name`, `email`, `email_verified`, `picture`, organization roles | Absent | Missing |
| Access tokens | Opaque references. Access TTL 10 minutes. Authorization code TTL 60 seconds. Refresh TTL 30 days. Refresh reuse disabled. | Opaque 43-character references with a 10-minute TTL for `client_credentials`, stored as SHA-256 hashes in `oauth2_authorization`. Introspection rejects unknown, invalidated, expired, orphaned, and lifecycle-revoked tokens in the auth server's order. No code or refresh tokens yet | Partial |
| ID tokens | Signed with the active `kid` using `RS256` or, when `AUTH_SIGNING_ALGORITHM=ML-DSA-65`, an RFC 9964 AKP key. Claims include login, display name, email, email verified, picture, and organization roles | Absent | Missing |
| Consent storage | `oauth2_authorization_consent` | Table migrated and unused | Missing |
| Refresh replay | `RefreshRotationAuthorizationService` inserts a hash under a row lock | Table migrated and unused | Missing |
| Signing keys | `RS256` RSA, or feature-gated `ML-DSA-65` AKP. Previous public JWKs stay on JWKS. Missing or private-in-public keys fail startup | `SigningKeys` in `packages/core/src/shared/infrastructure/crypto` loads and validates the same inputs and signs with either algorithm. Nothing serves JWKS or issues tokens yet | Partial |
| Registered clients used as an authorization server | `JdbcRegisteredClientRepository` on `oauth2_registered_client` | `PostgresRegisteredClientRepository` reads the same rows, including auth methods, grant types, and client settings, and the token endpoint authenticates against them with Argon2. Rows are this repository's JSON settings, not Spring's serialized form | Match |

## Schema

`packages/migrations/migrations/V1`–`V10` are the auth-server tables, including the Spring Authorization Server JDBC names.

| Table | Written by this repository's services |
| --- | --- |
| `users`, `organizations`, `organization_memberships` | Yes. `users.system_role` and `organizations.archived_at` are not mapped. |
| `auth_audit_records` | Yes. |
| `oauth2_registered_client`, `oauth_client_lifecycle` | Yes. Admin registration writes both rows in one transaction, with client and token settings. |
| `identity_links`, `identity_unlink_confirmations` | Yes, for list, prepare, and unlink. |
| `email_challenges` | No. |
| `identity_link_flows` | No. Pending links are in memory on the auth-server HTML path as well (`stagePendingLink`). The flow-state table is the persisted start/callback record. |
| `oauth2_authorization`, `oauth2_authorization_consent`, `oauth_refresh_token_history` | Yes, through `PostgresAuthorizationRepository`. Only `client_credentials` writes `oauth2_authorization` so far. Token columns hold SHA-256 hashes; `attributes` and `*_metadata` hold this repository's JSON. |
| `identity_security_notifications` | No. |

## Operations outside the request path

| Capability | Auth-server | This repository | Status |
| --- | --- | --- | --- |
| `GET /health` | `{ "ok": true }` | Example app only. The identity server does not expose it. | Missing |
| `GET /ready` | 200 when every check passes, otherwise 503. Body keys in order: `database` (connection valid within 2 s), `signing_key` (always true; the key is validated at startup), `smtp` (host and from address configured), `bootstrap` (reconciler finished), `ok` (`WebController.kt:51-64`). | Absent | Missing |
| Bootstrap | First owner (active platform admin), optional viewer, organization, and the `access` browser client, `directory` client, and provisioner client from encrypted configuration. Provisioner scopes are `admin:read`, `admin:write`, and `directory:read`. Secrets are re-hashed on every start. No audit rows (`BootstrapReconciler.kt:57-209`). | Absent | Missing |
| SMTP | Passwordless mail and the security-notification worker | Absent | Missing |
| Security notifications | Link and unlink enqueue one outbox row per event, keyed `sha256(action\|userId\|issuer\|subject)`. Delivery goes to a verified contact on an active account. Failures retry with backoff `min(30s·2^min(attempts−1,7), 1h)` and no attempt limit. The message omits tokens and claims. | Table unused | Missing |
| External identity providers | Allowlist of issuer, endpoints, client id, and optional secret. Callback failures use a generic message. Audit correlation values are hashes. | No provider client | Missing |
| Pulumi `gas` provider | Organizations, users, memberships, OAuth clients, and audit reads through the admin API, with `Idempotency-Key` set to the resource URN. Each request runs discovery and a client-credentials token request; idempotent requests retry three times on 408/429/5xx; delete treats 404 and 410 as success; preview makes no calls (`pulumi-provider-gas/main.go`, `provider_support.go`) | Absent | Missing |
| Listen address, port, public origin | `PORT`, `ISSUER_URL`, and `AUTH_PUBLIC_ORIGIN` (falls back to the issuer), injected by Fly and Pulumi. No listen-address setting (`application.yml:2,34,42`) | `loadIdentitySettings` reads the same names; `apps/server` listens on `PORT`. `IDENTITY_SERVER__HOST` sets the listen address, which auth-server does not have | Match |
| Native image | Jib image of the Spring process | `apps/server/build.ts` can compile a Bun binary. That binary still lacks the authorization server. | Partial |

## Identity notes that are not parity items

These `TODO.md` lines are about this repository's own wiring. Completing them does not, by itself, match auth-server:

| Note | Why it is not a parity row |
| --- | --- |
| Return system role on the user API | Auth-server's JSON user payload omits it. |
| Model organization status on the API | Auth-server archives only through the HTML admin. The JSON API hard-deletes an empty organization. |
| Register `/login`, `/passwordless`, `/oauth2/consent`, `/health`, and `/ready` because the OpenAPI document lists them | `apps/api/api/v1/openapi.yaml` does not list them. `apps/client/src/api/schema.d.ts` still does, from an older generation. |
| Persist consent by registering an authorization with the control-plane API | Auth-server writes consent from `POST /oauth2/authorize` into `oauth2_authorization_consent`. |
| Point `examples/app` at this identity server | Required for a demonstration. The example is not part of auth-server. |
| Blank-field 400s and unique-violation 409s on JSON create | Deliberate. Auth-server surfaces a 500 from Jackson or the database for these inputs; this repository rejects them cleanly. |
| HTML client registration secret delivery | Deliberate. Auth-server puts the new plain secret in the redirect URL; this repository reveals it once in the page model. |

## Updating this document

Change a row in the same change that changes the behavior. Keep the status date at the top equal to that change. Leave auth-server paths cited against `src/main/kotlin/org/gsio/auth` so a later reader can re-check a row without trusting the status word.
