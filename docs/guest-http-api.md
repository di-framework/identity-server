# Guest HTTP API on tenant identity

This is the record of moving the Bun identity HTTP surface onto the existing `identity` wasmCloud workload, and of the fixes required before that workload could serve tokens, sessions, mail, and organization writes.

> **Status (identity-server#50).** The guest in this repository now runs on the pglite provider
> component and reads its runtime secrets from the `identity-control` Secret; see
> [11. pglite](#11-pglite-identity-server50). Sections 1 to 10 record the Postgres-era guest that
> still serves the `authproto` instance (tenant `identity`, `directory` BackingService) until the
> [authproto cutover](#authproto-cutover), which has not happened (its tooling is built and proven
> offline; the runbook is in that section). Its database adapter, the
> `identity_runtime_secret` rows and the `psql` seeding described there no longer apply to new
> deploys.

The cluster was not reinstalled. The workload stayed on tenant `identity` (`di-tenant-identity` / `di-runtime-identity`) and kept the existing `directory` Postgres `BackingService`. `bun start` is still the local server. The guest is the cluster process.

## Target

Gateway on the target HTTP NodePort with `Host: identity.identity.localhost`:

- `GET /ready` returns 200 with `database`, `signing_key`, `smtp`, `bootstrap`, and `ok` all true
- `GET /oauth2/jwks` returns the active `kid`
- A client-credentials grant returns an access token, and an OpenID authorization-code grant returns an ID token that verifies against that JWKS
- `POST /login` sets `identity_session`, and a following account page sees that session
- One passwordless message is accepted by the SMTP sink (Mailpit)
- `POST /api/admin/organizations` returns 201, and a duplicate slug returns 409, through the control plane

## Layout

```text
client
  -> gateway :30180
    -> identity.wasm
         -> BackingService directory (Postgres)
         -> wasi:config (non-secrets)
         -> SMTP via egress to the `SMTP_HOST` row
```

`apps/guest` is the component. `apps/guest/src/app.ts` resolves the Postgres and config bindings, loads embedded assets, and forwards every request to `handle()` in `apps/guest/src/runtime.ts`. That function applies schema, loads settings, prepares signing keys and bootstrap, then calls the same `routeRequest` path as `apps/server/src/serve.ts`.

Deployment topology is `di-framework.deploy.toml`. Target `identity` uses tenant `identity`. The `deploy/platform` Pulumi program supplies its kubeconfig, context, and registry when it deploys; see `deploy/platform/README.md`.

## 1. Database adapter

`wasmcloud:postgres@0.2.0` exposes `query` and `queryBatch`, not a pooled connection. `packages/core` still expects `SqlDatabase.transaction` to hold one connection across `BEGIN` / work / `COMMIT`, including `SELECT … FOR UPDATE`.

`openPostgresDatabase` from `@di-framework/bindings/postgres` wraps `IdentityDatabase` as a `SqlDatabase` that runs in autocommit: it never sends `BEGIN` or `COMMIT`, and `transaction(fn)` runs `fn` on the same handle. See [Transaction semantics on wasmCloud](#transaction-semantics-on-wasmcloud) for why, and for how the repositories keep their invariants without one.

That module encodes parameters as the provider’s `pg-value` variants (uuid, bool, int, timestamptz, bytea, jsonb) and decodes result cells back to JSON values. SQL `?` placeholders become `$n`. UUID strings and safe integers are inlined so Postgres types them from context.

Row counts that the Bun driver reports as `changes` are not available from this provider. Deletes and conflict inserts that need a count now use `RETURNING 1`:

- `postgres-session-repository.ts` (`deleteExpired`)
- `postgres-authorization-repository.ts` (`deleteByPrincipal`)
- `postgres-directory-repository.ts` (membership delete)
- `postgres-notification-repository.ts` (notification insert)

`packages/core/src/shared/infrastructure/postgres.ts` loads `bun` through a variable `import()`. The guest bundle never opens that pool. The bundler warning about an unresolved specifier `pecifie` is that variable seen mid-token; the Wasm component does not call it.

### Transaction semantics on wasmCloud

`wasmcloud:postgres@0.2.0` has no connection or transaction handle. Each `query` and `query-batch` call is routed by the host's Postgres plugin to whichever pooled connection is free, and the guest's binding is a named import (`identity-database-query`), which the plugin serves from a per-credential pool with no affinity at all. A `BEGIN` sent as one call therefore does not cover the `SELECT` sent as the next, and a `COMMIT` can land on a connection that never saw the `BEGIN`.

The first guest version bracketed `transaction()` with `BEGIN` / `COMMIT` and refused to boot (`sharesTransaction()`, HTTP 503) when two `txid_current()` reads disagreed. Sequential requests passed only because a single connection happened to serve them. The first overlapping requests split a transaction across two connections, which left one connection `idle in transaction` in the host's pool forever (the plugin recycles connections without a reset), so every later boot read two different transaction ids and the workload answered 503 until its host pod was restarted.

The guest now runs in autocommit and never opens a transaction:

- Every statement commits on its own. `FOR UPDATE` and `pg_advisory_xact_lock` last for that statement only, so they serialize nothing on the guest. They stay in the code because the Bun server still relies on them. `packages/core/src/shared/infrastructure/postgres.ts` reserves one connection for each `transaction()`.
- Anything that must be atomic or single-use is one statement, and the Bun server runs the same statement inside its transaction:
  - `AuthorizationRepository.commitGrant` stores the tokens of a code or refresh grant with `UPDATE … WHERE` the code is still unused or the refresh token is still current. The loser of a concurrent exchange is treated as the replay it is (code: the authorization is deleted; refresh: `claimReplayedRefresh` revokes the family and audits).
  - `ChallengeRepository.claim` consumes a passwordless token with a conditional `UPDATE`; `insertUnlessRecent` applies the one-per-minute rule in the insert itself.
  - `DirectoryRepository.demoteOwner`, `deleteMembershipUnlessLastOwner`, and `archiveUnlessLast` check the last-owner and last-platform-admin rules in the statement, locking the other owners' rows with a `FOR UPDATE` sub-select so two concurrent changes wait for each other and re-check.
  - `LinkRepository.takeConfirmation` is a `DELETE … RETURNING`, and `deleteUnlessLastMethod` keeps the account's last sign-in method in the statement.
  - `NotificationRepository.claim` takes a due row by moving its next attempt forward, so two invocations draining the outbox never send the same mail.
  - Client registration and update write `oauth2_registered_client` and `oauth_client_lifecycle` in one data-modifying CTE.
- Not atomic on the guest, by design: bootstrap reconcile (idempotent upserts, repaired by the next run, the fingerprint is stored only after success), admin invite and the JSON `createUser` / `createOrganization` (a failure after the first insert leaves a row the next attempt reports as a conflict), and the audit rows written after a change (a change can commit with its audit row missing).
- `query-batch` scripts (schema migrations) are still one implicit transaction: the simple query protocol runs a multi-statement string on one connection and rolls all of it back on error.

`packages/core/tests/autocommit.test.ts` runs the single-use and last-owner invariants against the Bun pool with `transaction()` disabled, which is what the guest sees. `apps/guest/src/boot.test.ts` boots the guest over two connections used in turn.

## 2. Signing keys and passwords

Guest `node:crypto` does not implement `sign`, `verify`, or `createPrivateKey`, and the guest has no `Bun.password`. `Hashing` (SHA-256, HMAC, `randomBytes`) stays on `node:crypto`.

New pure-JavaScript modules, with no nested Wasm:

- `packages/core/src/shared/infrastructure/crypto/rsa.ts` — RS256 PKCS#1 SHA-256 sign and verify
- `packages/core/src/shared/infrastructure/crypto/mldsa.ts` — ML-DSA-65 sign and verify (`@noble/post-quantum`)
- `packages/core/src/shared/infrastructure/crypto/argon2id.ts` — Argon2id at Spring’s parameters (`memoryCost` 16384, `timeCost` 2)
- `packages/core/src/shared/infrastructure/crypto/base64url.ts` — shared by cursors and the hashers

`PasswordHasher` uses `Bun.password` when it exists and the JavaScript hasher otherwise, so PHC strings still match the Bun server. `SigningKeys.load` still fail-closes unless the active private JWK is RS256 or ML-DSA-65. `CursorCodec` no longer uses `Buffer`, so directory cursors work in the guest.

On QuickJS, one Argon2id hash or verify of those parameters takes about 30 seconds in the pure JavaScript hasher. The guest therefore registers the `argon2` interface of the composed `pqc-subtle:crypto@0.1.0` component (`@di-framework/wasm-pqc-subtle/component`, plugged in by the platform build) through `registerPasswordApi` in `apps/guest/src/app.ts`, which hashes in native Wasm in milliseconds with the same PHC shape. The JavaScript hasher remains the fallback when neither `Bun.password` nor a registered hasher exists.

## 3. Settings and readiness

Non-secret settings come from the `wasi:config` binding on `IdentityConfig` in `apps/guest/src/bindings.ts`: signing algorithm, SMTP port, bootstrap ids, and notification flags.

`SMTP_HOST` is not in that binding. The operator writes it, with the issuer URL, public origin, signing keys, SMTP password, bootstrap passwords, and client secrets, into `identity_runtime_secret (name, value)` from `V13__runtime_secrets.sql`. The guest reads those rows in `loadGuestSettings`, and a table value wins over wasi:config.

The first request runs `ensureSchema`, then validates signing keys and reconciles bootstrap. `GET /ready` returns the Bun report (`database`, `signing_key`, `smtp`, `bootstrap`). `GET /health` stays liveness.

A component invocation does not keep `NotificationWorker`’s `setTimeout` loop alive. The guest calls `runOnce()` at the end of each request and does not start the timer. The Bun server still calls `start()`.

Each HTTP invocation gets a fresh JavaScript realm, so the in-memory `ready` promise does not survive the request. Without a shortcut, every request re-ran bootstrap and spent about 90 seconds re-hashing the three client secrets. After a successful reconcile the guest stores a SHA-256 fingerprint of the bootstrap people and client settings in `identity_runtime_secret` under `bootstrap_fingerprint`. A later realm with the same fingerprint calls `BootstrapReconciler.markComplete()` and skips the hashes. Changing any of those settings changes the fingerprint, and the next request reconciles again.

That reconcile hashes only what changed. Beside the whole-settings fingerprint the guest stores one per confidential client under `bootstrap_client_fingerprints`, and passes the ids whose fingerprint still matches to `reconcile({ settledClients })`, which keeps their rows as they are. Adding the CLI client or rotating one secret therefore costs one hash at most, not three.

Only one realm reconciles at a time. Before reconcile the guest claims `bootstrap_lease` in `identity_runtime_secret` with a single `INSERT … ON CONFLICT DO UPDATE … WHERE value < now RETURNING` (three minutes, released after the fingerprints are stored). Every other request that arrives meanwhile gets its own realm, loses the claim, and answers 503 with `Retry-After: 5` at once instead of starting the same hashing. Before the lease, a client that polled `/health` every few seconds spawned a realm per poll, each hashing on the host's one CPU, and nothing finished. A realm the host aborts mid-reconcile leaves the lease to expire.

## 4. HTTP surface

`routeRequest` now accepts either a filesystem asset URL (the Bun server) or an embedded `Map` of bytes (the guest), plus an optional HTML shell. `apps/client/src/server/handler.ts` embeds that shell instead of always reading `index.html` with `Bun.file`.

`apps/guest/scripts/embed-assets.ts` generates `embedded-assets.ts`. Migrations are not copied into a TypeScript module. `embed-migrations.ts` reads `packages/migrations/migrations` and writes `apps/guest/src/migrations.json`, which the component bundle inlines. Run that script before `di-framework platform deploy` so the image matches the Flyway files. The guest applies one version at a time and records it in `identity_schema_migrations`.

That routes the existing control plane and browser app without new handlers:

- Admin JSON: users, organizations, memberships, OAuth clients, audit
- Account links
- `POST /oauth2/token`, introspect, revoke, `GET /oauth2/jwks`, userinfo, discovery
- Browser routes: `/login`, passwordless, `/oauth2/authorize`, consent, admin HTML, account pages
- Session cookie `identity_session` through `SessionService` and `browser_sessions`

## 5. SMTP

`smtp-mail-sender.ts` no longer calls `Bun.connect`. The dialogue uses `node:net`. EHLO, AUTH, MAIL, RCPT, and DATA are unchanged. STARTTLS or implicit TLS fail closed when `wasi:tls` is not linked. The stock host image has no TLS provider; the identity platform stack runs the tenant host as `ghcr.io/di-framework/wash:2.8.0-wasi-tls`, which links `wasi:tls/client@0.3.0-draft`. The destination host is the `SMTP_HOST` row in `identity_runtime_secret`, not a value compiled into the guest.

Egress is the `identity-egress` backing service. `allowedIpNameLookups` in `apps/guest/di-framework.config.json` lists the hosts the workload dials, and it is unset in this repo. Public IdP hostnames were left out of that list: DNS answers for those names changed often enough to reconcile the workload, roll the replica, and wipe in-memory bootstrap.

## 6. Schema changes

`V13__runtime_secrets.sql` creates `identity_runtime_secret`.

`V14__varchar_hashes.sql` changes every `char(n)` column the guest reads to `varchar`, using `rtrim` so fixed-width padding is not kept:

- `browser_sessions.id`
- `email_challenges.token_hash` and `request_ip_hash`
- `oauth_refresh_token_history.token_hash`
- `identity_link_flows.token_hash` and `session_hash`
- `identity_unlink_confirmations.token_hash` and `session_hash`
- `identity_security_notifications.event_key`

`wasmcloud:postgres@0.2.0` returns `value-conversion-failed` when it tries to decode `bpchar`. Inserts succeeded and reads of those columns failed, which surfaced as HTTP 500 on `POST /login`, account pages, and passwordless. `varchar` and `text` already decode.

Applied migrations were not edited. The guest applies `V14` on the next boot.

## 7. Platform fixes outside this repo

These live in `cli-extensions` (`@di-framework/cli-plugin-platform`) and are bundled into the guest at `di-framework platform deploy`.

**HTTP body future type.** `POST` requests trapped in Wasmtime with `handle is a future of a different type`. `Request.consumeBody` must receive the `wasi:http/types@0.3.0` future `RESULT_VOID_WASI_HTTP_TYPES_*_ERROR_CODE`. `pickFutureType` in `assets/http-adapter.ts` was selecting the generic `RESULT_VOID_ERROR_CODE`, which is a different future type. It now prefers the HTTP error-code future.

**URLSearchParams polyfill.** QuickJS has no `URLSearchParams`. The polyfill in `src/node-compat/fetch-runtime.ts` originally had `get` and `toString` only. Account pages call `has`, authorize builds redirects with `set`, and consent reads repeated `scope` fields with `getAll`. Those calls threw and the pages returned 500. `set` now updates the parent `URL`’s `search` and `href`. `+` in query strings and form bodies is decoded as a space. Without that, `scope=openid+profile+email` was one scope name and `/oauth2/authorize` redirected with `error=invalid_scope`.

## 8. Deploy

```bash
cd deploy/platform
pulumi up
```

The program creates the di-framework-kube instance and platform, then the component registry. It then runs `di-framework platform deploy identity --target identity` whenever the guest's sources change, with the registry port-forwarded for the push. That builds `apps/guest/dist/identity.wasm`, pushes it to `IDENTITY_REGISTRY_PUSH`, and updates `WorkloadDeployment/identity` in `di-tenant-<tenant>` (the stack's required `tenant`). No second Postgres service is created. Egress is limited to the hosts in `allowedIpNameLookups`.

The platform otherwise runs tenant hosts on stock `ghcr.io/wasmcloud/wash:2.8.0`, a default-features build whose host world has no `wasi:tls/client@0.3.0-draft`, and a deploy warns that the component imports `wasi:tls`. `deploy/platform` sets the platform's `tenantHostImage` to `ghcr.io/di-framework/wash:2.8.0-wasi-tls`, pinned by digest, with pull policy `IfNotPresent`. That is the platform repo's `platform/tenant-host` build: `--features wasi-tls` on wasmCloud `v2.8.0`, with the postgres invocation-lease patch. Stack config `tenantHostImage` overrides it, and `tenantHostLocalImage` publishes and runs a local build instead (see `deploy/platform/README.md`).

## 9. What failed on the way to the proof

| Symptom | Cause | Change |
| --- | --- | --- |
| Workload rolled continuously | Egress allow-list included public IdP names whose DNS answers changed | Allow-list limited to the SMTP host |
| `POST` trapped: future type mismatch | HTTP body completion used the wrong void future | `pickFutureType` selects the HTTP 0.3 error-code future |
| `POST /login` returned 403 | CSRF token was sent without the `identity_session` cookie from `GET /login` | Proof client stores `Set-Cookie` and sends it back |
| `GET /ready` and `GET /health` took ~90s and died if the client gave up | Argon2id bootstrap ran in the request, and a disconnected client aborted it | Long first request; later requests use the fingerprint |
| Every request hung after a settings change, host CPU pegged | Each concurrent request's realm re-ran the full reconcile and re-hashed all three client secrets | `bootstrap_lease` lets one realm reconcile, others answer 503; per-client fingerprints skip unchanged secrets |
| Login, account, and passwordless returned 500 `value-conversion-failed column 0` | `char(n)` / `bpchar` results | `V14` converts those columns to `varchar` |
| Account and authorize returned 500 at `banner` / `withQuery` | Polyfill lacked `has` and `set` | Polyfill implements `has`, `set`, `append`, `delete`, `getAll`, and writes back `URL.search` |
| Authorize returned `invalid_scope` | `+` was left in the scope string | Polyfill decodes `+` as a space |
| Organization create returned 401 on a long proof | Opaque access tokens expire in 600 seconds, and the slow path outlived that | Fingerprint makes later requests fast enough to use the token |
| Every request re-hashed client secrets | New JavaScript realm per invocation, and `ensureClient` always re-hashes | Fingerprint row plus `markComplete()` |

`POST` login also requires the cookie and `_csrf` from the same `GET /login`. A body-only post is a new anonymous session and fails the CSRF check.

## 10. Proof

After the last deploy (`WorkloadReplicaSet` `identity-65d84f4f44`, Ready), against the gateway with `Host: identity.identity.localhost`:

| Check | Result |
| --- | --- |
| `GET /ready` | 200, all four checks and `ok` true |
| `GET /oauth2/jwks` | 200, `kid` `identity-active` |
| `POST /oauth2/token` client credentials, scope `admin:write` | 200, opaque access token |
| `POST /login` as the bootstrap owner | 303 to `/`, `identity_session` set |
| `GET /account/identity-links` with that cookie | 200, `signedIn` true, page `links` |
| Authorization code + PKCE, scope `openid profile email` | 302 to the redirect URI with `code`; token exchange 200; ID token `kid` `identity-active`; RS256 signature verified against the JWKS |
| `POST /passwordless` for `owner@identity.local` | 200; Mailpit accepted the message |
| `POST /api/admin/organizations` | 201, then 409 for the same slug |

The authorization-code request returned the code directly because this client and user already had a stored consent from an earlier attempt. The code was still exchanged with the PKCE verifier and the ID token verified.

Bootstrap passwords and client secrets used by the proof were read from `identity_runtime_secret` in the `directory` database. They are not recorded here.

## Files

**This repo**

- `apps/guest/**` — component, bindings, SQL adapter, embedded assets and migrations, boot tests
- `di-framework.deploy.toml` — target `identity`
- `packages/migrations/migrations/V13__runtime_secrets.sql`
- `packages/migrations/migrations/V14__varchar_hashes.sql`
- `packages/core/src/shared/infrastructure/crypto/` — `argon2id.ts`, `rsa.ts`, `mldsa.ts`, `base64url.ts`; `passwords.ts` and `signing-keys.ts` call them
- `packages/core/src/shared/infrastructure/postgres.ts` — dynamic `bun` import
- `packages/core/src/mail/infrastructure/smtp-mail-sender.ts` — `node:net`
- `packages/core/src/bootstrap/application/bootstrap-reconciler.ts` — `markComplete()`
- `apps/server/src/serve.ts` and `apps/client/src/server/handler.ts` — embedded assets and shell
- Repository `RETURNING 1` updates listed in section 1
- `packages/core/package.json` — `@noble/hashes`, `@noble/post-quantum`

**cli-extensions**

- `packages/cli-plugin-platform/assets/http-adapter.ts` — HTTP 0.3 body future
- `packages/cli-plugin-platform/src/node-compat/fetch-runtime.ts` — `URLSearchParams` methods and `+` decoding

## 11. pglite (identity-server#50)

The guest no longer binds to a Postgres BackingService. `apps/guest/src/database.ts` opens the
`di-framework:pglite/database@0.2.0` import with `createWasmPgliteDatabase` from
`@di-framework/pglite-component` (6.0.11), the `SqlDatabase` adapter the provider publishes, and
the repositories, migrations and bootstrap run on it unchanged. `di-framework platform build`
(cli-plugin-platform 6.1.2) composes the provider into the component from
`ghcr.io/di-framework/pglite-component@sha256:9a00ac39…7d5e` (with pgcrypto; earlier `8bc30505…3286`). The deployed workload has one
replica, `deployPolicy: Recreate`, platform persistent storage at `/data`,
`DI_PGLITE_DATA_DIR=/data/pglite`, and `di-framework.dev/exclusive-instance`, so the exclusive
tenant host (`wash:2.8.0-wasi-tls-exclusive`) serves it from one component instance.

What changed against sections 1 and 3:

- **Transactions are real.** The provider has one connection per instance and the adapter puts
  every statement behind one mutex, so `transaction(fn)` is `BEGIN` … `COMMIT` with savepoints
  for nested calls, and a second transaction waits for the first instead of blocking on a row
  lock. The single-statement invariants from section 1 still hold and still protect the Bun
  server. The pooled-connection test in `packages/core/tests/postgres.test.ts` stays a Bun server
  test; `apps/guest/src/boot.test.ts` has the single-connection counterpart.
- **Migrations** run each Flyway file and its `identity_schema_migrations` row in one
  transaction. All of them apply on PostgreSQL 17.5.
- **Runtime secrets** come from the WASI environment, filled from `identity-control`
  (see `docs/configuration.md#wasmcloud-guest`). `V16__runtime_secrets_to_secret.sql` deletes any
  secret rows an earlier guest stored in `identity_runtime_secret`; that table keeps only the
  bootstrap fingerprints and the reconcile lease. Without `ISSUER_URL`, `AUTH_PUBLIC_ORIGIN` and
  `AUTH_ACTIVE_PRIVATE_JWK` the guest answers 503 and names the missing keys.
- **The instance is warm.** With the exclusive pool policy the instance, its database connection
  and its `ready` promise survive between requests; requests are served one at a time.

Tests: `apps/guest/src/guest.test.ts` and `boot.test.ts` run the guest on an in-process PGlite
(`@electric-sql/pglite` 0.4.6, PostgreSQL 17.5) behind the real adapter
(`apps/guest/tests/support/pglite.ts`): every migration, boot and bootstrap fingerprints and lease,
the admin API, a browser sign-in with consent and a PKCE code exchange, transactions on one
connection, and a restart on the same data directory. The fixture loads
`@electric-sql/pglite/contrib/pgcrypto`, so the column encryption opt-in, flows on ciphertext,
the `bytea` round trip through the WIT `blob` variant and the fail-closed restart without keys
run there too; `pgcrypto: false` models a provider build without the extension
(docs/configuration.md#column-encryption).

### Proof on a fresh instance

2026-10-12, kube instance `pgprove` (platform 6.0.11-equivalent main, published
`wash:2.8.0-wasi-tls-exclusive`), tenant `pgprove`, deployed as the tenant developer with
`deploy/guest/deploy.sh` and freshly generated values; pushed to the tenant registry. The
authorization-code rows are from the redeploy after the security review (the tenant check passed
as the developer: `di-tenant-pgprove has no Postgres directory BackingService`).
`apps/guest/scripts/live-check.ts` drove the gateway with `Host: identity.pgprove.localhost`:

| Check | Result |
| --- | --- |
| `/health` before the Secret had values | 503, `runtime settings missing from the identity-control Secret: ISSUER_URL, AUTH_PUBLIC_ORIGIN, AUTH_ACTIVE_PRIVATE_JWK` (database opened and migrated first). Since #57 the body is generic (`reason: runtime-settings-missing`) and the names are in the log. |
| After `runtime-secrets.ts apply` | `/health` 200 within 12 s; `/ready` all true |
| Provisioner client credentials, `POST /api/admin/organizations` | 201, then 409 for the same slug; `GET` 200 |
| Owner sign-in, consent, PKCE code exchange, UserInfo | 303, 303, 200, 200 |
| 32 parallel `/ready`, `/oauth2/jwks`, `/login` | all 200 in 0.7 s |
| Tenant host pod deleted | workload Ready again without a re-push; the organization reads back, the owner signs in with the password hashed before the restart, the stored consent is reused, same subject |
| Second `deploy.sh` (Secret deleted, CLI deploy, values re-applied) | 503 for one poll while the CLI's roll ran without values, then 200; data intact |
| Authorize validation: unknown client, unregistered redirect URI | 400, 400 |
| Code exchange: wrong PKCE verifier, wrong redirect URI, correct exchange, ID token verified against `/oauth2/jwks` (RS256, nonce, subject), code replay, wrong client secret | 400, 400, 200, verified, 400, 401 |
| Refresh: rotation, narrowing to `profile`, widening to `admin:write`, reuse of a rotated token, the family after reuse | 200, 200, `invalid_scope`, `invalid_grant`, 400 |

### Column encryption on `pgprove`

2026-10-12, the same instance and tenant, with the pglite provider pinned to
`sha256:9a00ac39…7d5e` (pgcrypto 1.3). The guest was built with cli-plugin-platform 6.1.2 and
pushed as the tenant developer `pgdev` through the tenant registry front, the same path as the
proving-grounds harness. Opted in with `runtime-secrets.ts column-keys --enable` and `apply`. The
database already held data from before the opt-in. Only status codes, counts and booleans were
recorded:

| Check | Result |
| --- | --- |
| Opt-in boot (V17–V19, pgcrypto probe, latch) | `/health` 200, `/ready` all true; state row enabled with both key checks; 11 encryption triggers |
| Admin API: create a user after opt-in, read it back, list | 201, 200 with the decrypted email and display name, list decrypted |
| Duplicate email of the new row (padded, lower-cased) | 409 through the blind index |
| Duplicate email of a legacy row (upper-cased) | 409 through legacy plaintext |
| Owner sign-in with the upper-cased email | signed in (legacy plaintext lookup) |
| Organization create/duplicate/read; sign-in, token, UserInfo; code exchange with ID token verification; refresh rotation and reuse | 201/409/200; 303, 200, 200; all as before. Consent was already stored for the owner, so it was reused rather than shown. |
| At rest, on a copy of PGDATA (database `template1`) taken after a clean shutdown, checked with the key and printing counts only | users: 2 encrypted rows, plaintext NULL, blind index set, both decrypt to an address, 2 legacy plaintext rows. `browser_sessions` 5, `auth_audit_records` 6, `oauth2_authorization` 3, `email_challenges` 2 encrypted rows, none with plaintext beside them, all decrypt. No ciphertext contains its plaintext. Legacy rows stay plaintext. |
| Restart with a Secret without the keys or the switch | `/health`, `/ready`, `/login`: 503 `{"error":"service unavailable","reason":"column-encryption-unavailable"}` |
| Keys restored | `/health` 200, `/ready` all true, flows and lookups as above |

As a tenant developer, replacing `identity-control` with a copy that drops keys is refused by
`tenant-secret-update`. The no-keys restart therefore deleted the Secret first, as `deploy.sh`
does.

### Data directory encryption on `pgprove`

2026-10-12, the same instance and tenant, as a **fresh** guest named `pgenc` (its own workload,
`pgenc-control` Secret and empty data directory; the plaintext `identity` guest was left as it
was). Built with cli-plugin-platform from cli-extensions `f15f84b` (main with #70 and #72,
unreleased), packed with `bun pm pack` and installed into an isolated extensions directory;
deployed with `deploy/guest/deploy.sh` as the tenant developer `pgdev` and freshly generated
values with `--column-encryption`. Only statuses, counts, booleans and KCVs were recorded:

| Check | Result |
| --- | --- |
| Build | `Composing the PGlite encryption layer into the provider`; deploy reports `encrypted at rest by ghcr.io/di-framework/pglite-encfs@sha256:46863e8b…a5d414` |
| Deployed component (fetched back from the tenant registry) | layer `sha256:041784d1…` (the pin's wasm layer) and the composed provider embedded verbatim; `custom "di-framework:pglite-encfs"` section present |
| First start, before `apply` (no `DI_PGLITE_KEY`) | every path 503 `boot-failed`; host log `pglite-encfs: DI_PGLITE_KEY is not set or invalid; refusing all file access`; data directory still empty (0 files) |
| After `apply` | `/health` 200 in 21 s; `/ready` all true (column encryption opted in at first boot) |
| Organization create, duplicate, read; owner sign-in, consent, token, UserInfo | 201, 409, 200; 303, 303, 200, 200 |
| Code exchange, ID token, refresh checks | as in the table above |
| Admin user create, read, list, duplicate email | 201, 200 decrypted, list decrypted, 409 |
| Tenant host pod deleted | `/health` 200 after 96 s; organization, user and owner sign-in read back with the same subject |
| Data directory on the node | 1767 files: 1581 with an encfs header under the key's KCV, 186 empty, 0 without a header; `.di-encfs` KCV equals `runtime-secrets.ts kcv`; the probe slug, the probe user's login and address, `pg_catalog`, `PostgreSQL`, `template1`: in 0 files (the plaintext `identity` directory: 26, 44, 5 files for the last three) |
| Secret recreated without `DI_PGLITE_KEY`, workload rolled | every path 503 `boot-failed`; same refusal in the host log; tree digest of the directory identical before and after, and again after five more requests |
| Secret with a different key | 503; `pglite-encfs: the data directory was encrypted with a different key (key check value mismatch); refusing`; tree digest unchanged |
| Key restored with `runtime-secrets.ts apply` | `/health` 200 in 5 s; data and sign-in as before, same subject |
| Second `deploy.sh` | CLI: `Kept control Secret pgenc-control: it holds declared app keys this deploy cannot read`; same KCV; `/health` 200; data intact |

The first `deploy.sh` stopped at the CLI's readiness wait (exit 3) while the tenant host rolled
to mount the new directory; the workload was Ready after 110 s and `apply` was run on its own,
as documented then. `deploy.sh` now waits for Ready itself and continues to `apply`. After the pod deletion the host container restarted once on a NATS connection
refusal at startup, unrelated to the layer. Key rotation was not exercised live (the platform's
`make smoke` covers it).

### The acceptance suites from #50

#50 asks for `examples/app/src/journey.test.ts` and `apps/server/tests/authorization-code.test.ts`
on the fresh instance. Neither can be pointed at a deployed guest as written:

- `examples/app/src/journey.test.ts` tests `examples/app`, a separate `@di-framework/auth` demo
  (`/auth/register`, `/me`, `__Host-sid`) with its own in-memory store. It imports no identity
  code and the guest has none of its routes, so there is nothing of it to run against `pgprove`.
  It passes in `bun test` as before.
- `apps/server/tests/authorization-code.test.ts` sets up through the database: it registers
  clients and inserts users with repositories, changes rows with SQL (avatar, archived and
  inactive users, expired codes) and reads audit rows. The pglite database inside the workload
  has no network path, so those steps cannot run remotely. Instead:
  - the whole suite (9 tests) runs on PGlite 17.5 behind the guest's adapter, in CI:
    `IDENTITY_TEST_DATABASE=pglite bun --config=bunfig.pglite.toml test apps/server/tests/authorization-code.test.ts`
    (9 pass);
  - its HTTP-only assertions run against `pgprove` through `authorizationCodeChecks` in
    `apps/guest/tests/support/flows.ts` (rows above), also run in-process by `boot.test.ts`.

| authorization-code.test.ts | On `pgprove` (live-check.ts) | On PGlite in CI |
| --- | --- | --- |
| login, consent, code, tokens, ID token, UserInfo, consent reuse, code replay | sign-in, consent, exchange, ID token verified, UserInfo, consent reused after restart, replay 400 | yes |
| refresh rotation and reuse revoking the authorization | rotate, narrow, widen refused, reuse `invalid_grant`, family revoked (the audit row is not readable remotely) | yes |
| authorize request validation | unknown client, unregistered redirect URI (the other cases need extra clients) | yes |
| code exchange checks client, expiry, redirect URI, PKCE | wrong secret 401, wrong redirect 400, wrong verifier 400 (expiry needs SQL) | yes |
| consent bound to the pending request and user | not remote (needs a second user) | yes |
| UserInfo refuses inactive users | not remote (needs SQL) | yes |
| prompt=login, max_age, prompt=none | not remote | yes |
| archived users get nothing | not remote (needs SQL) | yes |
| public loopback client | not remote (needs a public client) | yes |

### authproto cutover

Signed off on 2026-10-12: **migrate everything**, the data and the runtime secrets (issuer, public
origin, signing key, bootstrap passwords, client secrets, SMTP), into a pglite guest in a **new
tenant** on authproto, and keep the issuer by moving its host to the new tenant with a platform
**gateway route alias** (decided 2026-10-13). The tools below are proven offline against a
synthetic Postgres-era database, and the whole runbook, platform upgrade, route switch and
rollback included, ran end to end on the `pgprove` rehearsal instance (see
[Proof](#proof-of-the-cutover-tooling)), except one dependency pgprove did not have: authproto's
tenant-auth pods discover the issuer that is being cut over. Nothing here has run against
authproto yet. It needs
`@di-framework/platform` 6.0.13 and `di-framework-kube` v0.0.5 or later ([Runbook](#runbook)).

#### What moves, and how

| Step | Tool | What it does |
| --- | --- | --- |
| Export | `deploy/cutover/export.ts` | One read-only statement over `kubectl exec ... psql` reads the schema history, every table's rows (as PostgreSQL's own `json_agg` text) and count, and the `identity_runtime_secret` rows, as one snapshot. Writes a mode 0700 directory: `manifest.json` (version, tables, columns, counts, digests; no values), `tables/<t>.json`, `values.json` (the deploy.sh values file), `state.json`, and `directory.dump` (`pg_dump -Fc` of the whole database, for rollback). Files are 0600 and nothing is printed but names and counts. |
| Key | `deploy/guest/runtime-secrets.ts pglite-key` | Adds `DI_PGLITE_KEY` to `values.json` (a new data directory needs a new key) and prints its KCV. |
| Import | `deploy/cutover/import.ts` | Runs the guest's own encrypted provider (`apps/guest/.di-framework/di-framework-pglite.encrypted.wasm`, checked to be byte for byte the provider inside `apps/guest/dist/identity.wasm`) under `wasmtime`, plugged into a small wasip2 runner (`deploy/cutover/pglite-runner`, Rust) that serves `di-framework:pglite/database` to the guest's own adapter over stdin/stdout. Initialises a fresh encrypted directory, migrates it to the source version with the guest's migration code, loads every table and the bootstrap fingerprints in one transaction, checks the counts inside it, then checks every file on disk is encfs ciphertext under the key's KCV and contains no engine string or user login or email. |
| Rehearse | `deploy/cutover/rehearse.ts` | Boots the guest's request handler in-process on a **copy** of the imported directory, through the same provider: `/ready`, the later migrations, no bootstrap reconcile, the bootstrap organization, issuer and signing key `kid`, owner and viewer sign-in (a password changed since bootstrap is a `note` when the stored hash is proven carried), the three bootstrap clients' secrets, row counts and carried password hashes (`rehearse-core.ts`). |
| Install | `deploy/cutover/install.ts` | Dry run by default; the dry run lists the target through a read-only helper pod (DAC_READ_SEARCH only, only `<storageRoot>/di-tenants/<tenant uid>` mounted read-only, never created) and refuses a non-empty one. With `--yes`, a helper pod on the node (the platform's storage-init image, root with CHOWN and DAC_OVERRIDE only, with exactly the target directory mounted) copies the directory into `<storageRoot>/di-tenants/<tenant uid>/workloads/identity` (what the platform mounts as the guest's `/data`), directories 0700, files 0600, then owner 65532, and compares every file's SHA-256 and owner. The pod is deleted on success and on failure; a failed delete names it. Refuses a non-empty target (before sending anything), a tenant with `directory`, a tenant that already has the WorkloadDeployment (unless `--allow-existing-workload`), and a directory whose marker KCV is not the values file's. |
| Deploy | `deploy/guest/deploy.sh` | Unchanged path, with the guard lifted for this case only (below), pushing into the new tenant's own registry. |
| Route | `di-framework-kube up --platform-config` | Adds the gateway route alias `identity.identity` → `identity.<new tenant>`, so the issuer's host reaches the new tenant; removing it is the route rollback. |

Decisions and what they rest on:

- **Supported sources: V13..V15.** The Postgres-era guest records its migrations in
  `identity_schema_migrations`. authproto was deployed from the last Postgres-era commit
  (`23be792`, before #53 added V16), whose guest embeds V1..V15, so authproto is expected at
  **V15**; `export.ts` prints the version it found. V13 created `identity_runtime_secret`; V16 and
  later have deleted the secret rows, so such a source is refused. A source whose `_migrations`
  (the Bun server's history) is ahead of the guest's is refused too.
- **JSON, not a `pg_dump` script, carries the data.** A plain `pg_dump` is a psql script
  (`pg_dump` 16.10 and later wrap it in `\restrict`, and `COPY ... FROM stdin` needs psql), which
  the provider's `exec` cannot run. `json_agg` and `json_populate_recordset` move every value in
  PostgreSQL's own text form, and the importer names every column. `pg_dump -Fc` is still taken,
  as the rollback backup.
- **Runtime secret rows.** The old guest merged every row over wasi:config, and every setting it
  read is a name of the new guest's environment, so each row goes to `values.json` under its own
  name. That includes the eight bootstrap identity settings (`AUTH_BOOTSTRAP_ORGANIZATION_*`,
  `AUTH_BOOTSTRAP_OWNER_*` and `AUTH_BOOTSTRAP_VIEWER_*` but the passwords, which are secrets
  already): authproto overrides all eight, so the new guest reads them from its environment
  (`RUNTIME_BOOTSTRAP_IDENTITY_SETTINGS` in `apps/guest/src/settings.ts`, declared in
  `controlSecretKeys`) over its compiled-in defaults, exactly as the old guest's rows did. They
  are personal data, not secrets: a separate group (`BOOTSTRAP_IDENTITY_NAMES`), in the same
  Secret because that is the guest's only environment, and never printed. Any other name is refused (it changed the old guest's settings; dropping it silently
  would change the new guest's). `bootstrap_fingerprint` and `bootstrap_client_fingerprints` go
  to `state.json` and are inserted into the new `identity_runtime_secret`, so V16 deletes nothing
  (the import checks it) and the new guest, given the same settings, finds the same fingerprint
  and does not reconcile bootstrap. `bootstrap_lease` is dropped. The signing key lives only in
  `AUTH_ACTIVE_PRIVATE_JWK`, so carrying it keeps the issuer, the `kid` and every issued token.
- **The database is `template1`** (di-framework/platform#212): the runner opens the provider with
  its defaults, as the guest does, at the guest's `DI_PGLITE_DATA_DIR` (`/data/pglite`).
- **Later migrations run in the guest.** V16 deletes no imported row; V17 strips old secrets from
  imported sessions; V18..V20 install column encryption, off unless `IDENTITY_COLUMN_ENCRYPTION`
  is set (new writes only).

#### Guards

`deploy/guest/deploy.sh` and `runtime-secrets.ts guard` (also run by `apply`) treat the target as
authproto when the instance argument is `authproto`, when the kubeconfig is authproto's (its path
in kube's state directory, or a kubeconfig naming the same API server), or when the cluster has a
`directory` BackingService in **any** namespace, whatever the instance argument says. Such a
target is refused except for a tenant other than `identity` with exactly
`IDENTITY_AUTHPROTO_CUTOVER=authproto/<tenant>` in the environment (no trimming; the prefix is
the literal `authproto` whatever the instance is named, `pgprove` included), whose tenant
host (`hostgroup-tenant-<tenant>` in `di-runtime-<tenant>`) runs the exclusive-instance wash build
(matched by image name; `IDENTITY_EXCLUSIVE_HOST_DIGEST` adds a digest pin, see P2).
Every target still refuses a tenant whose `di-tenant-<tenant>` has the `directory` BackingService,
and every entry point refuses a tenant name that is not a DNS-1123 label. A tenant developer
kubeconfig (namespaced Role `di-developer`) may not list BackingServices cluster-wide; when that
list is Forbidden and neither the instance nor the kubeconfig names authproto, the guard warns and
checks `di-tenant-<tenant>` only. On a target named authproto a forbidden (or any failed) list
refuses, so the cutover runs with authproto's admin kubeconfig. The kubeconfig match compares the
first `server:` line as text: an alias of the same address or a multi-cluster kubeconfig used with
`--context` does not match, which matters once `directory` (the cluster-wide signal) is retired. The Pulumi program accepts `kubeInstance: authproto` only with
`cutoverConfirm: authproto/<tenant>`, and still refuses any cluster with a `directory`
BackingService, because `kube up` would rewrite authproto's whole install, tenant `identity`
included; so the cutover uses `deploy.sh`, not Pulumi.

> **Gate: export the runtime-secret rows before any migration at V16 or later touches
> `directory`.** V16 deletes every `identity_runtime_secret` row except the bootstrap state. On
> authproto those rows may be the only copy of the signing key (`AUTH_ACTIVE_PRIVATE_JWK`) and the
> client secrets. Any migrator from this repository at or after V16 does it: the pglite guest
> never connects to Postgres, but the Bun server (`bun start`, `applyMigrations`) with
> `DATABASE_URL` pointed at `directory` would. Export first (step 3 below), and check the export
> before running anything newer than V15 there. A `DELETE` does not erase the values: they stay in
> dead tuples until `VACUUM`, in WAL until it is recycled, and in every existing `pg_dump` or
> volume backup until rotation. Treat those as secret-bearing until then.

#### Runbook

Run from an identity-server checkout at the commit that adds these tools, on the machine that
holds authproto's kubeconfig and its di-framework-kube state. Keep `$OUT` on an encrypted volume,
in a path without spaces; it will hold every secret, all user data and a copy of the platform
stack's state and passphrase.

**Versions.** The route move needs releases that are new with this runbook:

| Tool | Minimum | Why |
| --- | --- | --- |
| `@di-framework/platform` | **6.0.13** | gateway route aliases (`routeAliases`, platform #218/#219); since 6.0.11 tenant hosts get only the `insecureRegistries` entries as plain-HTTP registries |
| `di-framework-kube` | **v0.0.5** | passes `routeAliases`, `tenantAuth`, `insecureRegistries` and the backing-class keys through `--platform-config` (kube #10/#11); older CLIs reject them or wipe hand-set ones on every `up` |
| `@di-framework/cli-plugin-platform` | **6.2.0** | 6.1.0 fails the build with `di-framework:pglite/database@0.2.0` unresolved. If the installed one is older and must stay, install 6.2.0 into its own directory and point `DI_FRAMEWORK_EXTENSIONS_DIR` at it for steps 1 and 8 |

Also needed: Bun (with `Bun.YAML`), kubectl, jq, oras, Node.js, npm and the Pulumi CLI (for
`up` and the preview), wasmtime 48, `wasm-tools`, rustup (the runner builds with the toolchain in
`deploy/cutover/pglite-runner/rust-toolchain.toml` on first use), podman (step 12's restore
check), and **`wac` on `PATH`**. The build (`di-framework platform build`) finds `wac` only on
`PATH`; `WAC=<path>` is read by the import runner alone, so it is not enough.

```sh
STATE="$HOME/Library/Application Support/di-framework-kube/authproto"
KC="$STATE/kubeconfig"
CTX="$(kubectl --kubeconfig "$KC" config current-context)"
NEW=identity-pg                     # the new tenant; any DNS label but `identity`
PUSHER=identity-cutover             # a NEW platform user that pushes the guest into $NEW's registry (step 8)
OUT=/path/on/encrypted/volume/authproto-cutover
mkdir -m 700 -p "$OUT"
HTTP_PORT="$(jq -r .httpPort "$STATE/state.json")"   # 28280 on authproto
GW="http://127.0.0.1:$HTTP_PORT"    # authproto's platform gateway
KUBE=/path/to/di-framework-kube     # v0.0.5 or later
PLATFORM_PACKAGE=@di-framework/platform@6.0.13
export PATH="/dir/containing/wac:$PATH"
# Every platform `up` in this runbook goes through this, with a whole config file (see "Rules").
up_platform() {
  "$KUBE" up --name authproto --http-port "$HTTP_PORT" --allow-insecure-registries \
    --platform-package "$PLATFORM_PACKAGE" --platform-config "$1" --timeout 20m
}
# directory's Postgres pod, for the read-only checks below and step 2.
POD="$(kubectl --kubeconfig "$KC" -n di-runtime-identity get pods -l app=di-bs-directory -o jsonpath='{.items[0].metadata.name}')"
psql_directory() { kubectl --kubeconfig "$KC" -n di-runtime-identity exec "$POD" -- psql -X -A -t -U app -d app -c "$1"; }
# Every Tenant's TenantAuthReady, each tenant-auth Deployment's readiness, and its pods with their
# restart counts, sorted. Two snapshots compared with diff show any restart (a new pod name too).
# Fails closed: a kubectl error or no tenant prints an ERROR line, which no check accepts, and a pod
# without container statuses (Pending) reads ready=false.
tenant_auth_state() {
  tenants="$(kubectl --kubeconfig "$KC" get tenants.platform.di-framework.dev -o jsonpath='{.items[*].metadata.name}')" \
    || { echo 'ERROR cannot list tenants'; return 1; }
  [ -n "$tenants" ] || { echo 'ERROR no tenants listed'; return 1; }
  for t in $tenants; do
    echo "tenant $t TenantAuthReady=$(kubectl --kubeconfig "$KC" get tenants.platform.di-framework.dev "$t" -o 'jsonpath={.status.conditions[?(@.type=="TenantAuthReady")].status}' || echo ERROR)"
    for d in tenant-controller tenant-console; do
      echo "deploy di-runtime-$t/$d ready=$(kubectl --kubeconfig "$KC" -n "di-runtime-$t" get deploy "$d" -o 'jsonpath={.status.readyReplicas}/{.spec.replicas}' || echo ERROR)"
    done
    pods="$(kubectl --kubeconfig "$KC" -n "di-runtime-$t" get pods -l 'app in (tenant-controller,tenant-console)' -o json)" \
      || { echo "ERROR cannot list the tenant-auth pods of $t"; continue; }
    printf '%s\n' "$pods" | jq -r '.items[] | (.status.containerStatuses // []) as $c
      | "pod \(.metadata.namespace)/\(.metadata.name) ready=\(($c | length) > 0 and all($c[]; .ready)) restarts=\([$c[].restartCount] | add // 0)"' \
      || echo "ERROR cannot read the tenant-auth pods of $t"
  done | LC_ALL=C sort
}
```

The confirmation the guard wants is literally `IDENTITY_AUTHPROTO_CUTOVER=authproto/<tenant>`:
the word `authproto`, a slash and the new tenant, whatever the instance is called. On a rehearsal
instance (`pgprove`, with its own `directory`) it is still `authproto/$NEW`, not `pgprove/$NEW`.

**Rules for every platform `up`:**

- **Always a whole file.** `--platform-config` *replaces* every key it allowlists (`tenants`,
  `users`, `tenantHostImage`, `tenantHostImagePullPolicy`, `networkPolicyEngine`, `storageRoot`,
  `egressAllowedDestinations`, `routeAliases`, `tenantAuth`, `insecureRegistries`,
  `backingServiceClasses`, `seedDefaultBackingClasses`); a key left out of the file is removed
  from the stack. Use only the two files P2 writes: `$OUT/platform.json` (no alias) and
  `$OUT/platform-alias.json` (the same plus the alias). Never edit the stack with `pulumi config
  set` in between.
- **Always `--allow-insecure-registries`.** The files list a plain-HTTP registry, and the CLI
  refuses a non-empty `insecureRegistries` without it on every `up`. `up_platform` passes it.
- **A rejected `up` still saves its config** (kube#13): the stack config is written before
  Pulumi validates it. After **any** failed `up`, run `up_platform` again with a known-good file
  (`$OUT/platform.json` before the switch in step 10, `$OUT/platform-alias.json` after it) before
  anything else, and never run a plain `up` (no `--platform-config`) during the cutover: it
  would apply whatever the failed run left behind.
- **Each gateway roll drops connections for under a second** (platform#223). The switch
  (step 10) and the route rollback each roll `di-platform-gateway` once; a client may see one
  failed request and retry.

##### Preconditions (before any freeze)

None of these checks stops or changes the old guest's data. P2 changes the platform (it adds
tenant `$NEW` and restarts every tenant host, the old guest's included), which the user accepted
as a maintenance blip. If a check fails, **STOP**: do not freeze, and present the options to the
coordinator. Resume only once a decision is recorded.

P0. **The source's runtime rows.** `export.ts` refuses any `identity_runtime_secret` row it has no
    setting for (step 3), so compare the names now, names only (never `value`):
    ```sh
    psql_directory 'SELECT name FROM identity_runtime_secret' > "$OUT/source-row-names.raw" \
      && [ -s "$OUT/source-row-names.raw" ] || echo 'STOP: could not read the row names'
    LC_ALL=C sort "$OUT/source-row-names.raw" > "$OUT/source-row-names"
    bun -e "import {RUNTIME_SETTING_NAMES} from './deploy/platform/components/control-secret.ts';
      import {STATE_ROW_NAMES, TRANSIENT_ROW_NAMES} from './deploy/cutover/source.ts';
      console.log([...RUNTIME_SETTING_NAMES, ...STATE_ROW_NAMES, ...TRANSIENT_ROW_NAMES].join('\n'))" \
      | LC_ALL=C sort > "$OUT/known-row-names"
    LC_ALL=C comm -23 "$OUT/source-row-names" "$OUT/known-row-names"   # must print nothing
    ```
    An empty comparison counts only after the read succeeded (no `STOP` line). Any name it prints is a setting the old guest applied that the new guest would silently lose:
    STOP. The known names include the eight bootstrap identity overrides
    (`AUTH_BOOTSTRAP_{ORGANIZATION_SLUG,ORGANIZATION_NAME,OWNER_LOGIN,OWNER_EMAIL,OWNER_DISPLAY_NAME,VIEWER_LOGIN,VIEWER_EMAIL,VIEWER_DISPLAY_NAME}`),
    which authproto sets. They are carried into `values.json` and the `identity-control` Secret
    and override the guest's compiled-in defaults, as the old guest's rows did; without them the
    new guest's bootstrap fingerprint would differ and it would bootstrap a second organization,
    owner and viewer from the defaults. They are personal data, not secrets; the tools print
    their names only.
P1. **The issuer host and the route alias.** While the old guest is still up, read its issuer
    and signing key id from its public documents:
    ```sh
    ISSUER="$(curl -s -H 'Host: identity.identity.localhost' "$GW/.well-known/openid-configuration" | jq -r .issuer)"
    OLD_KID="$(curl -s -H 'Host: identity.identity.localhost' "$GW/oauth2/jwks" | jq -r '.keys[].kid')"
    [ "$ISSUER" = "http://identity.identity.localhost:$HTTP_PORT" ] && [ -n "$OLD_KID" ] \
      && echo "issuer $ISSUER, kid $OLD_KID" || echo "STOP: issuer '$ISSUER', kid '$OLD_KID'"
    ```
    The cutover keeps this issuer, and so every issued token. On authproto it is
    `http://identity.identity.localhost:28280`. The gateway routes `<route-host>.<tenant>.localhost`
    by tenant name, so this host reaches tenant `identity` only. Step 10 moves it with an
    administrator **gateway route alias** (platform #218/#219, `@di-framework/platform` 6.0.13):
    `"routeAliases": {"identity.identity": "identity.$NEW"}` in the platform config. The gateway
    then sends `Host: identity.identity.localhost:28280` to `di-http` in `di-runtime-$NEW` with
    `Host: identity`, and keeps the original name in `X-Forwarded-Host`. Removing the alias with
    another `up` is the route rollback. Tenants can neither see nor change aliases.

    STOP if `$ISSUER` is not exactly `http://identity.identity.localhost:$HTTP_PORT`. The alias
    rewrites only the tenant label, so the route host must stay `identity`, which the new guest
    serves too. Also STOP if the stack already has a `routeAliases` entry (P2's builder checks
    this). If neither holds, the alternatives are a new issuer (it invalidates every token and
    relying-party configuration, so it is not "migrate everything" and needs a new sign-off), or
    deploying into tenant `identity` after `directory` is retired (the guard refuses this by
    design).
P2. **Upgrade the platform: declare `$NEW`, switch every tenant host to the exclusive image, and
    allowlist the plain-HTTP registry.** One `up` does all three, before the freeze, while the old
    guest still serves.

    1. **Instance settings.** `up` rebuilds the stack config from its flags as well as from the
       file. Print what the instance was created with:
       `jq '{httpPort, nodePort, namespace, release, chartVersion, kubesoloVersion, runMode}' "$STATE/state.json"`.
       Every value must equal what `up_platform` passes: `httpPort` the `$HTTP_PORT` above, and
       the others the defaults `"$KUBE" up --help` lists. If one differs, add the matching flag
       (`--node-port`, `--namespace`, `--release`, `--chart-version`, `--kubesolo-version`,
       `--run-mode`) to `up_platform`. If you cannot tell why it differs, STOP.
    2. **The exclusive host image.** The pglite guest needs the exclusive-instance wash build,
       which also carries wash patch 0002 (`--insecure-registry`, which `insecureRegistries`
       needs). The kube CLI's default tenant host image is not the exclusive build (and before
       v0.0.5 it predated 0002, which the platform refuses together with `insecureRegistries`),
       so `tenantHostImage` must name the exclusive build explicitly. Pin it by digest, and check
       the digest, since a failed fetch leaves `@` or `@null`:
       ```sh
       HOST_DIGEST="$(oras manifest fetch --descriptor ghcr.io/di-framework/wash:2.8.0-wasi-tls-exclusive | jq -r .digest)"
       printf '%s\n' "$HOST_DIGEST" | grep -Eqx 'sha256:[0-9a-f]{64}' && echo 'digest ok' || echo "STOP: no digest: $HOST_DIGEST"
       HOST_IMAGE="ghcr.io/di-framework/wash:2.8.0-wasi-tls-exclusive@$HOST_DIGEST"
       ```
       The digest is the multi-arch index's, which is what a pod's `imageID` reports when the
       image is pulled by this reference (so it is also the value for
       `IDENTITY_EXCLUSIVE_HOST_DIGEST`, below). The builder (item 3) refuses an image without a
       valid digest too.
       Switching the image restarts **every** tenant host (`acme` and the old guest's
       `identity` too). The user accepted that blip. Item 6 proves the old guest on the new
       image before the freeze, so a rollback restores it onto an image it has run on.
    3. **Build the two config files** from the instance's stack config, carrying every key `up`
       would otherwise drop, and adding tenant `$NEW` (with `coreInstances: 300`, as tenant
       `identity` declares; nothing here was load-tested with fewer), user `$PUSHER` (a member of
       `$NEW` only, for the push in step 8), the host image and the plain-HTTP registry. `up`
       rewrites the whole stack config from the file and its flags and drops every other key, so
       the builder refuses a stack with any key outside those two sets, whether set by hand
       under `di-framework-kube:` or in another namespace:
       ```sh
       umask 077
       STATE="$STATE" NEW="$NEW" PUSHER="$PUSHER" HOST_IMAGE="$HOST_IMAGE" OUT="$OUT" bun -e '
       const { STATE, NEW, PUSHER, HOST_IMAGE, OUT } = process.env;
       const stop = (why) => { console.error(`STOP: ${why}`); process.exit(1); };
       // What `up` writes to the stack (kube internal/platform/pulumi.go): the --platform-config allowlist,
       // and the keys it derives from its flags and the instance. It drops every other key.
       const KEYS = ["tenants", "users", "tenantHostImage", "tenantHostImagePullPolicy", "networkPolicyEngine",
         "storageRoot", "egressAllowedDestinations", "routeAliases", "tenantAuth", "insecureRegistries",
         "backingServiceClasses", "seedDefaultBackingClasses"];
       const FLAG_KEYS = ["kubeconfig", "context", "namespace", "release", "chart", "chartVersion", "httpNodePort",
         "timeoutSeconds", "insecureRegistry", "values", "kubernetesEndpoint", "httpEndpoint"];
       const TEXT = new Set(["tenantHostImage", "tenantHostImagePullPolicy", "networkPolicyEngine", "storageRoot"]);
       if (!/^[^@\s]+@sha256:[0-9a-f]{64}$/.test(HOST_IMAGE ?? "")) stop(`HOST_IMAGE is not pinned by a sha256 digest: ${HOST_IMAGE}`);
       const stack = Bun.YAML.parse(await Bun.file(`${STATE}/platform/Pulumi.dev.yaml`).text()).config ?? {};
       const PREFIX = "di-framework-kube:";
       const dropped = Object.keys(stack).filter((k) => !k.startsWith(PREFIX) || ![...KEYS, ...FLAG_KEYS].includes(k.slice(PREFIX.length)));
       if (dropped.length > 0) stop(`up would delete these stack keys: ${dropped.join(", ")}`);
       const config = {};
       for (const key of KEYS) {
         let value = stack[PREFIX + key];
         if (value === undefined) continue;
         if (value !== null && typeof value === "object" && "secure" in value) stop(`${key} is a Pulumi secret`);
         // A key set by hand with `pulumi config set` (tenantAuth on authproto) is stored as JSON text.
         if (typeof value === "string" && !TEXT.has(key)) value = JSON.parse(value);
         config[key] = value;
       }
       if (Object.keys(config.routeAliases ?? {}).length > 0) stop("the stack already has routeAliases");
       delete config.routeAliases;
       if (!config.tenantAuth?.registry) stop(`tenantAuth.registry is not set, so tenant ${NEW} gets no registry`);
       // up fills these two for a managed instance when the file lacks them; name them so the file is complete.
       config.networkPolicyEngine ??= "kube-router";
       config.storageRoot ??= "/var/lib/kubesolo";
       config.tenants ??= [];
       config.users ??= [];
       if (config.tenants.some((t) => t.name === NEW)) stop(`tenant ${NEW} is already declared`);
       if (config.users.some((u) => u.name === PUSHER)) stop(`user ${PUSHER} is already declared; pick a new name`);
       config.tenants.push({ name: NEW, runtime: { coreInstances: 300 } });   // as tenant identity
       config.users.push({ name: PUSHER, memberships: [{ tenant: NEW, role: "developer" }] });
       config.tenantHostImage = HOST_IMAGE;
       config.insecureRegistries = [...new Set([...(config.insecureRegistries ?? []),
         "examples-registry.wasmcloud.svc.cluster.local:5000"])];
       const write = (name, value) => Bun.write(`${OUT}/${name}`, JSON.stringify(value, null, 2) + "\n");
       await write("platform.json", config);
       await write("platform-alias.json", { ...config, routeAliases: { "identity.identity": `identity.${NEW}` } });
       // What up derives from its flags and the instance: compare with item 1 and `up --help`.
       for (const key of FLAG_KEYS) console.log(`${key}: ${JSON.stringify(stack[PREFIX + key])}`);
       '
       ```
       Any `STOP:` line: stop. For a key `up` would delete, find out who set it and why before
       going on; never delete it by hand to get past the check. The builder prints every
       flag-derived key, which must agree with item 1 and with what `up_platform` passes:
       `kubeconfig` is `$KC`, `context` is empty or `$CTX`, `kubernetesEndpoint` the API server
       in `$KC`, `httpEndpoint` `http://127.0.0.1:$HTTP_PORT`, `insecureRegistry` `true` (it
       becomes `true` in any case), `timeoutSeconds` whatever the last `up` used (it becomes
       1200), and `values` `{}` (anything else means the instance was brought up with `--values`
       files, which `up_platform` must then pass with `-f`). Review both files by eye: they hold no secret (`tenantAuth` names its OAuth Secret,
       it does not contain it), but they are the whole platform declaration from now on.

       Two rules shape these files. **Tenant `$NEW` is created by declaring it here, never with
       `kubectl apply`.** The Pulumi provider does not adopt existing objects, so declaring a
       Tenant that `kubectl` already created fails the `up` with "already exists" (and the alias
       target must be a declared tenant anyway). **The push user is declared here too**, with a
       membership in `$NEW` only, rather than by editing User objects with `kubectl`.
    4. **Every plain-HTTP registry is allowlisted.** authproto's old identity guest and
       `acme/greeter-staging` pull from plain-HTTP
       `examples-registry.wasmcloud.svc.cluster.local:5000`. Since 6.0.11 tenant hosts pull over
       plain HTTP only from the `insecureRegistries` entries, so without that entry their hosts
       cannot pull again after the upgrade restarts them, and the rollback target is lost. List
       the registry host of every component every WorkloadDeployment references and compare:
       ```sh
       kubectl --kubeconfig "$KC" get workloaddeployments -A -o json > "$OUT/workloads.json" \
         && jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)" as $w
             | .spec | [.. | objects | select(has("image")) | .image | strings] | unique[] | "\(split("/")[0]) \($w)"' \
             "$OUT/workloads.json" | LC_ALL=C sort -u > "$OUT/workload-registries" \
         && grep -q ' di-tenant-identity/identity$' "$OUT/workload-registries" \
         || echo 'STOP: could not list the workloads (the old guest is not among them)'
       cat "$OUT/workload-registries"
       jq -r --rawfile seen "$OUT/workload-registries" '(.insecureRegistries // []) as $plain
           | $seen | split("\n")[] | select(length > 0) | split(" ") as [$host, $workload]
           | select(($plain | index([$host])) == null)
           | select($host | test("^(ghcr\\.io|tenant-registry\\.di-runtime-[a-z0-9-]+\\.svc)$") | not)
           | "\($host) \($workload)"' "$OUT/platform.json"   # must print nothing
       ```
       The second command prints every registry that is neither allowlisted nor known to be TLS
       (GHCR, and the platform's own `tenant-registry.di-runtime-<tenant>.svc` pull listener).
       A reference without a registry host (`library/foo`, implicitly Docker Hub) is printed too,
       under its first path segment, so that it gets a look. For each line, find out how that
       registry is served. A plain-HTTP one goes into
       `insecureRegistries`, spelled exactly as the reference spells it (wash matches it
       case-sensitively, with no default port), after which you rebuild the files (item 3,
       adding it to the list there). A TLS one needs nothing. If you cannot tell, STOP.
    5. **Preview on a copy** of the project and its state, never on the instance itself. The
       function rebuilds the copy's stack config the way `up` does: the file's keys, plus the
       flag-derived keys (as the stack holds them, with `timeoutSeconds` and `insecureRegistry`
       as `up_platform` sets them), and nothing else:
       ```sh
       # preview_platform <config file> <report file>: `pulumi preview` of what `up_platform <config file>`
       # would apply, on a copy of the instance's project and state.
       preview_platform() {
         PREVIEW="$OUT/preview"      # holds the stack's state and passphrase: same care as $OUT
         rm -rf "$PREVIEW" && cp -Rp "$STATE/platform" "$PREVIEW" || return 1
         PREVIEW="$PREVIEW" CONFIG="$1" PACKAGE="$PLATFORM_PACKAGE" bun -e '
         const { PREVIEW, CONFIG, PACKAGE } = process.env;
         // Rebuild the stack config as `up` does: the file, plus the keys up derives from its flags
         // (the stack holds what the instance was brought up with; P2 item 1 checks they still match).
         const FLAG_KEYS = ["kubeconfig", "context", "namespace", "release", "chart", "chartVersion", "httpNodePort",
           "timeoutSeconds", "insecureRegistry", "values", "kubernetesEndpoint", "httpEndpoint"];
         const read = async (name) => Bun.YAML.parse(await Bun.file(`${PREVIEW}/${name}`).text());
         const project = await read("Pulumi.yaml");
         project.backend = { url: Bun.pathToFileURL(`${PREVIEW}/state`).href };   // the copy, not the instance
         const pkg = await read("package.json");
         pkg.dependencies["@di-framework/platform"] = PACKAGE.replace(/^@di-framework\/platform@/, "");
         const stack = await read("Pulumi.dev.yaml");
         const config = {};
         for (const key of FLAG_KEYS)
           if (stack.config[`di-framework-kube:${key}`] !== undefined) config[`di-framework-kube:${key}`] = stack.config[`di-framework-kube:${key}`];
         config["di-framework-kube:timeoutSeconds"] = 1200;      // --timeout 20m
         config["di-framework-kube:insecureRegistry"] = true;    // --allow-insecure-registries
         for (const [key, value] of Object.entries(JSON.parse(await Bun.file(CONFIG).text())))
           config[`di-framework-kube:${key}`] = value;
         stack.config = config;
         for (const [name, value] of [["Pulumi.yaml", project], ["package.json", pkg], ["Pulumi.dev.yaml", stack]])
           await Bun.write(`${PREVIEW}/${name}`, JSON.stringify(value, null, 2) + "\n");
         ' && (cd "$PREVIEW" && npm install --no-audit --no-fund >/dev/null \
           && PULUMI_CONFIG_PASSPHRASE_FILE="$PREVIEW/.passphrase" PULUMI_BACKEND_URL="$(jq -r .backend.url Pulumi.yaml)" \
             pulumi preview --stack dev --diff --non-interactive) > "$2" 2>&1
         status=$?   # the copy goes even when a step failed
         rm -rf "$PREVIEW"
         return "$status"
       }
       preview_platform "$OUT/platform.json" "$OUT/preview.txt" || echo 'STOP: the preview failed'
       ```
       The only changes allowed are:
       - **create:** Namespaces `di-tenant-$NEW` and `di-runtime-$NEW`, Tenant `$NEW`, and
         User `$PUSHER`;
       - **update:** the runtime operator's Helm release, whose `hostNamespaces` gains
         `di-runtime-$NEW`;
       - **replace:** the gateway's ConfigMap;
       - **rolls (pod template updates):** `di-platform-gateway`, `di-platform-controller` and the
         runtime operator. The controller rolls once on this first upgrade only, because
         `tenantAuth`'s stored form changes from JSON text to an object.

       Anything else is a STOP, in particular any delete, a change to Tenant `identity` or
       `acme`, or to an existing User. The tenant hosts' new image does not show here: the
       platform controller applies it to the host Deployments after the `up`.
    6. **Upgrade**, after saving the instance's project as it is now:
       ```sh
       cp -Rp "$STATE/platform" "$OUT/platform-before-upgrade"   # holds the stack's passphrase
       up_platform "$OUT/platform.json"
       ```
       If it fails, follow the rules above: `up_platform "$OUT/platform.json"` again once the
       cause is fixed, never a plain `up`. Then wait in this order. The image switch restarts the
       old guest's host, and the tenant-auth pods find the issuer (the old guest, see "The frozen
       issuer" below) only once it serves again, so the old guest comes first:
       ```sh
       # a. every tenant host rolled onto the new image
       for t in $(jq -r '.tenants[].name' "$OUT/platform.json"); do
         kubectl --kubeconfig "$KC" -n "di-runtime-$t" rollout status "deploy/hostgroup-tenant-$t" --timeout=600s \
           || echo "STOP: hostgroup-tenant-$t did not roll out"
         images="$(kubectl --kubeconfig "$KC" -n "di-runtime-$t" get deploy "hostgroup-tenant-$t" -o jsonpath='{.spec.template.spec.containers[*].image}')"
         case " $images " in *" $HOST_IMAGE "*) echo "host $t: ok" ;; *) echo "STOP: host $t runs '$images'" ;; esac
       done
       # b. the old guest serves again, with the same issuer and key (the host pulls the component first)
       served=
       for i in $(seq 1 60); do   # up to 10 minutes
         served="$(curl -s -m 10 -H 'Host: identity.identity.localhost' "$GW/.well-known/openid-configuration" | jq -r .issuer 2>/dev/null)"
         [ "$served" = "$ISSUER" ] && break
         sleep 10
       done
       kid="$(curl -s -m 10 -H 'Host: identity.identity.localhost' "$GW/oauth2/jwks" | jq -r '.keys[].kid')"
       [ -n "$ISSUER" ] && [ "$served" = "$ISSUER" ] && [ -n "$OLD_KID" ] && [ "$kid" = "$OLD_KID" ] \
         && echo 'old guest: ok' || echo "STOP: old guest issuer '$served', kid '$kid'"
       # the old guest's and acme's workloads Ready again
       for w in di-tenant-identity/identity di-tenant-acme/greeter-staging; do
         ready="$(kubectl --kubeconfig "$KC" -n "${w%/*}" get workloaddeployment "${w#*/}" -o 'jsonpath={.status.conditions[?(@.type=="Ready")].status}')"
         [ "$ready" = True ] && echo "$w: Ready" || echo "STOP: $w Ready='$ready'"
       done
       # c. tenant $NEW's auth pair and registry
       kubectl --kubeconfig "$KC" wait "tenants.platform.di-framework.dev/$NEW" --for=condition=TenantAuthReady --timeout=600s
       registry=
       for i in $(seq 1 120); do   # up to 10 minutes; `kubectl wait` has exited early on WorkloadDeployments
         registry="$(kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" get workloaddeployment di-tenant-registry -o 'jsonpath={.status.conditions[?(@.type=="Ready")].status}')"
         [ "$registry" = True ] && break
         sleep 5
       done
       [ "$registry" = True ] && echo 'tenant registry Ready' || echo 'tenant registry NOT Ready: STOP'
       ```
       Each check prints `ok`/`Ready` or a `STOP` line; a missing or empty answer is a `STOP`,
       never a pass. If anything fails, STOP before the freeze: the old guest
       is still the only guest. Fix the file and `up_platform` again; the project copy in
       `$OUT/platform-before-upgrade` records the previous stack config.
    7. **Tenant-auth gate.** Every Tenant must be `TenantAuthReady` and every tenant-auth
       Deployment (`tenant-controller` and `tenant-console` in each `di-runtime-*`) Ready. A pod
       the upgrade rolled while the old guest was down retries discovery for about 4 minutes,
       then crash-loops with a growing back-off, so give it time after item 6b:
       ```sh
       for i in $(seq 1 40); do   # up to 10 minutes after the old guest serves
         tenant_auth_state > "$OUT/tenant-auth.now"
         [ -s "$OUT/tenant-auth.now" ] \
           && ! grep -Ev 'TenantAuthReady=True$| ready=(1/1|/0)$| ready=true restarts=[0-9]+$' "$OUT/tenant-auth.now" \
           && break
         sleep 15
       done
       cat "$OUT/tenant-auth.now"
       ```
       The `grep` prints what is not ready yet (an `ERROR` line included); the loop ends only
       when the snapshot is non-empty and it prints nothing. If a pod is
       still in `CrashLoopBackOff` after that (it exhausted its discovery budget while the old
       guest was down), restart it once, now that the guest serves:
       `kubectl --kubeconfig "$KC" -n di-runtime-<tenant> rollout restart deploy/<tenant-controller|tenant-console>`,
       and run the loop again. If it still fails, STOP. Once the `grep` prints nothing, record
       the baseline that the frozen window is checked against:
       `cp "$OUT/tenant-auth.now" "$OUT/tenant-auth.baseline"`.
    8. **Preview the switch** against the upgraded stack, still before the freeze, so step 10 is
       known to change only the gateway:
       ```sh
       preview_platform "$OUT/platform-alias.json" "$OUT/preview-alias.txt" || echo 'STOP: the preview failed'
       ```
       The only changes allowed: the gateway's ConfigMap (replace) and `di-platform-gateway`
       (its config hash annotation, so it rolls). In particular nothing may touch
       `di-platform-controller` or any tenant-auth Deployment: they could not start again during
       the freeze. Anything else is a STOP.

    `deploy.sh` (through `runtime-secrets.ts guard`) refuses the cutover unless `$NEW`'s host
    runs the exclusive build, and that check is by **name only**: some image in the Deployment's
    pod template must match `(^|/)wash:<tag>` with `exclusive` in the tag
    (`/(^|\/)wash:[^\s@]*exclusive/`), with or without an `@sha256:` suffix. It does not compare
    a digest, so a rebuilt or retagged image under that name passes. To pin the digest too, set
    `IDENTITY_EXCLUSIVE_HOST_DIGEST=sha256:<64 hex>` for step 8: the guard then also requires
    every running `hostgroup-tenant-$NEW-*` pod to report that digest in
    `.status.containerStatuses[*].imageID` (what the node actually pulled), and refuses a
    malformed value or no running host pod. Read the digest from a host pod you trust:
    `kubectl --kubeconfig "$KC" -n "di-runtime-$NEW" get pods -o jsonpath='{.items[*].status.containerStatuses[*].imageID}'`.

    **The frozen issuer.** On authproto `tenantAuth.issuer` is `$ISSUER` itself
    (`http://identity.identity.localhost:28280`), reached through the platform gateway
    (`issuerUpstream: di-platform-gateway.wasmcloud.svc.cluster.local:80`), so the alias moves it
    too. Every tenant controller and console calls `discover(issuer)` when it starts: 20
    attempts with a growing back-off, about 4 minutes (longer if fetches hang), then it throws,
    exits, and stays in `CrashLoopBackOff` until discovery answers. Running pods keep their
    metadata, and API keys are checked against their Secrets only, so the push in step 8 does
    not need the issuer. But from the freeze (step 2) until the switch (step 10), and from
    rollback step 1 until rollback step 3, **no tenant-auth pod can start**. `$NEW`'s
    `tenant-controller` is also the registry front step 8 pushes through. Therefore:

    - Right before step 2, before step 8 and before step 10, run
      `tenant_auth_state | diff "$OUT/tenant-auth.baseline" -`. It must print nothing: a changed
      line means a pod is not Ready, restarted, or was replaced (a new pod name).
    - **If `$NEW`'s controller, or any tenant-auth pod, is not Ready or restarts between the
      freeze and the switch, roll back at once** (Rollback below). Do not wait for it: it cannot
      start until the issuer answers again, and the issuer stays frozen until step 10 or the
      rollback. After rollback step 3 the old guest serves; give the pod its retry time, restart
      it once if it is still crash-looping, run item 7 again, and start over as described under
      "Roll forward after a rollback".
    - Run no `up` between step 2 and step 10 but step 10's, which item 8 showed rolls only the
      gateway, and restart nothing in the platform or tenant runtime namespaces.

##### Cutover

1. **Build the guest** (the import uses the provider this build composes):
   `(cd apps/guest && di-framework platform build)`. It must log
   `Composing the PGlite encryption layer into the provider`. With an older plugin installed,
   prefix it with `DI_FRAMEWORK_EXTENSIONS_DIR=<dir with cli-plugin-platform 6.2.0>` (also for
   step 8). Prepare step 8's items 1 and 2 (the push key and the `oras` wrapper) now too: only
   steps 2 to 10 run with the issuer frozen, and nothing that can run before belongs there.
2. **Freeze writes on the Postgres guest.** First the tenant-auth check:
   `tenant_auth_state | diff "$OUT/tenant-auth.baseline" -` must print nothing (P2, "The frozen
   issuer"); otherwise STOP and run P2 item 7 again. Then record the old guest's replicas (a
   number, kept in `$OUT/old-replicas` for the rollback) and stop it:
   ```sh
   OLD_REPLICAS="$(kubectl --kubeconfig "$KC" -n di-tenant-identity get workloaddeployment identity -o jsonpath='{.spec.replicas}')"
   case "$OLD_REPLICAS" in
     ''|*[!0-9]*) echo "STOP: could not read the old guest's replicas: '$OLD_REPLICAS'" ;;
     *) echo "$OLD_REPLICAS" > "$OUT/old-replicas" && echo "recorded replicas: $OLD_REPLICAS" \
          && kubectl --kubeconfig "$KC" -n di-tenant-identity patch workloaddeployment identity --type merge -p '{"spec":{"replicas":0}}' ;;
   esac
   ```
   Then the freeze must hold on all three counts: the workload at `replicas: 0`,
   `Host: identity.identity.localhost` no longer answering `/health` with 200, and nothing else
   connected to `directory`. The connection count reaches `0`, but not at once: after
   `replicas: 0` the tenant host (`hostgroup-tenant-identity`) keeps the old guest's pooled
   connection open, idle, until its pool drops it. On pgprove that took 3.5 to 4.5 minutes, so
   wait for it, with a timeout. `freeze_check` prints `frozen: ok` only when every answer is
   there and right; a failed `kubectl`, `curl` or `psql`, or an empty answer, is a `STOP`:
   ```sh
   others='SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()'
   freeze_check() {
     r="$(kubectl --kubeconfig "$KC" -n di-tenant-identity get workloaddeployment identity -o jsonpath='{.spec.replicas}')" \
       || { echo 'STOP: cannot read the old workload'; return 1; }
     [ "$r" = 0 ] || { echo "STOP: the old workload has replicas='$r'"; return 1; }
     h="$(curl -s -o /dev/null -m 10 -w '%{http_code}' -H 'Host: identity.identity.localhost' "$GW/health")"
     [ "$h" != 200 ] || { echo 'STOP: the old guest still answers /health'; return 1; }
     n="$(psql_directory "$others")" || { echo 'STOP: cannot count the connections to directory'; return 1; }
     [ "$n" = 0 ] || { echo "STOP: $n other connections to directory"; return 1; }
     echo 'frozen: ok'
   }
   deadline=$(( $(date +%s) + 600 ))
   until freeze_check >/dev/null; do
     if [ "$(date +%s)" -ge "$deadline" ]; then echo 'not frozen after 10 minutes'; break; fi
     sleep 15
   done
   freeze_check   # must print 'frozen: ok'; anything else is a STOP: do not export
   ```
   Optional, instead of waiting: end only the old guest's **idle** connections. They come from
   the tenant host pods' IPs, so list those first and look at what matches:
   ```sh
   HOST_IPS="$(kubectl --kubeconfig "$KC" -n di-runtime-identity get pods -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.podIP}{"\n"}{end}' \
     | awk '$1 ~ /^hostgroup-tenant-identity-/ { printf "%s%s", sep, $2; sep = "," }')"
   old_guest="datname = current_database() AND pid <> pg_backend_pid() AND state = 'idle' AND client_addr = ANY('{$HOST_IPS}'::inet[])"
   psql_directory "SELECT pid, usename, application_name, client_addr, now() - state_change AS idle_for FROM pg_stat_activity WHERE $old_guest"
   psql_directory "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE $old_guest"
   ```
   Only with `replicas: 0` and `/health` not answering: the filter keeps connections that are
   running a statement or in a transaction, and connections from any other address. (An empty
   `HOST_IPS` gives `'{}'`, which matches nothing, so it ends nothing.) Then run `freeze_check`
   again. If it does not reach 0, find the client
   (`SELECT usename, application_name, client_addr, state FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()`)
   and stop it before step 3. Anything written after step 3 is lost.
3. **Export** (read-only on `directory`):
   `bun deploy/cutover/export.ts --kubeconfig "$KC" --context "$CTX" --namespace di-runtime-identity --service directory --out "$OUT/export"`.
   Expect `source schema V15`. If it refuses unknown runtime rows, review them (P0); do not edit
   the tool's mapping. A failed export leaves no `$OUT/export` behind. Then run `freeze_check`
   again: it must still print `frozen: ok` (a controller may have restored the replicas).
   Otherwise stop the writer again, delete the old export
   first (`rm -rf "$OUT/export"`: it holds secrets, and `export.ts` refuses a non-empty `--out`),
   and export again.
4. **Key:** `bun deploy/guest/runtime-secrets.ts pglite-key --values "$OUT/export/values.json"`.
   Record the KCV it prints, and back the key (the whole `values.json`) up apart from any volume
   backup. Optional: `runtime-secrets.ts column-keys --values "$OUT/export/values.json" --enable`
   to opt in to column encryption (new writes only).
5. **Import:**
   `bun deploy/cutover/import.ts --export "$OUT/export" --values "$OUT/export/values.json" --out "$OUT/data"`.
   Every table must read `n/n rows`, `rows V16 would delete: 0`, and the disk line
   `0 without a header; .di-encfs KCV matches: true; plaintext needles found: 0`. A failed import
   removes `$OUT/data` again, so it can simply be re-run.
6. **Rehearse:**
   `bun deploy/cutover/rehearse.ts --data "$OUT/data" --values "$OUT/export/values.json" --export "$OUT/export"`.
   Every line must be `ok` or `note`, including `bootstrap not reconciled` and
   `bootstrap organization`; any `FAIL` exits 1. The owner and viewer sign in with the bootstrap
   passwords in `values.json`, which are only what bootstrap first set. A user who changed it
   since reads
   `note <who> sign-in: HTTP 303, signed in: false: password changed since bootstrap (expected if the user changed it) ...`,
   and only when `<who> password hash carried` is `ok` (the stored hash's SHA-256 equals the
   export's; neither is printed). A rejected sign-in whose hash was not carried, without
   `--export`, or any other answer (a 5xx) is a `FAIL`. The owner gets the same rule: the three
   bootstrap clients already prove that carried Argon2id hashes verify, and the owner is the
   account most likely to have changed its bootstrap password. `<who> password hash format`
   closes the rest: the user's stored hash must have the bootstrap clients' head (algorithm,
   version and parameters, `$argon2id$v=19$m=…,t=…,p=…`; never the salt or hash, and only the
   algorithm name is printed). The same head is `ok`, the same algorithm and version with other
   parameters a `note`, anything else a `FAIL`, so a `note` for a changed password cannot hide
   a hash the new guest cannot verify.
7. **Install** (dry run, then for real), before the guest's WorkloadDeployment exists:
   `bun deploy/cutover/install.ts --data "$OUT/data" --values "$OUT/export/values.json" --kubeconfig "$KC" --context "$CTX" --tenant "$NEW"`.
   The dry run starts a read-only helper pod (root with DAC_READ_SEARCH only; only the tenant's
   own `<storageRoot>/di-tenants/<uid>` mounted, read-only and as type `Directory`, which kubelet
   never creates; deleted afterwards), lists the target and refuses a non-empty one as `--yes`
   would; it must print `target is empty or absent`, or `target is absent: ... does not exist
   yet` when the tenant has no directory on the node yet (kubelet then refuses the mount, and the
   dry run reads that event instead of waiting). Check the target path and
   counts, and repeat with `--yes`. Expect
   `installed: N/N files match, 0 missing, 0 changed, 0 extra; 0 not owned by 65532`.
   Record the target path it prints (`TARGET=...`) for step 12.
8. **Deploy into `$NEW`'s own registry.** The guest is pushed to tenant `$NEW`'s registry
   (`tenantAuth.registry`, WorkloadDeployment `di-tenant-registry`, Ready since P2) as user
   `$PUSHER`, and `$NEW`'s host pulls it from the in-cluster pull listener over TLS. Items 1
   and 2 need neither the export nor the freeze: do them before step 2, to keep the frozen
   window short. First, right before the push, the tenant-auth check
   (`tenant_auth_state | diff "$OUT/tenant-auth.baseline" -` prints nothing; otherwise roll
   back, see "The frozen issuer" in P2).
   1. **An API key for `$PUSHER`.** Console sign-in needs the issuer, which is frozen from
      step 2, so mint the key with the admin kubeconfig the way the tenant controller stores
      keys: a Secret `di-apikey-<id>` in `di-runtime-$NEW`, created with its labels (tenant,
      user, `api-key`), holding only the SHA-256 of the secret part. The full key goes into a
      mode 0600 Docker config and is never printed or passed as an argument. The timestamps
      come from Bun, so this works with BSD and GNU `date` alike, and an empty one stops:
      ```sh
      REG_PORT=28790                  # any free loopback port
      # mint_push_key: a key for $PUSHER in tenant $NEW, as the tenant controller stores keys (keys.ts).
      mint_push_key() (
        umask 077
        key_id="$(openssl rand -hex 8)"
        key_secret="$(openssl rand 32 | base64 | tr '+/' '-_' | tr -d '=\n')"
        times="$(bun -e 'const now = Date.now(); console.log(new Date(now).toISOString(), new Date(now + 86_400_000).toISOString())')"
        created_at="${times% *}"
        expires_at="${times#* }"
        for t in "$created_at" "$expires_at"; do
          printf '%s\n' "$t" | grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z' \
            || { echo "STOP: no timestamp: '$t'"; return 1; }
        done
        [ "${#key_secret}" = 43 ] || { echo 'STOP: key generation failed'; return 1; }
        kubectl --kubeconfig "$KC" -n "di-runtime-$NEW" create secret generic "di-apikey-$key_id" --dry-run=client -o json \
            --from-literal=hash="$(printf %s "$key_secret" | shasum -a 256 | awk '{print $1}')" \
            --from-literal=name=identity-cutover --from-literal=createdAt="$created_at" --from-literal=expiresAt="$expires_at" \
          | jq --arg tenant "$NEW" --arg user "$PUSHER" '.metadata.labels = {"platform.di-framework.dev/api-key": "true",
              "platform.di-framework.dev/tenant": $tenant, "platform.di-framework.dev/user": $user}' \
          | kubectl --kubeconfig "$KC" -n "di-runtime-$NEW" create -f - || return 1
        mkdir -m 700 -p "$OUT/docker"
        printf '{"auths":{"127.0.0.1:%s":{"auth":"%s"}}}\n' "$REG_PORT" \
          "$(printf '%s:dik_%s_%s' "$PUSHER" "$key_id" "$key_secret" | base64 | tr -d '\n')" > "$OUT/docker/config.json"
      )
      # cleanup_push: the port-forward, every key of $PUSHER (found by its labels, so it also works from a
      # new shell), and the local credentials.
      cleanup_push() {
        [ -z "${PF:-}" ] || kill "$PF" 2>/dev/null
        kubectl --kubeconfig "$KC" -n "di-runtime-$NEW" delete secret \
          -l "platform.di-framework.dev/api-key=true,platform.di-framework.dev/user=$PUSHER"
        rm -rf "$OUT/docker" "$OUT/bin"
      }
      mint_push_key || echo 'STOP: no key'
      ```
      The key expires a day after it is minted (`expiresAt`). `cleanup_push` (item 4) deletes
      it.
   2. **The `oras` wrapper.** Port 8790 of `tenant-controller` is TLS only (it answers plain
      HTTP with `400`), with a certificate for its in-cluster and public names, not for
      `127.0.0.1`. The plugin has no CA or TLS-skip option for its `oras` calls, so a wrapper on
      `PATH` adds `--insecure`, only to calls that name `127.0.0.1:$REG_PORT`. Every other call,
      GHCR fetches during the build included, keeps TLS verification:
      ```sh
      mkdir -m 700 -p "$OUT/bin"
      ORAS="$(command -v oras)"
      cat > "$OUT/bin/oras" <<EOF
      #!/bin/sh
      # --insecure only for calls that name the loopback port-forward; GHCR and the rest keep TLS.
      for arg in "\$@"; do
        case "\$arg" in *127.0.0.1:$REG_PORT*) exec "$ORAS" "\$@" --insecure ;; esac
      done
      exec "$ORAS" "\$@"
      EOF
      chmod 700 "$OUT/bin/oras"
      ```
   3. **Deploy**, through a port-forward to the registry front, overriding `deploy.sh`'s
      registry defaults with the **schemeless** push URL (an `http://` URL, `deploy.sh`'s
      default form, makes the push plain HTTP, which the front refuses) and the tenant's pull
      reference:
      ```sh
      kubectl --kubeconfig "$KC" -n "di-runtime-$NEW" port-forward svc/tenant-controller "$REG_PORT:8790" &
      PF=$!
      PATH="$OUT/bin:$PATH" DOCKER_CONFIG="$OUT/docker" \
        IDENTITY_REGISTRY_PUSH="127.0.0.1:$REG_PORT/identity" \
        IDENTITY_REGISTRY_PULL="tenant-registry.di-runtime-$NEW.svc/identity" \
        IDENTITY_AUTHPROTO_CUTOVER="authproto/$NEW" \
        deploy/guest/deploy.sh authproto "$NEW" "$OUT/export/values.json"
      ```
      (with `IDENTITY_EXCLUSIVE_HOST_DIGEST=sha256:...` too, to pin the host image; see P2).
      It logs `authproto cutover confirmed for the new tenant`, builds, deploys, waits for Ready
      and writes `identity-control`. If the deploy fails before the WorkloadDeployment exists,
      `deploy.sh` says so and prints the deploy command to re-run (add the variables above
      again); `runtime-secrets.ts apply` is the recovery only once the WorkloadDeployment
      exists, and `deploy.sh` prints it only then. The workload must reference the tenant
      registry:
      ```sh
      image="$(kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" get workloaddeployment identity -o jsonpath='{.spec.template.spec.components[*].image}')"
      case "$image" in "tenant-registry.di-runtime-$NEW.svc/identity"[:@]*) echo "image ok: $image" ;; *) echo "STOP: image '$image'" ;; esac
      ```
   4. **Clean up the push credentials, on every path:** `cleanup_push` after a successful
      deploy, after a failed one you will not retry at once, and before any rollback. From a
      new shell, define `KC`, `NEW`, `PUSHER`, `OUT` and the function again: it finds the keys
      by their labels
      (`kubectl --kubeconfig "$KC" -n "di-runtime-$NEW" get secret -l "platform.di-framework.dev/api-key=true,platform.di-framework.dev/user=$PUSHER"`),
      and `pkill -f "port-forward svc/tenant-controller $REG_PORT:8790"` ends a port-forward the
      old shell left behind. A later redeploy of `$NEW` mints a new key the same way, or
      through the console once the issuer serves from `$NEW`.

   **Why not authproto's `examples-registry`.** Pushing to
   `examples-registry.wasmcloud.svc.cluster.local:5000` (`deploy.sh`'s defaults, with
   `kubectl -n wasmcloud port-forward svc/examples-registry 25001:5000`) is simpler: no user,
   key or wrapper, and the pull reference is already in `insecureRegistries`. It is not
   recommended. That registry is plain HTTP and takes unauthenticated pushes, so anything that
   reaches it in the cluster could replace the identity provider's component. It would also
   tie the new guest to an allowlist entry that exists only for the old guest and `acme`, and
   it is not the path proven on pgprove. Use it only as a recorded decision if `$NEW`'s
   registry cannot be made Ready.
9. **Verify on the tenant host** (`Host: identity.$NEW.localhost`):
   `bun apps/guest/scripts/live-check.ts --values "$OUT/export/values.json" --url "$GW" --host identity.$NEW.localhost --read-only`.
   With `--read-only` and no `--slug` it reads the bootstrap organization, which bootstrap
   always creates (`BootstrapReconciler.ensureOrganization`): the values'
   `AUTH_BOOTSTRAP_ORGANIZATION_SLUG`, else the compiled-in `platform`
   (`apps/guest/src/bindings.ts`). It exits 1 unless `/ready` and that read answer 200; its
   `login` field signs in the bootstrap owner with the bootstrap password, which fails if the
   owner changed it (see step 6) and does not change the exit code. Then compare the key ids
   (public; nothing else of the key is printed):
   ```sh
   NEW_KID="$(jq -r '.AUTH_ACTIVE_PRIVATE_JWK | fromjson | .kid' "$OUT/export/values.json")"
   served_kid="$(curl -s -m 10 -H "Host: identity.$NEW.localhost" "$GW/oauth2/jwks" | jq -r '.keys[].kid')"
   [ -n "$NEW_KID" ] && [ "$NEW_KID" != null ] && [ "$served_kid" = "$NEW_KID" ] && [ "$NEW_KID" = "$OLD_KID" ] \
     && echo "kid ok: $NEW_KID" || echo "STOP: values '$NEW_KID', served '$served_kid', old guest '$OLD_KID'"
   ```
   This proves the guest, not the route: relying parties use `$ISSUER`.
10. **Switch the public route** to tenant `$NEW` with the gateway alias (P1).
    1. **One signer only.** Every other guest holding this signing key must be at 0 replicas
       before `$ISSUER` reaches `$NEW`: the old guest, frozen at 0 since step 2, any guest a
       rolled-back attempt left behind, and any workload, under any name, whose
       `<workload>-control` Secret holds a key with the same `kid`. `check_signers` prints
       `one signer: ok` only if all of these hold, and a `STOP` line for anything else,
       including a failed `kubectl` or an empty list:
       - `kubectl` lists the WorkloadDeployments;
       - `di-tenant-identity/identity` is listed at `replicas=0`;
       - `di-tenant-$NEW/identity` is listed at `replicas=1`;
       - every other workload named `identity` is at `replicas=0`;
       - every other running workload has no `<workload>-control` Secret whose
         `AUTH_ACTIVE_PRIVATE_JWK` has `$NEW_KID` (step 9). Only the `kid` is decoded and compared;
         the key is never printed or written to a file.
       ```sh
       check_signers() {
         case "$NEW_KID" in ''|null) echo 'STOP: no kid (step 9)'; return 1 ;; esac
         kubectl --kubeconfig "$KC" get workloaddeployments -A -o json > "$OUT/workloads.json" \
           || { echo 'STOP: cannot list the workloads'; return 1; }
         jq -r '.items[] | "\(.metadata.namespace) \(.metadata.name) \(.spec.replicas)"' "$OUT/workloads.json" > "$OUT/workloads.txt" \
           || { echo 'STOP: cannot read the workload list'; return 1; }
         bad=0
         grep -qx 'di-tenant-identity identity 0' "$OUT/workloads.txt" || { echo 'STOP: the old guest is not listed at replicas=0'; bad=1; }
         grep -qx "di-tenant-$NEW identity 1" "$OUT/workloads.txt" || { echo "STOP: the new guest is not listed at replicas=1"; bad=1; }
         while read -r ns name replicas; do
           [ "$ns $name" = "di-tenant-$NEW identity" ] && continue
           [ "$replicas" = 0 ] && continue
           if [ "$name" = identity ]; then echo "STOP: $ns/$name runs with replicas=$replicas"; bad=1; continue; fi
           jwk="$(kubectl --kubeconfig "$KC" -n "$ns" get secret "$name-control" --ignore-not-found -o 'jsonpath={.data.AUTH_ACTIVE_PRIVATE_JWK}')" \
             || { echo "STOP: cannot read $ns/$name-control"; bad=1; continue; }
           [ -n "$jwk" ] || continue
           kid="$(printf '%s' "$jwk" | jq -Rr '@base64d | fromjson | .kid // empty')" \
             || { echo "STOP: unreadable key in $ns/$name-control"; bad=1; continue; }
           [ "$kid" != "$NEW_KID" ] || { echo "STOP: $ns/$name signs with kid $kid and runs with replicas=$replicas"; bad=1; }
         done < "$OUT/workloads.txt"
         unset jwk
         [ "$bad" = 0 ] && echo 'one signer: ok'
         return "$bad"
       }
       check_signers || echo 'STOP: do not switch'
       ```
       Scale a stray signer to 0 first, as in step 2, and run it again. Limitation: a guest that
       keeps its key somewhere other than a `<workload>-control` Secret is found only by its
       workload name. The Postgres-era guest is one (its key is in `directory`), which is why
       `di-tenant-identity/identity` is checked by name. Then the tenant-auth check: `tenant_auth_state | diff "$OUT/tenant-auth.baseline" -`
       must print nothing (`$NEW`'s new workload does not show in it); otherwise roll back (P2,
       "The frozen issuer").
    2. **Switch:**
       ```sh
       up_platform "$OUT/platform-alias.json"
       kubectl --kubeconfig "$KC" -n wasmcloud rollout status deploy/di-platform-gateway --timeout=300s
       ```
       The only change is the alias: the gateway's config and its `di-framework.dev/config-hash`
       annotation change, so `di-platform-gateway` rolls. On pgprove the switch took effect
       about 4 s after the rollout completed, about 17 s after `up` started. The old gateway pod
       keeps routing until the new one is Ready, then closes its idle keep-alive connections and
       lets in-flight requests finish, so no pooled upstream connection to the old tenant host
       outlives it. Open client connections drop for under a second (platform#223). If the
       `up` fails, `up_platform "$OUT/platform.json"` first (the rules above), then retry or
       roll back.
    3. **Verify against the real issuer host**, as a relying party sees it:
       ```sh
       discovery="$(curl -s -m 10 "$ISSUER/.well-known/openid-configuration")"
       iss="$(printf '%s' "$discovery" | jq -r .issuer)"
       jwks_kid="$(curl -s -m 10 "$(printf '%s' "$discovery" | jq -r .jwks_uri)" | jq -r '.keys[].kid')"
       [ -n "$ISSUER" ] && [ "$iss" = "$ISSUER" ] && [ "$iss" = "$(jq -r .ISSUER_URL "$OUT/export/values.json")" ] \
         && [ -n "$NEW_KID" ] && [ "$jwks_kid" = "$NEW_KID" ] \
         && echo 'issuer ok' || echo "STOP: issuer '$iss', kid '$jwks_kid'"
       bun apps/guest/scripts/live-check.ts --values "$OUT/export/values.json" --url "$ISSUER" --host "${ISSUER#http://}" --read-only \
         && echo 'live-check ok' || echo 'STOP: live-check failed'
       ```
       Both must print `ok`. If either prints `STOP`, roll back (below).
11. **Soak.** Leave the old workload at 0 replicas and `directory` untouched for the soak period
    the coordinator sets, watching sign-ins, token refreshes and the guest's logs. Rollback is
    still available. Browser sessions expire after 30 minutes without use
    (`SESSION_IDLE_MS`), so sessions carried from the old guest survive only if the freeze to
    step 10 took less than that since their last request; refresh tokens keep their own
    lifetime. Users whose session expired sign in again.
12. **Final backup, verified.** Before anything is retired, all three of:
    - **`directory`:** either a fresh `pg_dump -Fc` (`umask 077`;
      `kubectl --kubeconfig "$KC" -n di-runtime-identity exec "$POD" -- pg_dump -Fc -U app -d app > "$OUT/final-directory.dump"`),
      or the export's `$OUT/export/directory.dump` with its digest re-checked
      (`shasum -a 256 "$OUT/export/directory.dump"` equals `jq -r .backup.sha256 "$OUT/export/manifest.json"`).
      Call it `DUMP`. First its table of contents:
      `kubectl --kubeconfig "$KC" -n di-runtime-identity exec -i "$POD" -- pg_restore --list < "$DUMP" | grep -c 'TABLE DATA'`
      must succeed and print the exported tables **plus** the tables the export does not copy as
      data but the dump holds: `identity_runtime_secret` and `identity_schema_migrations` (and
      `_migrations` and `_migrations_lock`, only if the Bun server ever migrated `directory`).
      On authproto that is `$(jq '.tables | length' "$OUT/export/manifest.json") + 2`, i.e.
      15 + 2 = 17. `--list` reads only the archive's table of contents, not the data, so then
      restore it into a scratch Postgres (local podman, no volume; the restored copy holds
      every secret, so `--rm` and remove it at once) and compare every exported table's rows:
      ```sh
      podman run -d --rm --name directory-restore-check -e POSTGRES_PASSWORD=restore-check --tmpfs /var/lib/postgresql/data postgres:16-alpine
      restore_ok=yes
      deadline=$(( $(date +%s) + 120 ))
      until podman logs directory-restore-check 2>&1 | grep -q 'init process complete' \
        && podman exec directory-restore-check pg_isready -U postgres >/dev/null 2>&1; do
        if [ "$(date +%s)" -ge "$deadline" ]; then echo 'scratch Postgres not ready after 2 minutes'; restore_ok=no; break; fi
        sleep 1
      done
      if [ "$restore_ok" = yes ]; then
        podman exec directory-restore-check createdb -U postgres restored \
          && podman exec -i directory-restore-check pg_restore -U postgres -d restored --no-owner --no-privileges --exit-on-error < "$DUMP" \
          || restore_ok=no
      fi
      if [ "$restore_ok" = yes ]; then
        jq -r '.tables[] | "\(.name) \(.count)"' "$OUT/export/manifest.json" | while read -r table count; do
          got="$(podman exec directory-restore-check psql -X -A -t -U postgres -d restored -c "SELECT count(*) FROM \"$table\"")"
          [ "$got" = "$count" ] && echo "ok $table $got" || echo "MISMATCH $table restored $got, exported $count"
        done
      fi
      podman stop directory-restore-check
      [ "$restore_ok" = yes ] || echo 'RESTORE CHECK NOT DONE: STOP, the dump is not verified'
      ```
      A timeout or a failed restore sets `restore_ok=no`, skips the comparison and ends with
      `RESTORE CHECK NOT DONE`: STOP and find the cause; nothing is verified then. Otherwise
      every line must be `ok`: the dump was taken in the same freeze as the export (or, for a
      fresh dump, from a `directory` nothing has written to since). Use a Postgres image at
      least as new as `directory`'s server. Record the file and its SHA-256.
    - **The new guest's encrypted data directory** (`$TARGET` from step 7), copied off the node
      in a short, announced pause with the new workload at 0 replicas, through a read-only
      helper pod like `install.ts`'s dry-run pod (root with DAC_READ_SEARCH only, which may read
      the host uid's 0700 files and change nothing; the target mounted read-only):
      ```sh
      NEW_REPLICAS="$(kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" get workloaddeployment identity -o jsonpath='{.spec.replicas}')"
      case "$NEW_REPLICAS" in ''|*[!0-9]*) echo "STOP: could not read the replicas: '$NEW_REPLICAS'" ;; esac
      echo "recorded replicas: $NEW_REPLICAS"   # keep this; it is restored below
      kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" patch workloaddeployment identity --type merge -p '{"spec":{"replicas":0}}'
      # wait until Host: identity.$NEW.localhost no longer answers /health
      NODE="$(kubectl --kubeconfig "$KC" get nodes -o jsonpath='{.items[0].metadata.name}')"
      kubectl --kubeconfig "$KC" apply -f - <<EOF
      apiVersion: v1
      kind: Pod
      metadata: { name: identity-cutover-backup, namespace: kube-system }
      spec:
        nodeName: $NODE
        restartPolicy: Never
        automountServiceAccountToken: false
        containers:
          - name: backup
            image: busybox:1.37.0
            command: [sleep, "3600"]
            securityContext:
              runAsUser: 0
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              capabilities: { drop: [ALL], add: [DAC_READ_SEARCH] }
            volumeMounts: [{ name: data, mountPath: /data, readOnly: true }]
        volumes: [{ name: data, hostPath: { path: $TARGET, type: Directory } }]
      EOF
      kubectl --kubeconfig "$KC" -n kube-system wait --for=condition=Ready pod/identity-cutover-backup --timeout=180s
      umask 077
      kubectl --kubeconfig "$KC" -n kube-system exec identity-cutover-backup -- sh -c 'cd /data && find . -type f -exec sha256sum {} +' \
        | LC_ALL=C sort > "$OUT/final-data.node.sha256"
      kubectl --kubeconfig "$KC" -n kube-system exec identity-cutover-backup -- tar -C /data -cf - . > "$OUT/final-data.tar"
      kubectl --kubeconfig "$KC" -n kube-system delete pod identity-cutover-backup
      kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" patch workloaddeployment identity --type merge -p "{\"spec\":{\"replicas\":$NEW_REPLICAS}}"
      mkdir -m 700 "$OUT/final-data" && tar -C "$OUT/final-data" -xf "$OUT/final-data.tar"
      (cd "$OUT/final-data" && find . -type f -exec shasum -a 256 {} +) | LC_ALL=C sort > "$OUT/final-data.copy.sha256"
      diff "$OUT/final-data.node.sha256" "$OUT/final-data.copy.sha256" && echo 'copy matches the node'
      dd if="$OUT/final-data/.di-encfs" bs=1 skip=8 count=16 2>/dev/null | xxd -p
      ```
      Both listings use `LC_ALL=C sort`, since `find` order and the locale's collation differ
      between the node and the workstation. The `diff` must print nothing, and the KCV (bytes
      8..24 of `.di-encfs`) must equal `DI_PGLITE_KEY`'s from step 4
      (`bun deploy/guest/runtime-secrets.ts kcv --values "$OUT/export/values.json"`). Delete the
      pod even if a step fails. Then move `final-data.tar` (or `final-data/`) to the backup
      location.
    - **`values.json`** (it holds `DI_PGLITE_KEY` and every secret), stored apart from the data
      copy: on a different volume or a different host from the copied data directory, so
      neither copy alone opens the other.

    File counts differ between steps, and that is expected: the import's disk line counts the
    files `import.ts` wrote (ciphertext files plus empty ones), and `install.ts` reports the same
    set as `N/N` (the rehearsal runs on a copy and changes nothing). Once the guest runs it
    applies V16..V20, rewrites tables (new relation files replace old ones), writes WAL and
    checkpoints, so the node's count drifts from the install's from the first start. Compare the
    node with its copy in the same pause, never with the install's count.

    `directory` is never dropped without a restorable copy verified this way.
13. **Retire** the old workload, the `directory` BackingService and tenant `identity`. Destroy
    `$OUT` once the new guest's own backups run; `directory.dump`, the old volume and every older
    backup of `directory` stay secret-bearing until destroyed. The alias stays: `$ISSUER`'s host
    is served through it for as long as the issuer is kept, so every later platform config keeps
    `"routeAliases": {"identity.identity": "identity.$NEW"}` (the alias source's tenant need not
    be declared; only the target must). Retiring tenant `identity` is a later `up_platform` with
    it removed from `tenants` in `platform-alias.json`. Keep
    `examples-registry.wasmcloud.svc.cluster.local:5000` in `insecureRegistries` while any
    workload still pulls from it (`acme/greeter-staging` does). Remove user `$PUSHER` the same
    way once no deploy needs it. After the retirement the guard still recognises authproto by
    its kubeconfig (path or API server) and by the instance name, so **every later**
    `deploy.sh` or `runtime-secrets.ts apply` with authproto's kubeconfig, including routine
    redeploys of `$NEW`, still needs `IDENTITY_AUTHPROTO_CUTOVER=authproto/$NEW` and still
    checks the exclusive tenant host image. That is intended.

**Rollback** (any time before step 13; the export never writes to `directory`). Never let the two
guests run at once: they share the signing key, and their refresh-token state diverges. The
platform upgrade from P2 stays (tenant `$NEW`, the exclusive host image, the allowlist): the
old guest was proven on it before the freeze.

Before step 1, run `cleanup_push` (step 8, item 4) if the push credentials may still exist.

1. Stop the **new** guest first, and confirm it is stopped (any `STOP` line: do not go on):
   ```sh
   kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" patch workloaddeployment identity --type merge -p '{"spec":{"replicas":0}}'
   r="$(kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" get workloaddeployment identity -o jsonpath='{.spec.replicas}')"
   h="$(curl -s -o /dev/null -m 10 -w '%{http_code}' -H "Host: identity.$NEW.localhost" "$GW/health")"
   [ "$r" = 0 ] && [ "$h" != 200 ] && echo 'new guest stopped' || echo "STOP: replicas '$r', /health $h"
   ```
   Repeat the last three lines until it prints `new guest stopped`.
2. If the alias is set (step 10), remove it: `up_platform "$OUT/platform.json"` (the same file
   without `routeAliases`), then
   `kubectl --kubeconfig "$KC" -n wasmcloud rollout status deploy/di-platform-gateway --timeout=300s`.
   On pgprove this took about 17 s; the gateway roll drops open connections for under a second
   (platform#223). If the `up` fails, run it again with the same file (the rules above); do
   not continue to step 3 while `$ISSUER` may still reach `$NEW`.
3. Only then restore the old guest's replicas from step 2 (`$OUT/old-replicas`) and check
   that it answers again:
   ```sh
   OLD_REPLICAS="$(cat "$OUT/old-replicas")"
   case "$OLD_REPLICAS" in ''|*[!0-9]*) echo "STOP: no recorded replicas: '$OLD_REPLICAS'" ;;
     *) kubectl --kubeconfig "$KC" -n di-tenant-identity patch workloaddeployment identity --type merge -p "{\"spec\":{\"replicas\":$OLD_REPLICAS}}" ;;
   esac
   h="$(curl -s -o /dev/null -m 10 -w '%{http_code}' -H 'Host: identity.identity.localhost' "$GW/health")"
   [ "$h" = 200 ] && echo 'old guest answers' || echo "not yet: /health $h"
   ```
   Repeat the last two lines until it prints `old guest answers` (the host may pull the
   component first), then check `$ISSUER` the same way if the route moved.
   Discovery answers again from here. Run P2 item 7's loop: a tenant-auth pod that restarted
   while the issuer was frozen recovers on its own within its retry budget, or needs one
   `rollout restart` if it is still crash-looping.
4. Remove the new tenant's workload, in `di-tenant-$NEW`:
   ```sh
   kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" delete workloaddeployment identity
   kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" delete secret identity-control   # every runtime secret and DI_PGLITE_KEY
   kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" get services                     # the deploy's Service for the workload
   kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" delete service identity          # if it is still listed
   ```
   This leaves the node data directory (`$TARGET` from step 7) in place: it is the new guest's
   data, encrypted under step 4's `DI_PGLITE_KEY`, and the only copy of anything written after
   step 8 (which is not copied back). Because it is not empty, `install.ts` (its dry run and
   `--yes`) refuses tenant `$NEW` from then on.

Data written to the new guest after step 8 is not copied back.

**Roll forward after a rollback: into a fresh tenant.** Do not reuse `$NEW`. The old guest took
writes again after rollback step 3, so the cutover starts over: pick another tenant name
(`NEW=identity-pg2`) and push user (`PUSHER=identity-cutover2`), and run P0..P2 and steps 1..12
again, with a new export (`rm -rf "$OUT/export" "$OUT/data"` first; both hold secrets) and so a
new `values.json` and a new `DI_PGLITE_KEY`. P2 declares the new tenant through new config files
built from the stack as it is then (which still declares the first attempt's tenant), and the
alias then targets `identity.$NEW` of the new attempt. There is deliberately no
`install.ts --wipe-target`: wiping would delete, through a root pod, the only copy of what the
rolled-back guest wrote, and a fresh tenant needs no new destructive tooling and costs only a
name. Keep the first attempt's data directory and its `values.json` until whatever it holds is
reviewed, then retire the first attempt's tenant (its directory goes with it, or by hand) and
destroy that `values.json`.

#### Proof of the cutover tooling

A later full rehearsal on `pgprove` ran the runbook end to end on a cluster. What it found
(rehearsal sign-in checks, the step 9 slug, the freeze's idle connection, the confirmation
value, the image check, rollback and roll-forward, the first push into a new tenant, the step 12
backup checks) is folded into the runbook and tools above. Separately, authproto's
`identity_runtime_secret` turned out to override the eight bootstrap identity settings, which
the export now carries (P0).

2026-10-13, the route alias on pgprove, with the platform and kube changes that ship as
`@di-framework/platform` 6.0.13 and `di-framework-kube` v0.0.5. Every step passed: P2's
`platform.json` built from the instance's stack config, the preview on a copy (only the changes
P2 allows), the upgrade with `--allow-insecure-registries`, `TenantAuthReady` and the new tenant's
registry, steps 1 and 5..9 into the new tenant, the single-signer check, the switch
(`routeAliases`, effective about 4 s after the gateway rollout and 17 s after `up` started),
the issuer checks of step 10, and the rollback (`up` without the alias, about 17 s). What it
found is folded into the runbook:

- a tenant created with `kubectl apply` cannot be declared afterwards ("already exists"), so P2
  creates it by declaring it;
- authproto's old guest and `acme/greeter-staging` pull from plain-HTTP `examples-registry`,
  which must be in `insecureRegistries` or their hosts cannot pull after the upgrade (P2 item 4);
- the kube CLI's default tenant host image is refused with `insecureRegistries`, so P2 names the
  exclusive build, which restarts every tenant host;
- a rejected `up` still saves its config (kube#13), and each gateway roll drops connections for
  under a second (platform#223) (the rules for every `up`);
- the build needs cli-plugin-platform 6.2.0 and `wac` on `PATH`;
- the tenant registry front (8790) is TLS only: the push that works is the schemeless URL with
  an `oras --insecure` wrapper and an API key of a user declared as a member of the new tenant
  (step 8);
- the first upgrade rolls the controller once, because `tenantAuth`'s stored form changes.

**Not covered by the pgprove run: tenant-auth on the frozen issuer.** pgprove's
`tenantAuth.issuer` was a static discovery stub in its own namespace
(`proving-grounds/scripts/kube.sh`), not the identity guest that was cut over. authproto's is
the guest itself, `http://identity.identity.localhost:28280` through the gateway
(`issuerUpstream: di-platform-gateway.wasmcloud.svc.cluster.local:80`). So pgprove did not
exercise what happens to tenant controllers and consoles while that issuer is frozen, or how
they rediscover it through the alias. P2 items 6 to 8 and "The frozen issuer" cover this from the
platform source (`discover()` in `platform/tenant-auth/src/oidc.ts`: 20 attempts, about
4 minutes, then the pod exits): the order of the waits, a baseline checked before the freeze,
before the push and before the switch, a preview showing the switch rolls only the gateway, and
an immediate rollback if a tenant-auth pod restarts in the frozen window.

2026-10-12. The live pgprove run was not possible: `kubesolo-pgprove` (stopped with exit 137)
restarted in a loop because Kubesolo could not pull `rancher/local-path-provisioner` through the
podman machine's TLS (the post-quantum key share drop described in the proving-grounds notes), and
importing the image into its containerd needs a privileged host-PID helper that was not
authorised. Everything up to the cluster was run locally instead:

- **Source:** `postgres:16-alpine` (16.15), `--rm`, populated by the Postgres-era guest itself
  (identity-server `23be792`, the commit authproto runs, `handle()` on Bun over the same
  no-affinity binding bridge its boot test uses): migrations V1..V15, the runtime secret rows as
  the Postgres-era Pulumi program wrote them (with an RS256 test key generated for this proof),
  bootstrap, three organizations, a browser OAuth client and a service client registered through
  the admin API, five password users, memberships, the owner's sign-in and consent, two refresh
  token families (one rotated once), a viewer session, and a stale `bootstrap_lease` row.
- **Export, key, import, rehearse** as in the runbook, with `--podman <container>` in place of
  the kubectl target. Then the **current guest code** (in-process on Bun) on a copy of the
  imported directory through the encrypted provider under wasmtime 48.0.1, with the exported
  values, for the checks that need the seed's own secrets.

| Check | Result |
| --- | --- |
| Export | V15 found; 15 tables with counts (users 7, organizations 4, memberships 6, registered clients 5, client lifecycle 5, authorizations 3, consents 2, refresh history 1, sessions 2, audit 9); 11 settings to `values.json`, 2 fingerprint rows to `state.json`, `bootstrap_lease` not carried; directory 0700, files 0600 |
| Export refusals | an extra runtime row (`SMTP_PORT`): refused, no directory written; V12, V16, gaps, `_migrations` ahead, a name that is not an identifier: refused (tests) |
| Import (31 s) | V1..V15 applied by the guest's migration code; every table `n/n`; fingerprint rows carried; `identity_runtime_secret` rows V16 would delete: 0 |
| On disk | 1756 files: 1570 encfs ciphertext under the key's KCV, 186 empty, 0 without a header; `.di-encfs` KCV equals `runtime-secrets.ts kcv`; `PostgreSQL`, `pg_catalog`, `template1` and every user login and email: in 0 files |
| Guest boot on the import | `/ready` 200, all checks true; V16..V20 applied; stored bootstrap fingerprint unchanged (no reconcile); `identity_runtime_secret` holds only the two fingerprint rows; every table count unchanged |
| Issuer and key | discovery `issuer` equals `ISSUER_URL`; JWKS serves the old `kid`; both ID tokens the old guest issued verify (RS256) against the new JWKS, same `kid` and `iss`; a new code exchange signs with the same `kid` |
| Users | owner, viewer and all five users sign in with the passwords the old guest hashed (signed-in session confirmed); a wrong password does not sign in |
| Clients | the bootstrap access, directory and provisioner clients and both admin-registered clients authenticate with their old secrets (introspection 200); wrong secrets 401; provisioner client credentials then the admin API lists 7 users |
| Tokens | the old guest's opaque access token introspects as active within its 600 s lifetime (first run) and inactive after it (second run, 30 minutes later); refresh: an unused token of either family rotates (200, new token); the already rotated token is reuse (400 `invalid_grant`) and revokes its family (the token just issued: 400) |
| Sessions and consent | the viewer's session cookie from the old guest is still signed in; the owner's stored consent is reused (authorize redirects straight to the callback with a code) |
| Refusals | rehearsal with another `DI_PGLITE_KEY`: `pglite-encfs: ... key check value mismatch; refusing`, open failed; install with a key whose KCV differs from the marker: refused before any cluster call; import into a non-empty directory: refused |
| Logs | the tools' combined output scanned for 32 secret and PII strings (every value, the JWK's private parts, user passwords, client secrets, emails, password hashes): 0 found |

`deploy/cutover/roundtrip.test.ts` runs the export and import on real engines in CI (Postgres
16 at V13, V14 and V15, PGlite 17.5 behind the guest's adapter), boots the current guest on the
V15 import and signs in and authenticates with the old credentials; `units.test.ts` covers the
mapping, refusals, the runner protocol, the ciphertext check and the install plan;
`commands.test.ts` runs the export, import and install orchestration with stubbed psql, kubectl
and runner processes (atomic export, cleanup on failure, the helper pod deleted on every path).

**Not proven by this offline run:** anything on a cluster. The install helper pod and its image
on the node, deploying into a tenant whose storage was pre-filled, the guest under wash (QuickJS
and the composed Argon2 component) on imported data, the freeze in step 2 (`replicas: 0` on a
WorkloadDeployment), and the route move were proven later on pgprove (above). The rehearsal runs
the guest's code on Bun, not the component, and wasmtime, not wash. Nothing has run against
authproto.

**Decisions behind the preconditions** (P1 and P2, before any freeze):

- **The issuer's host** (P1). authproto's issuer names tenant `identity` in its host. Keeping it
  (and so every token) means serving that host from the new tenant, which the gateway does not
  do by tenant name. Decided 2026-10-13: an administrator gateway route alias (platform #218/#219)
  rather than a CoreDNS rewrite or reusing tenant `identity`. P1 still stops for an issuer the
  alias cannot move.
- **The tenant host image** (P2). The pglite guest needs the exclusive-instance wash build, and
  `insecureRegistries` needs wash patch 0002, which that build carries. Switching it restarts
  every tenant host, the old guest's included; the user accepted that maintenance blip, and P2
  proves the old guest on the new image before the freeze.
