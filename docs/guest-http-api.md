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
tenant** on authproto. The tools below are built and proven offline against a synthetic
Postgres-era database (see [Proof](#proof-of-the-cutover-tooling)); the cluster steps (tenant,
install, deploy) are not proven live yet. Nothing here has run against authproto.

#### What moves, and how

| Step | Tool | What it does |
| --- | --- | --- |
| Export | `deploy/cutover/export.ts` | One read-only statement over `kubectl exec ... psql` reads the schema history, every table's rows (as PostgreSQL's own `json_agg` text) and count, and the `identity_runtime_secret` rows, as one snapshot. Writes a mode 0700 directory: `manifest.json` (version, tables, columns, counts, digests; no values), `tables/<t>.json`, `values.json` (the deploy.sh values file), `state.json`, and `directory.dump` (`pg_dump -Fc` of the whole database, for rollback). Files are 0600 and nothing is printed but names and counts. |
| Key | `deploy/guest/runtime-secrets.ts pglite-key` | Adds `DI_PGLITE_KEY` to `values.json` (a new data directory needs a new key) and prints its KCV. |
| Import | `deploy/cutover/import.ts` | Runs the guest's own encrypted provider (`apps/guest/.di-framework/di-framework-pglite.encrypted.wasm`, checked to be byte for byte the provider inside `apps/guest/dist/identity.wasm`) under `wasmtime`, plugged into a small wasip2 runner (`deploy/cutover/pglite-runner`, Rust) that serves `di-framework:pglite/database` to the guest's own adapter over stdin/stdout. Initialises a fresh encrypted directory, migrates it to the source version with the guest's migration code, loads every table and the bootstrap fingerprints in one transaction, checks the counts inside it, then checks every file on disk is encfs ciphertext under the key's KCV and contains no engine string or user login or email. |
| Rehearse | `deploy/cutover/rehearse.ts` | Boots the guest's request handler in-process on a **copy** of the imported directory, through the same provider: `/ready`, the later migrations, no bootstrap reconcile, issuer and signing key `kid`, owner and viewer sign-in, the three bootstrap clients' secrets, row counts. |
| Install | `deploy/cutover/install.ts` | Dry run by default. With `--yes`, a helper pod on the node (the platform's storage-init image, root with CHOWN and DAC_OVERRIDE only, with exactly the target directory mounted) copies the directory into `<storageRoot>/di-tenants/<tenant uid>/workloads/identity` (what the platform mounts as the guest's `/data`), directories 0700, files 0600, then owner 65532, and compares every file's SHA-256 and owner. The pod is deleted on success and on failure; a failed delete names it. Refuses a non-empty target (before sending anything), a tenant with `directory`, a tenant that already has the WorkloadDeployment (unless `--allow-existing-workload`), and a directory whose marker KCV is not the values file's. |
| Deploy | `deploy/guest/deploy.sh` | Unchanged path, with the guard lifted for this case only (below). |

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
  name. Any other name is refused (it changed the old guest's settings; dropping it silently
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
`IDENTITY_AUTHPROTO_CUTOVER=authproto/<tenant>` in the environment (no trimming), whose tenant
host (`hostgroup-tenant-<tenant>` in `di-runtime-<tenant>`) runs the exclusive-instance wash build.
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
holds authproto's kubeconfig. Needs Bun, kubectl, wasmtime 48, `wac` (`WAC=<path>`, or
`DF_SQLITE_TOOLS_DIR/bin/wac` as for the build), `wasm-tools`, rustup (the runner builds with the
toolchain in `deploy/cutover/pglite-runner/rust-toolchain.toml` on first use), and
cli-plugin-platform 6.2.0 or later. Keep `$OUT` on an encrypted volume; it will hold every
secret and all user data.

```sh
KC="$HOME/Library/Application Support/di-framework-kube/authproto/kubeconfig"
CTX="$(kubectl --kubeconfig "$KC" config current-context)"
NEW=identity-pg                     # the new tenant; any DNS label but `identity`
OUT=/path/on/encrypted/volume/authproto-cutover
GW=http://127.0.0.1:<gateway port>  # authproto's platform gateway
mkdir -m 700 -p "$OUT"
export WAC=/path/to/wac
```

##### Preconditions (before any freeze)

Neither check stops or changes the old guest. If either fails, **STOP**: do not freeze, and
present the options below to the coordinator. Resume only once a decision is recorded.

P1. **The issuer host.** While the old guest is still up, read its issuer from its public
    discovery document:
    `ISSUER="$(curl -s -H 'Host: identity.identity.localhost' "$GW/.well-known/openid-configuration" | jq -r .issuer)"`.
    The cutover keeps this issuer (and so every issued token), so after step 10 requests for
    `$ISSUER`'s host must reach tenant `$NEW`. The gateway routes `<name>.<tenant>.localhost` by
    tenant name, so if the host is `*.identity.localhost`, or if nothing defines how that host is
    moved to `$NEW`, STOP. Options:
    - an alias in front of the gateway that sends `$ISSUER`'s host to `identity.$NEW.localhost`
      (its own change; moving it back is the route rollback);
    - a new issuer, which invalidates every token and relying party configuration (not "migrate
      everything", so a new sign-off);
    - deploying into tenant `identity` after `directory` is retired: the guard refuses this by
      design, and it would need its own change and its own rollback story.
P2. **The exclusive tenant host image.** Create the new tenant now (the old guest is untouched).
    With the installation label of the existing tenant
    (`kubectl --kubeconfig "$KC" get tenants.platform.di-framework.dev identity -o jsonpath='{.metadata.labels}'`):
    ```sh
    kubectl --kubeconfig "$KC" apply -f - <<EOF
    apiVersion: platform.di-framework.dev/v1alpha1
    kind: Tenant
    metadata:
      name: $NEW
      labels: { <installation label key>: <value> }
    spec: {}
    EOF
    kubectl --kubeconfig "$KC" wait tenants.platform.di-framework.dev/$NEW --for=condition=Ready --timeout=300s
    kubectl --kubeconfig "$KC" -n "di-runtime-$NEW" get deploy "hostgroup-tenant-$NEW" -o jsonpath='{.spec.template.spec.containers[*].image}'
    ```
    The image must be the exclusive-instance build, `ghcr.io/di-framework/wash:2.8.0-wasi-tls-exclusive`
    (`deploy.sh` refuses the cutover otherwise). If it is not, STOP: switching it is a platform
    config change that rolls **every** tenant host, the old guest's included, which a rollback
    would then restore onto an image it was never tested with. Options: switch the image and
    prove the old guest on it before the cutover, or a platform change that gives only `$NEW`'s
    host the exclusive build. Tenant `$NEW` can stay or be deleted; nothing else changed.

##### Cutover

1. **Build the guest** (the import uses the provider this build composes):
   `(cd apps/guest && di-framework platform build)`. It must log
   `Composing the PGlite encryption layer into the provider`.
2. **Freeze writes on the Postgres guest.** Record its replicas, then stop it:
   `kubectl --kubeconfig "$KC" -n di-tenant-identity get workloaddeployment identity -o jsonpath='{.spec.replicas}'`,
   then
   `kubectl --kubeconfig "$KC" -n di-tenant-identity patch workloaddeployment identity --type merge -p '{"spec":{"replicas":0}}'`,
   and check that `Host: identity.identity.localhost` no longer answers `/health`. Then check that
   nothing else is connected to `directory`; this must print `0`:
   ```sh
   POD="$(kubectl --kubeconfig "$KC" -n di-runtime-identity get pods -l app=di-bs-directory -o jsonpath='{.items[0].metadata.name}')"
   kubectl --kubeconfig "$KC" -n di-runtime-identity exec "$POD" -- psql -X -A -t -U app -d app \
     -c 'SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()'
   ```
   If it is not 0, find the client (`SELECT usename, application_name, client_addr FROM pg_stat_activity ...`)
   and stop it before step 3. Anything written after step 3 is lost.
3. **Export** (read-only on `directory`):
   `bun deploy/cutover/export.ts --kubeconfig "$KC" --context "$CTX" --namespace di-runtime-identity --service directory --out "$OUT/export"`.
   Expect `source schema V15`. If it refuses unknown runtime rows, review them; do not edit the
   tool's mapping. A failed export leaves no `$OUT/export` behind. Then repeat both checks of
   step 2: the old workload's `replicas` must still be `0` (a controller may have restored it)
   and the `pg_stat_activity` count `0`. Otherwise stop the writer again, delete the old export
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
   Every line must be `ok`, including `bootstrap not reconciled`.
7. **Install** (dry run, then for real), before the guest's WorkloadDeployment exists:
   `bun deploy/cutover/install.ts --data "$OUT/data" --values "$OUT/export/values.json" --kubeconfig "$KC" --context "$CTX" --tenant "$NEW"`,
   check the target path and counts, and repeat with `--yes`. Expect
   `installed: N/N files match, 0 missing, 0 changed, 0 extra; 0 not owned by 65532`.
8. **Deploy** (registry port-forward as for authproto's earlier deploys):
   `kubectl --kubeconfig "$KC" -n wasmcloud port-forward svc/examples-registry 25001:5000 &`, then
   `IDENTITY_AUTHPROTO_CUTOVER=authproto/$NEW deploy/guest/deploy.sh authproto "$NEW" "$OUT/export/values.json"`.
   It logs `authproto cutover confirmed for the new tenant`, builds, deploys, waits for Ready and
   writes `identity-control`.
9. **Verify on the tenant host** (`Host: identity.$NEW.localhost`):
   `bun apps/guest/scripts/live-check.ts --values "$OUT/export/values.json" --url "$GW" --host identity.$NEW.localhost --slug unused --read-only`,
   and compare `curl -s -H "Host: identity.$NEW.localhost" "$GW/oauth2/jwks" | jq -r '.keys[].kid'`
   with `jq -r '.AUTH_ACTIVE_PRIVATE_JWK | fromjson | .kid' "$OUT/export/values.json"` (a public
   key id). This proves the guest, not the route: relying parties use `$ISSUER`.
10. **Move the public route** for `$ISSUER`'s host to tenant `$NEW`, as decided in P1. Then verify
    against the real issuer host, as a relying party sees it:
    `curl -s "$ISSUER/.well-known/openid-configuration" | jq -r .issuer` must equal `$ISSUER`
    and `jq -r .ISSUER_URL "$OUT/export/values.json"`; the `jwks_uri` it names must serve the kid
    from step 9; and `live-check.ts` as in step 9 with `--url` and `--host` taken from `$ISSUER`
    must pass. If any check fails, roll back (below).
11. **Soak.** Leave the old workload at 0 replicas and `directory` untouched for the soak period
    the coordinator sets, watching sign-ins, token refreshes and the guest's logs. Rollback is
    still available.
12. **Final backup, verified.** Before anything is retired, all three of:
    - **`directory`:** either a fresh `pg_dump -Fc` (`umask 077`;
      `kubectl --kubeconfig "$KC" -n di-runtime-identity exec "$POD" -- pg_dump -Fc -U app -d app > "$OUT/final-directory.dump"`),
      or the export's `$OUT/export/directory.dump` with its digest re-checked
      (`shasum -a 256 "$OUT/export/directory.dump"` equals `jq -r .backup.sha256 "$OUT/export/manifest.json"`).
      Either way, prove it restorable:
      `kubectl --kubeconfig "$KC" -n di-runtime-identity exec -i "$POD" -- pg_restore --list < <dump> | grep -c 'TABLE DATA'`
      must succeed and count the exported tables. Record the file and its SHA-256.
    - **The new guest's encrypted data directory** (`<storageRoot>/di-tenants/<uid>/workloads/identity`,
      printed by step 7), copied off the node while the new workload is at 0 replicas (a short,
      announced pause), with a helper pod like `install.ts`'s. Check the copy: its SHA-256 listing
      equals the one taken on the node in the same pause, and its `.di-encfs` KCV
      (bytes 8..24: `dd if=<copy>/.di-encfs bs=1 skip=8 count=16 2>/dev/null | xxd -p`) equals `DI_PGLITE_KEY`'s from step 4.
    - **`values.json`** (it holds `DI_PGLITE_KEY` and every secret), stored apart from the data
      copy, so neither alone opens the other.

    `directory` is never dropped without a restorable copy verified this way.
13. **Retire** the old workload, the `directory` BackingService and tenant `identity`. Destroy
    `$OUT` once the new guest's own backups run; `directory.dump`, the old volume and every older
    backup of `directory` stay secret-bearing until destroyed. After the retirement the guard
    still recognises authproto by its kubeconfig (path or API server) and by the instance name,
    so **every later** `deploy.sh` or `runtime-secrets.ts apply` with authproto's kubeconfig,
    including routine redeploys of `$NEW`, still needs `IDENTITY_AUTHPROTO_CUTOVER=authproto/$NEW`
    and still checks the exclusive tenant host image. That is intended.

**Rollback** (any time before step 13; the export never writes to `directory`). Never let the two
guests run at once: they share the signing key, and their refresh-token state diverges.

1. Stop the **new** guest first:
   `kubectl --kubeconfig "$KC" -n "di-tenant-$NEW" patch workloaddeployment identity --type merge -p '{"spec":{"replicas":0}}'`,
   and check that `Host: identity.$NEW.localhost` no longer answers `/health`.
2. If the route moved (step 10), move it back to tenant `identity`.
3. Only then restore the old guest's replicas from step 2 and check that
   `Host: identity.identity.localhost` answers `/health` (and `$ISSUER`, if the route moved).
4. Remove the new tenant's workload.

Data written to the new guest after step 8 is not copied back.

#### Proof of the cutover tooling

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

**Not proven:** anything on a cluster. Creating a tenant with `kubectl apply`, the install helper
pod and its image on the node, deploying into a tenant whose storage was pre-filled, the guest
under wash (QuickJS and the composed Argon2 component) on imported data, the freeze in step 2
(`replicas: 0` on a WorkloadDeployment), and the route move. The rehearsal runs the guest's code
on Bun, not the component, and wasmtime, not wash.

**Decisions the runbook stops for** (preconditions P1 and P2, before any freeze):

- **The issuer's host** (P1). If authproto's issuer names tenant `identity` in its host, keeping
  the issuer (and so every token) means serving that host from the new tenant, which the gateway
  does not do by tenant name; P1 lists the options.
- **The tenant host image** (P2). The pglite guest needs the exclusive-instance wash build; if
  the new tenant's host runs another image, switching it rolls every tenant host, the old
  guest's included; P2 lists the options.
