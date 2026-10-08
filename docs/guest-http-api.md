# Guest HTTP API on tenant identity

This is the record of moving the Bun identity HTTP surface onto the existing `identity` wasmCloud workload, and of the fixes required before that workload could serve tokens, sessions, mail, and organization writes.

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

The program creates the di-framework-kube instance and platform, then the component registry. It then runs `di-framework platform deploy identity --target identity` whenever the guest's sources change, with the registry port-forwarded for the push. That builds `apps/guest/dist/identity.wasm`, pushes it to `IDENTITY_REGISTRY_PUSH`, and updates `WorkloadDeployment/identity` in `di-tenant-identity`. No second Postgres service is created. Egress is limited to the hosts in `allowedIpNameLookups`.

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
