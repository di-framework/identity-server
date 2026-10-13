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
| `MIGRATION_DATABASE_URL` | empty | Optional owner-role URL for [role separation](#database-role-separation): migrations run as this role, and the `DATABASE_URL` role gets DML and EXECUTE only. |
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
| `IDENTITY_COLUMN_ENCRYPTION` | `disabled` | `enabled` opts in to pgcrypto column encryption (see [Column encryption](#column-encryption)). Any other value fails startup. |
| `IDENTITY_COLUMN_KEY`, `IDENTITY_BIDX_KEY` | empty | Column encryption key and blind-index key: 32 random bytes each, base64, different from each other. Required once encryption is enabled. |

Generate a signing key with:

```bash
bun scripts/generate-jwk.ts            # RS256
bun scripts/generate-jwk.ts ML-DSA-65  # only after relying parties accept ML-DSA-65
```

## Startup

`apps/server` connects Postgres, applies the migrations, validates the signing keys, loads the
column encryption state (enabling it when opted in), reconciles the
bootstrap owner, organization, and the three clients, starts the notification worker, then
listens. Any failure exits the process before it accepts traffic. Bootstrap is safe on every start:
it creates what is missing, re-hashes the client secrets, and never renames the organization.

## Column encryption

Optional at-rest encryption of PII and secrets with pgcrypto, for **new writes only**
(identity-server#56, di-framework/platform#138).

| Column | Protection |
| --- | --- |
| `users.email`, `users.display_name`, `users.avatar_url` | `pgp_sym_encrypt` into `<column>_enc`. `users_email_key` stays: new rows write `email` NULL, which never collides. |
| `users.normalized_email` | HMAC-SHA256 blind index `normalized_email_bidx` (UNIQUE); the three email lookups use it. The address itself is in `email_enc`. |
| `email_challenges.email` | encrypted, plus `email_bidx` of the trimmed lower-cased address for the issuance rate limit (index on `email_bidx, purpose, created_at`) |
| `identity_links.subject` | encrypted, plus `subject_bidx` (`UNIQUE (issuer, subject_bidx)`); the three subject lookups use it |
| `identity_links.provider_email`, `identity_link_flows.nonce`, `identity_link_flows.code_verifier`, `identity_unlink_confirmations.subject`, `identity_security_notifications.recipient_email`, `oauth2_authorization.oidc_id_token_claims`, `browser_sessions.attributes`, `auth_audit_records.before_metadata`, `auth_audit_records.after_metadata` | encrypted |

Logins (`login`, `normalized_login`) stay plaintext. Token, secret and password columns already
hold SHA-256 or Argon2id hashes and are unchanged.

**Opting in.** `V18__column_encryption.sql` always runs. It creates the pgcrypto extension (or, on
an engine without it, logs a notice and carries on), adds the nullable `_enc` and `_bidx`
columns and indexes, and adds the one-row `identity_column_encryption` table with
`enabled = false`. Its CHECK constraints are added `NOT VALID`, so V18 itself scans no rows.
`V19__validate_column_encryption_checks.sql` validates them in a separate migration, which only
takes SHARE UPDATE EXCLUSIVE locks and so blocks neither reads nor writes.
`V20__pin_column_encryption_search_path.sql` pins name resolution in both trigger functions
(`SET search_path = pg_catalog, pg_temp`, and the latch table named by schema), so a caller's
`search_path` or a temp table cannot change what they read.
Nothing is encrypted yet. To opt in, put both keys and `IDENTITY_COLUMN_ENCRYPTION=enabled` in
the settings (for the guest, in `identity-control`; see below) and restart. At startup
(`IdentityModule.prepare`, or the guest's boot before bootstrap) the service:

1. runs `CREATE EXTENSION IF NOT EXISTS pgcrypto` and looks up the schema pgcrypto lives in, so
   its functions are called schema-qualified, whatever the `search_path`;
2. proves the engine works with the real keys, by running an encrypt/decrypt round trip and an
   HMAC that it compares with its own;
3. only then sets `enabled = true` and records an HMAC check value for each key, never the keys.

**Enabling is one-way.** The `identity_column_encryption_guard` trigger refuses (SQLSTATE
`IDC02`) any of these: turning `enabled` off, changing or clearing a recorded key check,
deleting the row, or truncating the table. The service and the plaintext-reject trigger also
treat recorded key checks as enabled, even if `enabled` were forced off.

**What the in-database latch does and does not stop.** These triggers stop mistakes. Against a
SQL writer that **does not own the tables** (for example, a session using the service role's
credentials under [role separation](#database-role-separation)), they stop exactly two things:
downgrading or rekeying the latch, and writing a new non-NULL value to a protected plaintext
column. Since V20 that also holds when the writer creates its own
`pg_temp.identity_column_encryption` or changes its `search_path`: the trigger functions read only
the real latch table. They do not stop the table owner or a superuser. Either one can
`ALTER TABLE … DISABLE TRIGGER`, `DROP TRIGGER`, or replace the trigger functions, and then
downgrade the latch or write plaintext.

They are not access control for the data. A writer with DML on the tables can still change or
delete rows, change the columns that are not encrypted, write NULL or arbitrary bytes to an `_enc`
or `_bidx` column, and copy ciphertext from one row to another. Without the keys, it cannot read
or produce valid ciphertext.

- **Bun server on Postgres:** use [role separation](#database-role-separation). The service's
  own role then is not the owner, and the latch holds against the service role and anything that
  borrows its credentials.
- **Without role separation** (a single `DATABASE_URL` role that owns the schema), the service's
  own credentials can undo the latch.
- **wasmCloud guest on pglite:** the guest's database user is effectively a superuser of its
  embedded engine. There, the latch only protects against mistakes, and the protection that counts
  is the key custody below. Keep
`IDENTITY_COLUMN_ENCRYPTION=enabled` and both keys in the settings after opting in. The switch
is what opts a fresh database in (for example, a restore into an empty one). On an
already-enabled database the keys are what count, and removing the switch does not turn
encryption off.

**Once enabled, it fails closed.**
- Startup needs both keys, and they must match the recorded checks. A missing or different key
  stops the Bun server at startup. The guest answers every request with 503 and the generic body
  `{"ok":false,"error":"service unavailable","reason":"column-encryption-unavailable"}`. A
  request that reaches an unusable cipher also answers 503, with `service unavailable`. Which setting is missing, or which key differs, appears only in the
  log. Nothing falls back to plaintext.
- In the database, the `identity_reject_plaintext` trigger refuses (SQLSTATE `IDC01`, which the
  service maps to 503) any INSERT or UPDATE that writes a new non-NULL value to a protected
  plaintext column.
- An instance that loaded the disabled state before another instance opted in reacts in two
  ways. On an `IDC01` refusal it drops its cached state at once, and it also re-reads a disabled
  state every 30 seconds (`DISABLED_REFRESH_MS`). Within at most one refusal or 30 seconds it
  therefore reads encrypted rows correctly, provided it has the keys. Roll the keys out to every
  instance before any instance opts in.
- The trigger costs about 5 µs per written row on the server: an `EXPLAIN ANALYZE` of 20,000
  `browser_sessions` updates on Postgres 16 measured 4.9 µs per row while disabled and 5.6 µs
  per row while enabled, against 5.4 µs for the update itself. That is small next to the ~0.4 ms
  round trip of each statement.
- An engine without pgcrypto cannot be enabled: startup fails with
  `column encryption needs the pgcrypto extension`. The pglite provider gets pgcrypto in a
  separate di-framework/platform change. Until that ships, the guest runs unencrypted and should
  not be opted in.

**Existing rows are not rewritten.** Rows written before the opt-in keep their plaintext. Reads
return `coalesce(pgp_sym_decrypt(<column>_enc, key), <column>)`. Lookups match the blind index
or the legacy plaintext column. A new user or link is refused (409) while a legacy row has the
same normalized email or `(issuer, subject)`, so uniqueness holds across both kinds of row. When
a legacy row is updated, only the columns that the update writes are encrypted; for example, a
display name change encrypts the display name but leaves the legacy email plaintext. **Legacy
plaintext stays in the table until a later re-encrypt (backfill) pass, which is a follow-up. It
also stays in WAL, dead tuples (until VACUUM) and every backup taken before then.** Treat
backups from before the opt-in as holding plaintext PII.

**Statements.** A key is always a bound statement parameter and never part of SQL text, for
example `<schema>.pgp_sym_encrypt(?::text, ?::text, 'cipher-algo=aes256, s2k-mode=1,
s2k-digest-algo=sha256')` and `<schema>.hmac(?::text, ?::text, 'sha256')`. Statements are
composed with the `sql` tag (`packages/core/src/shared/infrastructure/sql.ts`), which only ever
turns values into `?` bindings. `packages/core/tests/column-encryption.test.ts` records every
statement and asserts this. MDC integrity is on, and compression is off. S2K is salted but not
iterated, because the key is 32 random bytes and not a password. Ciphertext length still follows
plaintext length (an email's length is visible, for example).

### Threat model and logging

Column encryption protects copies of the data at rest that do not include the keys: the data
directory, `pg_dump` output, base backups, and WAL written after the opt-in. It does **not**
protect against someone who controls the live database server or the service process. The keys
travel to the server with every statement, so such a person can capture them, for example by
turning on statement logging. It also does not cover plaintext from before the opt-in (see
above).

The keys are bound values, so they reach any log that records bound values:

- **Postgres (Bun server).** With `log_min_duration_statement`, `log_statement` or
  `auto_explain`, Postgres logs `DETAIL: parameters: $1 = '…'`, which includes keys and plaintext.
  For the application role, turn off parameter logging:
  `ALTER ROLE identity SET log_parameter_max_length = 0;` and
  `ALTER ROLE identity SET log_parameter_max_length_on_error = 0;`. Do not enable statement
  logging with parameters for that role. Connect to Postgres over TLS (`sslmode=verify-full`),
  because the keys cross the network on every statement.
- **The service.** Driver errors can carry the statement and its values (PGlite's
  `DatabaseError` keeps `params` and `query`). `PostgresGateway` strips `params`, `parameters`,
  `query` and `values` from every database error before rethrowing it. The control-plane and
  route error handlers log only `message (code)`, and HTTP error bodies are generic.
- **The production guest.** The platform pglite provider already redacts statement values from
  its error descriptions.

### Key custody

- `IDENTITY_COLUMN_KEY` (encryption) and `IDENTITY_BIDX_KEY` (blind index) are two independent
  32-byte random values, base64 encoded. They are separate from each other and from the pglite
  filesystem key `DI_PGLITE_KEY`, so a leak of one does not expose the others.
- They live only in the runtime settings: `identity-control` for the guest, the stack's secret
  state for `deploy/platform` (`random.RandomBytes`), and the process environment for the Bun
  server. They are never stored in the database, and the service never logs them. Database
  server logs are configured separately; see [Threat model and logging](#threat-model-and-logging).
- The two keys must differ. The settings loader refuses equal keys, and so do the runtime
  secrets tools.
- **Losing `IDENTITY_COLUMN_KEY` makes every encrypted column unreadable, and losing
  `IDENTITY_BIDX_KEY` breaks every lookup by email or subject.** Back both up with the same care
  as the database backups, but store them separately from those backups.
- Key rotation is not supported yet. Re-encrypting under a new key is the same follow-up pass as
  the backfill. `runtime-secrets.ts column-keys` never replaces an existing key.
- Generating keys: `bun deploy/guest/runtime-secrets.ts generate ... [--column-encryption]`
  writes both keys into a new values file. For an existing file, run
  `bun deploy/guest/runtime-secrets.ts column-keys --values <file> [--enable]`, which adds any
  missing key and with `--enable` sets the switch, then `apply`. `apply` refuses a values file
  that enables encryption without both keys, with malformed keys, or with two equal keys. With
  Pulumi, set `columnEncryption: true` in the stack config. The keys are generated either way.
- The control-Secret keys are `IDENTITY_COLUMN_ENCRYPTION`, `IDENTITY_COLUMN_KEY` and
  `IDENTITY_BIDX_KEY`, declared in `controlSecretKeys` of `apps/guest/di-framework.config.json`
  alongside the data directory keys (see [Data directory encryption](#data-directory-encryption)).

## Database role separation

For the Bun server on Postgres, set `MIGRATION_DATABASE_URL` to a role that owns the identity
schema, and `DATABASE_URL` to a separate login role that owns nothing. At startup the server
then does this:

1. It applies the migrations as the owner role.
2. It grants the service role exactly this (`grantServiceRole` in `packages/migrations`):
   - `USAGE` on the schema;
   - `SELECT, INSERT, UPDATE, DELETE` on the tables, but read-only on the migration runner's
     `_migrations` and `_migrations_lock`;
   - `USAGE, SELECT` on sequences;
   - `EXECUTE` on functions.

   It first revokes everything else, so `TRUNCATE`, `REFERENCES`, `TRIGGER` and leftover grants
   go. The grants are re-applied on every start, which also covers new tables.
3. It serves on the service role.

Startup refuses a service role that is the owner, a superuser, or the owner of any table in the
schema. As the service role, `ALTER TABLE … DISABLE TRIGGER`, `DROP TRIGGER`,
`CREATE OR REPLACE FUNCTION` on the trigger functions, `TRUNCATE`, writes to `_migrations`, and
downgrading or deleting the latch row all fail. A plaintext write to a protected column is refused
with `IDC01`, also from a session that has created a `pg_temp.identity_column_encryption` shadow
table claiming encryption is off (V20). `packages/core/tests/role-separation.test.ts` checks each
of these on PostgreSQL 16.

Two caveats about DDL:

- `CREATE TABLE` in `public` fails for the service role only because PostgreSQL 15 and later no
  longer grant `CREATE` on `public` to `PUBLIC`. On PostgreSQL 14 and earlier, run
  `REVOKE CREATE ON SCHEMA public FROM PUBLIC;` yourself. The trigger functions do not depend on
  it, because V20 pins their name resolution.
- The service role can still create temporary tables, since `PUBLIC` has `TEMPORARY` on the
  database by default. Since V20 this does not affect the triggers. To remove it anyway, run
  `REVOKE TEMPORARY ON DATABASE identity FROM PUBLIC;`. The service does not use temporary tables.

```sql
-- once, as a superuser
CREATE ROLE identity_owner LOGIN PASSWORD '…';      -- MIGRATION_DATABASE_URL uses this role
CREATE ROLE identity_service LOGIN PASSWORD '…';    -- DATABASE_URL uses this role

-- a new database:
CREATE DATABASE identity OWNER identity_owner;

-- an existing database, where the single role `identity` has been migrating and serving so far
-- and owns the tables. Connected to that database, hand everything it owns to the owner role:
REASSIGN OWNED BY identity TO identity_owner;
```

In the existing-database case, `identity` is the role that used to be the only one. After the
`REASSIGN OWNED` it owns nothing, and you have two options:

- Point `DATABASE_URL` at `identity_service`, as above, and then retire or lock the `identity`
  login.
- Skip `CREATE ROLE identity_service` and keep `DATABASE_URL` on `identity`, which is now the
  service role. This only works if `identity` is not a superuser. For example, the `POSTGRES_USER`
  of the official image and of `compose.yml` is a superuser, and startup refuses it.

Either way, `DATABASE_URL` must name the role that owns nothing, and `MIGRATION_DATABASE_URL`
must name `identity_owner`.

With `MIGRATION_DATABASE_URL` unset, the server keeps the earlier behaviour: one role migrates and
serves, so it owns the tables and could undo the latch. The pglite guest has no roles; see
[Column encryption](#column-encryption).

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
  `AUTH_CLI_CLIENT_ID`, `AUTH_CLI_REDIRECT_URIS`, and for [column encryption](#column-encryption)
  `IDENTITY_COLUMN_ENCRYPTION`, `IDENTITY_COLUMN_KEY`, `IDENTITY_BIDX_KEY`
  (`RUNTIME_SECRET_SETTINGS` in `apps/guest/src/settings.ts`). Optionally also the bootstrap
  identity, which overrides the compiled-in defaults: `AUTH_BOOTSTRAP_ORGANIZATION_SLUG`,
  `AUTH_BOOTSTRAP_ORGANIZATION_NAME`, and `AUTH_BOOTSTRAP_{OWNER,VIEWER}_{LOGIN,EMAIL,DISPLAY_NAME}`
  (`RUNTIME_BOOTSTRAP_IDENTITY_SETTINGS`; personal data, not secrets, never logged; the authproto
  cutover carries them from the Postgres-era `identity_runtime_secret`). An environment value
  wins over wasi:config. The same Secret carries `DI_PGLITE_KEY` (and, during a rotation,
  `DI_PGLITE_KEY_PREVIOUS`) for the [data directory encryption](#data-directory-encryption) layer;
  the guest code never reads them.

wasi:config cannot carry secrets or URLs (the platform rejects them), and tenant admission lets a
workload without an environment label reference only its `<workload>-control` Secret, which
cli-plugin-platform creates for the control token. The guest refuses to boot without
`ISSUER_URL`, `AUTH_PUBLIC_ORIGIN` and `AUTH_ACTIVE_PRIVATE_JWK`: every request answers 503 with
`{"ok":false,"error":"service unavailable","reason":"runtime-settings-missing"}`, and the log
line `identity boot failed: runtime settings missing from the identity-control Secret: <names>`.
Every boot failure answers the same generic body with a coarse `reason`:

| `reason` | Cause |
| --- | --- |
| `runtime-settings-missing` | The runtime settings above are absent |
| `bootstrap-in-progress` | Another realm is running bootstrap (with `Retry-After: 5`) |
| `column-encryption-unavailable` | Column encryption is enabled but unusable |
| `boot-failed` | Any other failure |

The details are only in the log, because a driver message can echo a value.

Every name the Secret may hold is declared in `controlSecretKeys` of
`apps/guest/di-framework.config.json`, so `di-framework platform deploy` keeps `<name>-control` (`identity-control` for the default `name`)
instead of rewriting it with only `DI_CONTROL_TOKEN` and `DI_CONTROL_IDENTITY`. As a tenant
developer it keeps the Secret as it is; as an administrator it carries the declared keys over and
rotates the token. This needs cli-plugin-platform with di-framework/cli-extensions#70 and #72 (the
release after 6.1.2); 6.1.2 does not know `controlSecretKeys` or `pglite.encryption`.
`deploy/guest/deploy.sh <instance> <tenant> <values-file>` (both instance and tenant are
required) runs:

1. checks: `runtime-secrets.ts preflight` reads the values file (mode 0600, known and required
   names) against the guest config: every name declared in `controlSecretKeys`, `DI_PGLITE_KEY`
   present (its KCV is logged), and a plaintext guest only with the explicit development opt-out.
   It prints the workload name, which is the config's `name`. Then `di-tenant-<tenant>` must have
   no Postgres `directory` BackingService (that tenant still runs the Postgres-era guest, as
   authproto's `identity` does; the check reads the cluster, so it holds whichever kubeconfig or
   tenant was passed). The instance `authproto` is refused too, except for the signed-off cutover
   into a new tenant, confirmed with `IDENTITY_AUTHPROTO_CUTOVER=authproto/<tenant>`
   ([authproto cutover](guest-http-api.md#authproto-cutover));
2. `di-framework platform build`, before anything on the cluster changes;
3. `di-framework platform deploy <name> --target identity`;
4. `bun deploy/guest/runtime-secrets.ts apply`, which repeats both checks, writes the whole
   Secret (a fresh control token, the identity, and the values; the guest has no cron or queue
   invokers that use the token) on kubectl's stdin through raw create/replace, which tenant
   developers may use without reading Secrets, and rolls the workload by setting only
   `IDENTITY_RUNTIME_REVISION` in its environment config (the other entries, such as
   `DI_PGLITE_DATA_DIR`, stay).

The values file is only read, so the data directory key in it is the same on every deploy. On a
first deploy the Secret does not exist yet: the CLI creates it with only its control keys, and the
guest answers 503 until step 4 (the encryption layer refuses to start without its key and
changes nothing). On the first deploy of a new workload the CLI's fixed readiness wait (30 x 2 s)
usually ends before the tenant host has rolled to mount the new directory, and step 3 exits 3
with `did not become ready`. `deploy.sh` expects that: it polls the WorkloadDeployment's Ready
condition for up to `IDENTITY_READY_TIMEOUT` seconds (default 300) and goes on to step 4. If the
workload is still not Ready, or step 3 or 4 fails otherwise, it prints the exact recovery command:
fix the cause and run
`bun deploy/guest/runtime-secrets.ts apply --values <file> --kubeconfig <kc> --tenant <tenant>`
on its own; it rewrites the Secret and rolls the workload.

**The key in the cluster is checked before it is replaced.** When the caller may read
`<name>-control` (an administrator's kubeconfig, or the Pulumi program), `apply` compares the KCV
of the `DI_PGLITE_KEY` already there with the values file's. A different key, or a values file
without one, is refused before anything is written, unless the cluster's key is supplied as
`DI_PGLITE_KEY_PREVIOUS` ([rotation](#rotation)); the message shows KCVs only. A tenant
developer may not read Secrets, so for them nothing is compared: `apply` says so, and the KCV it
prints must match your custody record before you run it.

`bun deploy/guest/runtime-secrets.ts generate --out <file> --origin <url> --smtp-host <host>`
creates a values file (mode 0600) for a new instance, including `DI_PGLITE_KEY`, and prints that
key's KCV. The `deploy/platform` Pulumi program does the same with values it keeps in stack
state.

The database is embedded PostgreSQL 17, the `di-framework:pglite` provider composed into the
component at build time (`pglite` in `apps/guest/di-framework.config.json`, pinned by GHCR
digest). Its root is `DI_PGLITE_DATA_DIR` (default `/data/pglite`), inside the workload's
persistent `/data` directory. The tenant host must run the exclusive-instance wash build
(`ghcr.io/di-framework/wash:2.8.0-wasi-tls-exclusive`), which serves the workload from one
component instance so the database has one opener.

## Data directory encryption

The guest's PGlite data directory is **encrypted at rest by default** (identity-server#62,
di-framework/platform#138). `pglite.encryption` in `apps/guest/di-framework.config.json` pins the
platform's `pglite-encfs` layer by digest
(`ghcr.io/di-framework/pglite-encfs@sha256:46863e8b…a5d414`), and `di-framework platform build`
composes it between the pglite provider and the host:

```
guest ──di-framework:pglite──▶ pglite provider ──wasi:filesystem──▶ pglite-encfs ──▶ host
```

The build checks the wiring with an explicit `wac compose` and a fail-closed import allowlist,
and refuses a layer without the `di-framework:pglite-encfs` custom section. Every regular file of
the data directory (tables, catalogs, WAL, configuration) is stored as AES-256-XTS ciphertext
behind a 4 KiB header; directory and file names, sizes and timestamps stay visible. The layer's
design, format and threat model are in di-framework/platform `platform/pglite-encfs/README.md`.

**Two layers.** This is the filesystem half. [Column encryption](#column-encryption) is the other:

| | Data directory (`pglite-encfs`) | Columns (pgcrypto) |
| --- | --- | --- |
| Default | on | off; opt in with `IDENTITY_COLUMN_ENCRYPTION=enabled` |
| Covers | every file of the data directory, including WAL and catalogs | the PII and secret columns listed above, for new writes |
| Protects against | a stolen disk or volume, a leaked snapshot or file-level backup, a storage administrator, another workload mounting the directory | the same, plus `pg_dump` output and anything else that reads rows without the column keys |
| Does not protect against | the host, the wash process, anyone who can read the tenant's Secrets, or the guest itself (it sees plaintext through SQL); tampering is not detected | the live database server or the service process (see [Threat model and logging](#threat-model-and-logging)) |
| Key | `DI_PGLITE_KEY` | `IDENTITY_COLUMN_KEY`, `IDENTITY_BIDX_KEY` |

Use both: the keys are independent, so a leak of one does not expose the others.

**The key.** `DI_PGLITE_KEY` is 32 random bytes, base64, in `<name>-control` with the other
runtime values; the layer reads it from the WASI environment and hides it from the engine. It is
declared in `controlSecretKeys` together with `DI_PGLITE_KEY_PREVIOUS` and every runtime value
(the build refuses an encrypted provider without the declaration).

- `runtime-secrets.ts generate` writes it into a new values file and prints its KCV, never the
  key. For an existing values file of a **new** deployment, `runtime-secrets.ts pglite-key
  --values <file>` adds one when it is missing. Neither ever replaces a key that exists.
- `deploy.sh` and `apply` only read the values file, and refuse one without `DI_PGLITE_KEY`
  before anything on the cluster changes. The Pulumi program generates the key once and keeps it
  in stack state.
- On the first start over an empty directory, the layer writes the `.di-encfs` marker with the
  key's check value and initdb runs on ciphertext. From then on the directory opens only with that
  key.

### Key custody: losing the key loses the data

There is no recovery path. Without `DI_PGLITE_KEY` nobody can read the database, you included.

- **Back up the key separately from the volume backups.** A backup holding both defeats the
  encryption, and a volume backup without the key is useless. Keep it in a password manager or
  vault; a local values file stays at mode `0600`.
- **Record the KCV** (key-check value) with each backup, so you can tell which key opens which
  backup: `bun deploy/guest/runtime-secrets.ts kcv --values <file>` (Pulumi: the
  `pgliteKeyCheckValue` output). It is HKDF-SHA256 of the key, one-way and safe to store, and
  equals bytes 8..24 of the data directory's `.di-encfs` marker. `deploy.sh` and `apply` log it.
- **Never regenerate the key for an existing volume.** A new key does not decrypt the old data.
- Deleting the Secret, or a Secret without the key, is an outage, not data loss, as long as the
  key still exists somewhere: the guest fails closed (below) until the key is back.

### Fail closed

The layer checks the marker before the provider touches the directory:

| State | Result |
| --- | --- |
| marker matches `DI_PGLITE_KEY` | starts |
| empty directory | writes the marker, starts (initdb on ciphertext) |
| marker matches `DI_PGLITE_KEY_PREVIOUS` | rotates (below), starts |
| marker matches neither key, or `DI_PGLITE_KEY` missing or invalid | refused |
| data but no marker (a plaintext directory) | refused |

A refusal locks the directory before anything is written, so the directory is unchanged. The
provider's open fails, and the guest answers every request, `/health` included, with 503
`{"ok":false,"error":"service unavailable","reason":"boot-failed"}`. The tenant host log carries
the layer's reason (for example `pglite-encfs: the data directory was encrypted with a different
key ...`). Restoring the right key and rolling the workload (`runtime-secrets.ts apply`) recovers
it with its data.

### Rotation

A rotation re-wraps each file's data key under the new key; the data is not re-encrypted.

1. In the values file, move the current key to `DI_PGLITE_KEY_PREVIOUS` and put a new key (32
   random bytes, base64, for example `openssl rand -base64 32`) in `DI_PGLITE_KEY`. Back up the
   new key and record its KCV (`runtime-secrets.ts kcv` prints both). `apply`, which rolls the
   workload.
2. At start the layer re-wraps every file header and then flips the marker. The tenant host log
   says `pglite-encfs: key rotation complete: re-wrapped N file keys`. Keep both keys until that
   line: a start with only the old key after a partial sweep fails closed.
3. Remove `DI_PGLITE_KEY_PREVIOUS` from the values file. A tenant developer cannot replace the
   Secret with fewer keys (`tenant-secret-update` refuses a replace that drops a key), so delete
   it first: `kubectl delete secret <name>-control -n di-tenant-<tenant>` (`<name>` is the
   config's `name`, `identity` by default), then `apply`. The
   running instance keeps its environment until `apply` rolls it.

A rotation does not lock out a compromised old key: someone holding it and an old volume image
can still read data written later, because the data keys stay. After a suspected compromise,
move the data to a fresh deployment under a new key (below).

### Existing plaintext deployments

The layer refuses a directory that holds data but no marker, and it never encrypts a plaintext
directory in place. **There is no automatic conversion.** A guest deployed before this change
has a plaintext data directory, so redeploying it with this config fails closed (503) and leaves
the directory as it was. For such a deployment, either:

- **Deploy fresh and move the data:** deploy under a new workload name (a new, empty data
  directory) with a key, then export the data from the old guest and import it into the new one
  through the admin API (organizations, users, clients) or a SQL dump and restore, and retire the
  old workload and its directory. Data in the old directory, its WAL and its backups stays
  plaintext until they are destroyed. An offline converter is tracked in
  di-framework/platform#199 and has not been built.
- **Stay opted out** for now, with the risks of a plaintext directory. Main always builds the
  encrypted guest, so this means deploying that workload from a local or branch copy of the
  config without `pglite.encryption`, with `IDENTITY_PGLITE_PLAINTEXT=1`, as described below,
  on every deploy until you move the data. It is a stopgap for that one deployment, not a
  supported configuration.

### Opting out (development only)

A plaintext data directory takes two explicit steps, and is meant for local development and
tests only:

1. remove `pglite.encryption` from `apps/guest/di-framework.config.json` in a local or branch
   copy (main keeps the encrypted default, and the tests pin it there);
2. deploy with `IDENTITY_PGLITE_PLAINTEXT=1` in the environment of `deploy.sh` or
   `runtime-secrets.ts apply`, and a values file without `DI_PGLITE_KEY` (`generate
   --plaintext-pglite`).

Without the variable, `preflight` and `apply` refuse a config without `pglite.encryption`; with
it, they warn. They also refuse a values file that holds `DI_PGLITE_KEY` for a plaintext build,
because that file belongs to an encrypted directory, which a plaintext provider cannot read. The
tests pin the committed config to the encrypted default.

## Provisioning with Pulumi

`packages/provider` is the `gas` provider in TypeScript. See its README for resources and
configuration. It authenticates as the provisioner client and sends each mutation with an
`Idempotency-Key` equal to the resource URN.
