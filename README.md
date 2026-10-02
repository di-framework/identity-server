# @di-framework/identity

> Status: Incubating

`@di-framework/identity` is an identity provider and control plane on Postgres. It is an OAuth 2 / OpenID Connect authorization server (authorization code with PKCE, consent, refresh rotation, client credentials, opaque access tokens, RS256 or ML-DSA-65 ID tokens), a scope-protected JSON admin API for users, organizations, memberships, OAuth clients, and audit records, and the PatternFly sign-in, admin, and account pages. Its behavior follows the GSIO Auth Server; `docs/internal/parity.md` tracks each surface. The service is a Bun and TypeScript workspace. Domain services sit behind repository ports, HTTP routes come from `@di-framework/http`, authorization rules are `@di-framework/authz` policies, and settings come from `@di-framework/config`.

The workspace compares the OpenAPI document emitted by the HTTP controllers with the local API spec, and it requires 100% line coverage from `bun test`.

## Getting Started

Prerequisites: [Bun](https://bun.sh) and [Podman](https://podman.io). Framework packages install from npm. The pre-commit hook also runs [Semgrep](https://semgrep.dev) when it is installed (`brew install semgrep` or `pipx install semgrep`); its rulesets download from the Semgrep registry on each run.

Start Postgres with the Compose file in this repository. The database, user, and password are `identity`, and the server listens on port 5432.

```bash
podman compose up -d
bun install
bun test
bun typecheck
```

`DATABASE_URL` overrides the Postgres URL. `IDENTITY_DATABASE__URL` sets the same value through `@di-framework/config`. When neither is set, the default is `postgres://identity:identity@127.0.0.1:5432/identity`. The Compose file also starts Mailpit for local mail.

`bun start` needs a signing key and bootstrap settings. [Configuration and operations](docs/configuration.md) lists every variable and a complete local command.

`di-framework generate` writes the HTTP controllers from the schema manifests in `apps/api/src/contracts`. `bun run generate:api` does that, then writes `apps/api/api/v1/openapi.yaml` from the generated `@Endpoint` metadata. Tests write that spec before they run. The spec is not committed.

```bash
bun run generate:api
bun run generate:types
```

`bun run lint` runs Biome.

| Package | Path | Role |
| --- | --- | --- |
| `@di-framework/identity` | `packages/core` | Directory, OAuth, audit, and identity-link domain services |
| `@di-framework/identity-migrations` | `packages/migrations` | Versioned Flyway SQL and the migration runner |
| `@di-framework/identity-codegen` | `packages/codegen` | OpenAPI projection and generated contract types |
| `@di-framework/identity-api` | `apps/api` | JSON control-plane HTTP handlers |
| `@di-framework/identity-client` | `apps/client` | PatternFly screens for sign-in, the directory, and the account |
| `@di-framework/identity-server` | `apps/server` | Serves the pages, the OAuth endpoints, and the JSON API on one port |
| `@di-framework/identity-provider` | `packages/provider` | `gas` Pulumi provider for the admin API |

## Screens

![Sign in](docs/images/sign-in.png)

![Users](docs/images/users.png)

![Organizations](docs/images/organizations.png)

![OAuth clients](docs/images/oauth-clients.png)

![Linked identities](docs/images/linked-identities.png)

## Contributing

A `CONTRIBUTING.md` file is not in this repository yet. Changes are expected to keep `bun test` and `bun x tsc --noEmit` passing. The pre-commit hook typechecks, runs Biome on staged files, and runs Semgrep on staged files (skipped with a warning when `semgrep` is not installed). `bun run semgrep` scans the whole repository. The pre-push hook runs the test suite.

## Scope

* OAuth 2 / OIDC authorization server: authorize, consent, token, introspection, revocation, UserInfo, JWKS, and discovery
* Form login, Argon2 passwords, passwordless email links, and Postgres browser sessions
* Users, organizations, memberships, OAuth clients, and audit in the JSON admin API and the HTML admin
* Linked external identities with step-up unlinking and security-notification mail
* Bootstrap of the first owner, organization, and clients; `/health` and `/ready`
* A `gas` Pulumi provider that provisions through the admin API
* Postgres persistence with versioned SQL migrations and an emitted OpenAPI document

## Communications

No public mailing list, chat channel, or meeting is set up for this repository.

* User mailing list: none
* Developer mailing list: none
* Slack channel: none
* Public meeting schedule: none
* Social media: none

## Resources

Roadmap, adopters, release notes, and a security policy are not in this repository yet.

* [di-framework documentation](https://docs.di-framework.dev)
* [Build and example stack](docs/README.md)
* Repository layout: `packages/core`, `packages/migrations`, `packages/codegen`, `apps/api`, `apps/client`, `apps/server`

## License

This project is licensed under the [ISC License](LICENSE).

