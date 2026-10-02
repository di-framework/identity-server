# @di-framework/identity

> Status: Incubating

`@di-framework/identity` is an identity control-plane service that stores directory, OAuth client, audit, and identity-link records in Postgres and serves them as a JSON HTTP API. Operators need a single place to create users and organizations, manage memberships and OAuth clients, and record who changed them. The service is a Bun and TypeScript workspace. Domain services sit behind repository ports, HTTP routes come from `@di-framework/http`, and the database URL comes from `@di-framework/config`.

The workspace compares the OpenAPI document emitted by the HTTP controllers with the local API spec, and it requires 100% line coverage from `bun test`.

## Getting Started

Prerequisites: [Bun](https://bun.sh) and [Podman](https://podman.io). Framework packages install from npm.

Start Postgres with the Compose file in this repository. The database, user, and password are `identity`, and the server listens on port 5432.

```bash
podman compose up -d
bun install
bun test
bun typecheck
```

`DATABASE_URL` overrides the Postgres URL. `IDENTITY_DATABASE__URL` sets the same value through `@di-framework/config`. When neither is set, the default is `postgres://identity:identity@127.0.0.1:5432/identity`.

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
| `@di-framework/identity-server` | `apps/server` | Serves the client and the JSON API on one port |

## Screens

![Sign in](docs/images/sign-in.png)

![Users](docs/images/users.png)

![Organizations](docs/images/organizations.png)

![OAuth clients](docs/images/oauth-clients.png)

![Linked identities](docs/images/linked-identities.png)

## Contributing

A `CONTRIBUTING.md` file is not in this repository yet. Changes are expected to keep `bun test` and `bun x tsc --noEmit` passing. The pre-commit hook typechecks and runs Biome on staged files. The pre-push hook runs the test suite.

## Scope

* Users, organizations, memberships, and directory member pages
* OAuth client create, update, secret rotation, and revoke
* Audit listing and identity-link list, prepare-unlink, and unlink
* Postgres persistence with versioned SQL migrations
* An emitted OpenAPI document checked against the JSON operations in the local spec

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
* [TODO](TODO.md)
* [Build and example stack](docs/README.md)
* Repository layout: `packages/core`, `packages/migrations`, `packages/codegen`, `apps/api`, `apps/client`, `apps/server`

## License

This project is licensed under the [ISC License](LICENSE).

