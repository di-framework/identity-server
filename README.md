# Welcome to the @di-framework/identity Project!

`@di-framework/identity` is an identity control-plane service that stores directory, OAuth client, audit, and identity-link records in Postgres and serves them as a JSON HTTP API. Operators need a single place to create users and organizations, manage memberships and OAuth clients, and record who changed them. The service is a Bun and TypeScript workspace. Domain services sit behind repository ports, HTTP routes come from `@di-framework/http`, and the database URL comes from `@di-framework/config`.

The workspace compares the OpenAPI document emitted by the HTTP controllers with the local API spec, and it requires 100% line coverage from `bun test`.

## Getting Started

Prerequisites: [Bun](https://bun.sh), [Podman](https://podman.io), and the sibling `di-framework` packages linked on this machine (`@di-framework/cli`, `config`, `core`, `http`, and `repo`).

Start Postgres with the Compose file in this repository. The database, user, and password are `identity`, and the server listens on port 5432.

```bash
podman compose up -d
bun install
bun test
bun typecheck
```

`DATABASE_URL` overrides the Postgres URL. `IDENTITY_DATABASE__URL` sets the same value through `@di-framework/config`. When neither is set, the default is `postgres://identity:identity@127.0.0.1:5432/identity`.

Generate the checked-in OpenAPI types after the local spec is present at `apps/api/api/v1/openapi.yaml`:

```bash
bun run generate:types
```

That spec is generated locally and is not committed. `bun run lint` runs Biome.

| Package | Path | Role |
| --- | --- | --- |
| `@di-framework/identity` | `packages/core` | Directory, OAuth, audit, and identity-link domain services |
| `@di-framework/identity-migrations` | `packages/migrations` | Versioned Flyway SQL and the migration runner |
| `@di-framework/identity-codegen` | `packages/codegen` | OpenAPI projection and generated contract types |
| `@di-framework/identity-api` | `apps/api` | JSON control-plane HTTP handlers |
| `@di-framework/identity-client` | `apps/client` | UI application. No screens are implemented yet |
| `@di-framework/identity-server` | `apps/server` | Serves the client and the JSON API on one port |

## Contributing

A `CONTRIBUTING.md` file is not in this repository yet. Changes are expected to keep `bun test` and `bun x tsc --noEmit` passing. The pre-commit hook typechecks and runs Biome on staged files. The pre-push hook runs the test suite.

## Scope

### In Scope

`@di-framework/identity` is intended to serve the JSON admin control plane. The project implements:

* Users, organizations, memberships, and directory member pages
* OAuth client create, update, secret rotation, and revoke
* Audit listing and identity-link list, prepare-unlink, and unlink
* Postgres persistence with versioned SQL migrations
* An emitted OpenAPI document checked against the JSON operations in the local spec

### Out of Scope

`@di-framework/identity` is an identity service, not the dependency-injection framework. The framework packages live in the `di-framework` repository. This service will not incorporate:

* Browser and HTML routes, including login, consent, passwordless sign-in, `/health`, and `/ready`
* OAuth scope checks on the admin API
* Passwordless email invitations
* End-user UI screens in `@di-framework/identity-client`

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

## Conduct

This repository does not include a `CODE_OF_CONDUCT.md` file yet. The README layout follows the [CNCF project README template](https://github.com/cncf/project-template/blob/main/README-template.md). The CNCF Code of Conduct is published at <https://github.com/cncf/foundation/blob/main/code-of-conduct.md>.
