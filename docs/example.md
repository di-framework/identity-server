# Example

`examples/compose.yml` runs the identity server and its database.

| Service | Role |
| --- | --- |
| `postgres` | Database for the identity JSON API |
| `identity` | Native `@di-framework/identity-server` image |

Build the Linux executable first. The Dockerfile copies a binary that is already on disk.

```bash
bun apps/server/build.ts --docker
podman compose -f examples/compose.yml up --build
```

The identity server listens on port 4180. Browser screens for the directory, audit log, and linked identities call the JSON API through a client generated from the OpenAPI document (`openapi-typescript` and `openapi-fetch`). That API reads and writes Postgres. Sign-in, passwordless links, and consent stay in the server process. Routes under `/api/` do not authenticate callers.

The example application in `examples/app` uses `@di-framework/auth`. Run it on the host so the issuer host is the host the browser uses:

```bash
AUTH_SECRET=example-only-secret-not-for-production-use bun examples/app/src/main.ts
```

`AUTH_SECRET` must be at least 32 characters. The value above is an example. Replace it before any shared or production deployment. `AUTH_ISSUER` defaults to `http://127.0.0.1:3000`.

The app mounts `@di-framework/auth` at `/auth` and protects `GET /me`. Passwords must be at least 15 characters. Session cookies use the `__Host-` prefix: `Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, and no `Domain`.

`examples/app/src/journey.test.ts` walks that journey. A short password is rejected and is not echoed. Registration sets the session cookie. `/me` rejects a missing or forged cookie. A wrong password returns "Invalid credentials" and does not set a session. Logout revokes the session. An unexpected failure returns "Internal Server Error" and leaves the internal message in the log. `bun test` runs the journey.

A Linux binary of the example app is optional and is separate from the compose file:

```bash
bun examples/app/build.ts --docker
```

`examples/app/Dockerfile` copies that binary.
