# Example auth stack

`examples/compose.yml` runs four processes:

| Service | Role |
| --- | --- |
| `postgres` | Database for the identity JSON API |
| `identity` | Native `@di-framework/identity-server` image |
| `app` | Small application using `@di-framework/auth` |
| `verify` | Checks the running stack, then exits |

Build the Linux executables first. The Dockerfiles only copy binaries that are already on disk.

```bash
bun apps/server/build.ts --docker
bun examples/app/build.ts --docker
podman compose -f examples/compose.yml up --build --abort-on-container-exit --exit-code-from verify
```

`AUTH_SECRET` in the compose file is an example value. Replace it before any shared or production deployment. It must be at least 32 characters.

The example app mounts `@di-framework/auth` at `/auth` and protects `GET /me`. Passwords must be at least 15 characters. Session cookies use the `__Host-` prefix: `Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, and no `Domain`.

`examples/verify.ts` waits until both servers answer, then checks:

- The identity sign-in cookie is `HttpOnly`, `Path=/`, and `SameSite=Lax`.
- A sign-in POST without the CSRF token does not create a session.
- A sign-in POST with the token does, and that session can open the user list.
- The example app rejects a short password and does not echo the password.
- Registration sets a `__Host-sid` cookie with the attributes above.
- `/me` is 401 without a session and 401 with a forged cookie.
- A wrong password returns "Invalid credentials" and does not set a session cookie.
- Logout expires the cookie and the old session no longer opens `/me`.

The identity JSON API under `/api/` is the control plane. This service does not authenticate those routes. The example checks that the browser sign-in and the example app session behave as described. It does not add an authorization layer to `/api/`.

The browser screens keep their own in-memory directory inside the identity process. The JSON API reads and writes Postgres.
