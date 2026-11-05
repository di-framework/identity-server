# Identity service docs

- [Configuration and operations](configuration.md) — environment variables, startup, endpoints, local stack
- [Admin API: OAuth clients](admin-oauth-clients.md) — tenant client registration: audiences, public PKCE clients, idempotent creates
- [Native executable and image](native-executable.md) — `apps/server/build.ts` and the Dockerfile
- [Example](example.md) — identity compose file, and the example app journey tests
- [Guest HTTP API](guest-http-api.md) — the wasmCloud guest: the Postgres-era deploy on tenant `identity`, the move to pglite (identity-server#50) with its proof, and the pending authproto cutover
