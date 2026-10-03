# Native executable

`apps/server/build.ts` builds the browser client, stages the sign-in page and the SQL migrations, then compiles `@di-framework/identity-server` into one executable. It emits the TypeScript with `tsc` first so constructor injection is still present in the executable. The executable contains the Bun runtime. A machine that runs it does not need Bun or `node_modules`.

Run `bun run generate:api` first when the schema manifests changed. That refreshes the generated controllers and the local OpenAPI document. The OpenAPI document is not committed.

```bash
bun apps/server/build.ts
```

That writes `apps/server/dist/identity-server` for the machine running the build.

The image runs Linux. Pass `--docker` so the executable targets `bun-linux-arm64` or `bun-linux-x64` to match this machine:

```bash
bun apps/server/build.ts --docker
```

`IDENTITY_TARGET` overrides the target, for example `bun-linux-x64`.

`apps/server/Dockerfile` copies that executable into a Debian image and runs it as the `identity` user. It listens on `0.0.0.0` and `PORT` (4180 in the image). On startup it opens Postgres from `DATABASE_URL` or `IDENTITY_DATABASE__URL`, applies the embedded SQL migrations, validates `AUTH_ACTIVE_PRIVATE_JWK`, reconciles the bootstrap owner, organization, and clients, and starts the security-notification worker. It exits if any of those fail. [Configuration](configuration.md) lists every variable.

```bash
podman build -t identity-server -f apps/server/Dockerfile apps/server
```

The framework packages this workspace links (`@di-framework/core`, `http`, `repo`, `config`, `authz`) are bundled into the executable at build time. The image build does not install them again.
