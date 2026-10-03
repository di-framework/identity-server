# Baremetal wasmCloud platform

This Pulumi project installs `@di-framework/platform` 6.0.5 on the SSH host
from stack config `sshHost` and `sshUser`. k0s is adopted when it is already running (`owned=0`);
this stack resets k0s only when it created the installation (`owned=1`).

`di-framework platform cluster up` runs this project. Application workloads stay
out of it.

## State

The CLI uses a file backend at `.pulumi-state/` and passphrase `local-dev`
unless `PULUMI_BACKEND_URL` or `PULUMI_CONFIG_PASSPHRASE` is already set.

From the identity-server repo root:

```sh
di-framework platform cluster up --yes
```

## Ports

| Setting | Value | Purpose |
| --- | ---: | --- |
| `apiPort` | `6443` | Kubernetes API on the host |
| `registryPort` | `30500` | NodePort for the in-cluster OCI registry |
| `httpPort` | `30180` | NodePort for the wasmCloud HTTP entrypoint |

## Tenant

Stack `dev` declares tenant `identity`. The developer kubeconfig is the `users`
entry whose membership on that tenant has role `developer`. Workloads use
`di-tenant-identity` and host group `tenant-identity`. The admin kubeconfig is
`.kubeconfig-dev`. The developer kubeconfig is `.kubeconfig-dev-identity`.

The host group runs `ghcr.io/di-framework/wash:2.8.0-wasi-tls` (`tenantHostImage`,
pull policy `IfNotPresent`). That image is the platform `tenant-host` build
(`--features wasi-tls`, including the postgres invocation-lease patch) and links
`wasi:tls/client@0.3.0-draft`. `createPlatform` otherwise defaults to
`ghcr.io/wasmcloud/wash:2.8.0`, which does not. The tag is pinned until
platform#28 records a digest; then set `tenantHostImage` to `image@sha256:…`.
Use `Always` only when overriding the image to a mutable local tag.

PostgreSQL uses the cluster default StorageClass (`local-path` on this host).
`createPlatform` seeds `postgres-dedicated` without its own `storageClassName`.

Tenant HTTP routes use `Host: <workload>.identity.localhost` on port `30180`.
That gateway rewrites the host to the workload name and forwards to
`di-http` in `di-runtime-identity`. A host without the `.identity.localhost`
suffix reaches the default host group instead.

`dnsSinkZone`, when set, adds a CoreDNS zone that answers NXDOMAIN. Use it when
pod search includes a LAN zone that still resolves stale cluster names. The
zone is stack config, not a name compiled into this program.
