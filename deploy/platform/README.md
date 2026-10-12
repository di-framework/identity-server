# Identity platform

One Pulumi program builds identity on wasmCloud end to end:

```sh
cd deploy/platform
pulumi install      # once, after cloning
pulumi config set database pglite   # once per stack; see below
pulumi config set tenant <tenant>   # required; never a tenant that runs the Postgres guest
pulumi up
pulumi destroy
```

| Resource | What it does |
| --- | --- |
| `KubeInstance` (`components/kube.ts`) | Downloads the [di-framework-kube](https://github.com/di-framework/kube) release for this machine, verifies it against `checksums.txt`, and caches it. It runs `di-framework-kube up` on create and update, and `down` on delete. kube creates a Kubesolo container, or uses an existing cluster, and installs `@di-framework/platform` with the stack's `tenant` (and a `developer` user in it) and the tenant host image below. |
| `InClusterRegistry` (`components/registry.ts`) | Plain-HTTP OCI registry in the platform namespace: PVC, Deployment, and a ClusterIP Service for component pulls, plus a NodePort Service when a local tenant host image is published. It is skipped when the stack sets an external `registry`. |
| `PublishedImage` (`components/image.ts`) | Only with `tenantHostLocalImage`: publishes that local tenant host build to the registry. The engine saves it as an OCI layout and `oras` copies it through a port-forward. |
| `DeploymentPatch` `tenant-host-rollout` | Switches the tenant host to stop-then-start updates, because the tenant quota has no room for a second host pod, and so two hosts never open the database at once. With a published local image, it also rolls the host whenever that image's digest changes. |
| `CliWorkload` (`components/workload.ts`) | The identity component, with the pglite provider composed in. It runs `di-framework platform deploy identity` when its sources change, and `di-framework platform destroy identity` on delete. |
| `Mailpit` (`components/mailpit.ts`) | SMTP relay in `di-tenant-identity` on a fixed ClusterIP, plus the platform egress grant that lets the guest dial it. Skipped when `smtpHost` is set. |
| `RandomPassword`, `tls.PrivateKey` | Bootstrap passwords, client secrets, the SMTP password, and the RS256 signing key, generated once and kept in state. |
| `RuntimeSecrets` (`components/secrets.ts`) | Writes those values to the workload's `identity-control` Secret after every deploy, rolls the workload onto them, and waits until `/health` answers 200. |

`pulumi up` creates them in that order and `pulumi destroy` removes them in reverse.

## How the deploy works

`di-framework platform deploy` builds `apps/guest` into a Wasm component, composes the
pglite provider into it (pulled from GHCR by the digest in `apps/guest/di-framework.config.json`),
and pushes it with `oras`. It then applies the `WorkloadDeployment`, `Service`, and bindings in
`di-tenant-identity`. The CLI keeps owning those generated manifests; the
`CliWorkload` resource only decides when to run it.

- **Change detection.** The resource's input is a sha256 over `apps/`, `packages/`,
  `package.json`, `bun.lock`, `tsconfig.json`, and `di-framework.deploy.toml`. It skips
  `node_modules`, build output, and tests. `pulumi up` redeploys only when that
  digest changes.
- **Registry access.** With the in-cluster registry, the resource holds a
  `kubectl port-forward` to `127.0.0.1:<registryForwardPort>` for the length of the
  deploy, because Kubesolo publishes only the HTTP gateway port. Hosts pull from the
  registry Service's cluster DNS name.
- **Connection.** The resource passes the kube kubeconfig, context, and registry to the
  CLI through the variables `di-framework.deploy.toml` interpolates for target
  `identity`.

## Logs

Pulumi dynamic providers cannot stream output, so the kube and deploy steps run
quietly. A fresh kube instance takes several minutes. Their output goes to the system
temp directory:

- `di-framework-kube-<instance>-up.log` and `-down.log`
- `di-framework-deploy-identity.log` and `di-framework-destroy-identity.log`

A failure reports the log path, its last lines, and the CLI's error message.

## Database

The guest runs on embedded PostgreSQL 17: the `di-framework:pglite` provider component
(platform repo, `platform/pglite-component`), which `di-framework platform build` composes into
the guest from `ghcr.io/di-framework/pglite-component`, pinned by digest in
`apps/guest/di-framework.config.json` (`pglite.image`). There is no Postgres BackingService and no
database network endpoint. The CLI renders the workload with one replica, `deployPolicy:
Recreate`, the platform's persistent storage at `/data`, `DI_PGLITE_DATA_DIR=/data/pglite`, and
the `di-framework.dev/exclusive-instance` component config, so the host serves every request from
one component instance that holds the database's single connection.

The data directory is a host path the platform manages for the workload, not a PVC. Back it up
at the file level; the backup agent's `pg_dump` over the network does not apply. Encryption at
rest is planned as a separately composed `wasi:filesystem` layer between the guest and the
provider, which is why the provider stays a separate component.

## Tenant host image

The identity component imports `wasi:tls`, which the stock `ghcr.io/wasmcloud/wash:2.8.0`
host does not provide, and its database needs the exclusive-instance pool policy. The tenant
host runs the platform repo's `platform/tenant-host` build instead: wash 2.8.0 with the
`wasi-tls` feature and patches 0001 (exclusive instance) and 0002 (insecure-registry allowlist),
published as `ghcr.io/di-framework/wash:2.8.0-wasi-tls-exclusive` for amd64 and arm64. The
program pins it by digest with pull policy `IfNotPresent`. Set `tenantHostImage` to run a
different pullable image; without the exclusive patch, `platform deploy` warns and concurrent
requests can open the database twice.

To try an unpublished host build, build it and name it in `tenantHostLocalImage`:

```sh
# In the platform repo
podman build -t localhost/di-framework/wash:2.8.0-wasi-tls platform/tenant-host
# Here
pulumi config set tenantHostLocalImage localhost/di-framework/wash:2.8.0-wasi-tls
```

The program publishes it to the in-cluster registry, and the node pulls it from
`127.0.0.1:<registryNodePort>`, which Kubesolo's containerd allows over plain HTTP because it
is a loopback address. Each rebuild rolls the host.

## Prerequisites

- The Pulumi CLI, Node.js, npm, and Bun. kube runs its own Pulumi project with
  Node.js and npm. The program uses Bun as its package manager.
- For a local Kubesolo container, a Docker-compatible engine on the Docker socket.
  kube publishes builds for macOS and Linux on amd64 and arm64.
- `kubectl` and `oras`, and the `di-framework` CLI with the platform extension. The
  program uses the repo's `node_modules/.bin/di-framework` when it exists.
- With `tenantHostLocalImage`, Podman or Docker holding that image.

## Stack config

`database` is required and must be `pglite`. Earlier versions of this program ran the guest on
a Postgres BackingService; updating such a stack deletes that BackingService and starts the guest
on an empty pglite database. That is the authproto cutover, which needs its own sign-off
(`docs/guest-http-api.md#authproto-cutover`), so every stack opts in explicitly. Do not set it on
a stack that still runs the Postgres guest. `tenant` is required too and has no default
(authproto's tenant is `identity`). All other keys are optional.

| Key | Default | Purpose |
| --- | --- | --- |
| `kubeVersion` | `latest` | kube release tag; pin one, such as `v0.0.4`, for repeatable runs |
| `kubeBinary` | unset | Local kube build instead of a release download |
| `kubeInstance` | `identity` | kube instance name; use one per environment |
| `kubeStateDir` | kube's default | kube `--state-dir` |
| `kubeconfig`, `context` | unset | Install onto this existing cluster instead of Kubesolo |
| `httpPort` | `28180` | Gateway port of a new Kubesolo container, fixed at creation |
| `platformPackage` | `@di-framework/platform@6.0.11` | Platform package kube installs |
| `values` | unset | List of administrator Helm values documents |
| `purgeClusterOnDestroy` | `false` | Also delete the Kubesolo cluster and its data on destroy |
| `registry` | unset | `{ push, pull }` of an external registry; skips the in-cluster one |
| `registryForwardPort` | `25180` | Loopback port for pushes to the in-cluster registry |
| `registryStorageClass` | cluster default | StorageClass for the in-cluster registry |
| `tenantHostImage` | `ghcr.io/di-framework/wash:2.8.0-wasi-tls-exclusive` by digest | Tenant host image the nodes pull |
| `tenantHostLocalImage` | unset | Local engine image to publish and run as the tenant host instead |
| `registryNodePort` | `30500` | NodePort the node pulls a published local host image through |
| `containerEngine` | first of `podman`, `docker` that answers | Engine that holds `tenantHostLocalImage` |
| `platformNamespace` | `wasmcloud` | Namespace kube installs the platform into |
| `publicOrigin` | `url` output | identity's public origin |
| `issuerUrl` | `publicOrigin` | OIDC issuer |
| `accessRedirectUris` | `http://localhost:3000/callback` | Access client redirect URIs |
| `smtpHost` | in-cluster Mailpit | External mail relay host; skips Mailpit and its egress grant |
| `mailpitClusterIP` | `10.43.250.25` | Mailpit's fixed ClusterIP; must sit in the cluster's Service range |
| `workloadForwardPort` | `25181` | Loopback port for reaching the workload through `di-http` |

With `latest`, each `up` looks up the newest kube release. A newer release changes the
kube resource's inputs, and the next `up` reruns `di-framework-kube up` with it. Set
`GITHUB_TOKEN` if the GitHub API rate limit gets in the way.

A shared environment on an existing cluster with an external registry:

```sh
pulumi stack init staging
pulumi config set kubeVersion v0.0.4
pulumi config set kubeInstance identity-staging
pulumi config set kubeconfig /secure/staging.kubeconfig
pulumi config set --path registry.push https://ghcr.io/acme
pulumi config set --path registry.pull ghcr.io/acme
pulumi up
```

## Outputs

| Output | Value |
| --- | --- |
| `kubeconfig`, `context` | Admin kubeconfig path in kube's state directory, and its context |
| `namespace` | Platform namespace |
| `registry` | Push and pull references the deploy used |
| `image` | Pull reference of the deployed identity component |
| `tenantHostImage` | Image reference the tenant host runs |
| `url` | Tenant route through the gateway, such as `http://identity.identity.localhost:28180` |
| `signingKeyId` | `kid` of the active signing key |
| `bootstrapOwnerPassword`, `bootstrapViewerPassword` | Secret. Passwords of the bootstrap `owner` and `viewer` |
| `accessClientSecret`, `directoryClientSecret`, `provisionerClientSecret` | Secret. Bootstrap client secrets |

```sh
kubectl --kubeconfig "$(pulumi stack output kubeconfig)" -n di-tenant-identity get workloaddeployments
curl "$(pulumi stack output url)/health"
```

## Runtime secrets

The guest reads the issuer URL, public origin, signing key, SMTP host and password,
bootstrap passwords, and client secrets from its WASI environment, which the platform fills
from the workload's `identity-control` Secret (`localResources.environment.secretFrom`).
wasi:config refuses secrets and URLs, and tenant admission lets a workload without an
environment label reference only its `<workload>-control` Secret. Nothing secret is stored in
the database; migration `V16` removes what the earlier Postgres guest kept there.

The program generates the values with `@pulumi/random` and `@pulumi/tls` and keeps them,
encrypted, in stack state. `di-framework platform deploy` rewrites `identity-control` on every
deploy with only its control token, so `RuntimeSecrets` writes the whole Secret again after each
deploy (a fresh control token, the identity, and the values, sent to kubectl on stdin), sets
`IDENTITY_RUNTIME_REVISION` in the workload's environment config to roll it, and waits up to 10
minutes for `/health`. Until then the guest answers 503 and names the missing settings; it never
starts with the default issuer or without a signing key.

```sh
pulumi stack output --show-secrets bootstrapOwnerPassword
```

To rotate a value, replace its resource: `pulumi up --replace <urn>`.

Before it deletes or writes `identity-control`, the program checks that `di-tenant-<tenant>` has
no Postgres `directory` BackingService and refuses the tenant otherwise (on an existing cluster
named by `kubeconfig`, it checks before anything else runs, `kube up` included).

> **Status:** this Pulumi path (`tenant`, the tenant check, `resetControlSecret`, `deployedAt`
> and the always-rolling `RuntimeSecrets`) has been type-checked only. It has not run against a
> live cluster yet; the live proof used `deploy/guest/deploy.sh`. Treat the first fresh-stack
> `pulumi up` as its test.

Without Pulumi, `deploy/guest/deploy.sh <instance> <tenant> <values-file>` does the same steps;
`bun deploy/guest/runtime-secrets.ts generate` creates a values file. See
`docs/configuration.md#wasmcloud-guest`.

## Mail

Mailpit catches everything identity sends. Open its UI with:

```sh
kubectl --kubeconfig "$(pulumi stack output kubeconfig)" -n di-tenant-identity \
  port-forward service/mailpit 8025:8025
```

Tenant hosts run wash with `--socket-egress=enforce`: a guest may resolve and dial only
what a platform egress grant approves, and the approval for a private address must be a
literal `ip:port`. So Mailpit's Service has a fixed ClusterIP, kube puts
`<ip>:1025` in the platform's `egressAllowedDestinations`, and the program creates an
`egress` BackingService and a ServiceBinding for the identity workload. The guest's
`SMTP_HOST` is that IP. `egressAllowedDestinations` needs kube v0.0.4 or newer.

## Known issues

- `latest` needs the GitHub API. When it fails, the program retries, then falls back to the
  newest cached kube release with a warning.
- Changing the platform config restarts the platform controller, which then recreates the
  user token Secret. Until it does, kube fails with
  `di-user-<user>-<tenant>-token ... does not exist`; that can take a few minutes. Wait for
  the Secret in the platform namespace, then run `pulumi up` again. The platform README
  documents this.
- A `di-framework platform deploy` run outside this program resets `identity-control` to the CLI's
  control token only. The guest then answers 503 until the next `pulumi up` (or
  `deploy/guest/runtime-secrets.ts apply`) writes the values again.
- Stacks created before the switch to pglite still have the `directory` BackingService in state.
  The next `pulumi up` deletes it; with `databaseDeletionPolicy` `Retain` (the old default) the
  platform keeps its data. Export anything you need first: the pglite guest starts from an empty
  database (see `docs/guest-http-api.md#authproto-cutover`).

## State

`Pulumi.yaml` keeps state in `.pulumi-state/` next to the program. Set
`PULUMI_CONFIG_PASSPHRASE` or answer the prompt. For shared environments, run
`pulumi login` with a shared backend and remove the `backend` entry, or set
`PULUMI_BACKEND_URL`.

kube keeps the cluster and platform state in its state directory, including its own
Pulumi project and the admin kubeconfig. Back up both. kube's ownership claim on a
cluster is released only by a successful `down`, which `pulumi destroy` runs. If an
update fails, run `pulumi up` again; never delete state to get past the claim.
Downloaded kube binaries are cached in `di-framework-kube/<version>/` under
`$XDG_CACHE_HOME`, or `~/.cache` when it is unset.

`.pulumi-state/` may still hold a stack for the earlier SSH project,
`di-framework-wasmcloud-identity-server-b36cba8af7`. This project has a different name
and never touches it.
