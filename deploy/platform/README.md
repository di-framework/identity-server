# Identity platform

One Pulumi program builds identity on wasmCloud end to end:

```sh
cd deploy/platform
pulumi install      # once, after cloning
pulumi up
pulumi destroy
```

| Resource | What it does |
| --- | --- |
| `KubeInstance` (`components/kube.ts`) | Downloads the [di-framework-kube](https://github.com/di-framework/kube) release for this machine, verifies it against `checksums.txt`, and caches it. It runs `di-framework-kube up` on create and update, and `down` on delete. kube creates a Kubesolo container, or uses an existing cluster, and installs `@di-framework/platform` with the tenants in `platform.json` and the tenant host image below. |
| `InClusterRegistry` (`components/registry.ts`) | Plain-HTTP OCI registry in the platform namespace: PVC, Deployment, and a ClusterIP Service for component pulls, plus a NodePort Service when a local tenant host image is published. It is skipped when the stack sets an external `registry`. |
| `PublishedImage` (`components/image.ts`) | Only with `tenantHostLocalImage`: publishes that local tenant host build to the registry. The engine saves it as an OCI layout and `oras` copies it through a port-forward. |
| `DeploymentPatch` `tenant-host-rollout` | Switches the tenant host to stop-then-start updates, because the tenant quota has no room for a second host pod. With a published local image, it also rolls the host whenever that image's digest changes. |
| `BackingService` `directory` | The tenant's Postgres, provisioned by the platform controller. Pulumi waits for `Ready`. |
| `CliWorkload` (`components/workload.ts`) | The identity component. It runs `di-framework platform deploy identity` when its sources change, and `di-framework platform destroy identity` on delete. |
| `Mailpit` (`components/mailpit.ts`) | SMTP relay in `di-tenant-identity` on a fixed ClusterIP, plus the platform egress grant that lets the guest dial it. Skipped when `smtpHost` is set. |
| `RandomPassword`, `tls.PrivateKey` | Bootstrap passwords, client secrets, the SMTP password, and the RS256 signing key, generated once and kept in state. |
| `RuntimeSecrets` (`components/secrets.ts`) | Writes those values to the guest's `identity_runtime_secret` table and waits until `/health` answers 200. |
| `DeploymentPatch` `tenant-host-secrets` | Restarts the tenant host when the values change, so the guest boots with them. |

`pulumi up` creates them in that order and `pulumi destroy` removes them in reverse.

## How the deploy works

`di-framework platform deploy` builds `apps/guest` into a Wasm component and pushes
it with `oras`. It then applies the `WorkloadDeployment`, `Service`, and bindings in
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

## Tenant host image

The identity component imports `wasi:tls`, which the stock `ghcr.io/wasmcloud/wash:2.8.0`
host does not provide. The tenant host runs the platform repo's `platform/tenant-host` build
instead: wash 2.8.0 with the `wasi-tls` feature and the Postgres invocation-lease patch,
published as `ghcr.io/di-framework/wash:2.8.0-wasi-tls` for amd64 and arm64. The program
pins it by digest with pull policy `IfNotPresent`. Set `tenantHostImage` to run a different
pullable image.

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

All keys are optional.

| Key | Default | Purpose |
| --- | --- | --- |
| `kubeVersion` | `latest` | kube release tag; pin one, such as `v0.0.4`, for repeatable runs |
| `kubeBinary` | unset | Local kube build instead of a release download |
| `kubeInstance` | `identity` | kube instance name; use one per environment |
| `kubeStateDir` | kube's default | kube `--state-dir` |
| `kubeconfig`, `context` | unset | Install onto this existing cluster instead of Kubesolo |
| `httpPort` | `28180` | Gateway port of a new Kubesolo container, fixed at creation |
| `platformPackage` | `@di-framework/platform@6.0.5` | Platform package kube installs |
| `values` | unset | List of administrator Helm values documents |
| `purgeClusterOnDestroy` | `false` | Also delete the Kubesolo cluster and its data on destroy |
| `registry` | unset | `{ push, pull }` of an external registry; skips the in-cluster one |
| `registryForwardPort` | `25180` | Loopback port for pushes to the in-cluster registry |
| `registryStorageClass` | cluster default | StorageClass for the in-cluster registry |
| `tenantHostImage` | `ghcr.io/di-framework/wash:2.8.0-wasi-tls` by digest | Tenant host image the nodes pull |
| `tenantHostLocalImage` | unset | Local engine image to publish and run as the tenant host instead |
| `registryNodePort` | `30500` | NodePort the node pulls a published local host image through |
| `containerEngine` | first of `podman`, `docker` that answers | Engine that holds `tenantHostLocalImage` |
| `platformNamespace` | `wasmcloud` | Namespace kube installs the platform into |
| `databaseDeletionPolicy` | `Retain` | `Delete` also removes the `directory` database's data on destroy |
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
bootstrap passwords, and client secrets from the `identity_runtime_secret` table in the
`directory` database (`V13__runtime_secrets.sql`), because wasi:config refuses them.

The program generates them with `@pulumi/random` and `@pulumi/tls` and keeps them,
encrypted, in stack state. The database's network policy admits only host pods, so
`RuntimeSecrets` writes the rows with `psql` inside the Postgres pod through
`kubectl exec`. It manages only its own row names and leaves the guest's bootstrap
fingerprint alone. It then waits up to 10 minutes for `/health`, since the first boot
hashes the bootstrap secrets with Argon2id on QuickJS.

```sh
pulumi stack output --show-secrets bootstrapOwnerPassword
```

To rotate a value, replace its resource: `pulumi up --replace <urn>`.

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
- An interrupted `pulumi destroy` can leave `directory` deleting, held by a binding from the
  identity workload. Run `di-framework platform destroy identity --target identity`, then
  `pulumi up --refresh`.

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
