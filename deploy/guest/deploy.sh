#!/bin/sh
# Build the identity guest (pglite composed in) and deploy it to a di-framework-kube instance
# without Pulumi, then write its runtime secrets and roll it onto them.
#
# Usage: deploy/guest/deploy.sh <instance> <tenant> <values-file>
#
#   <instance>     di-framework-kube instance name. Required; there is no default.
#   <tenant>       tenant to deploy into. Required; there is no default.
#   <values-file>  runtime secrets JSON, mode 0600 (checked), e.g. from
#                  `bun deploy/guest/runtime-secrets.ts generate --out <file> ...`
#
# The variables di-framework.deploy.toml interpolates for target `identity` default to the
# instance's admin kubeconfig and the in-cluster `examples-registry` behind a port-forward on
# REGISTRY_FORWARD_PORT; override any of them through the environment. A tenant developer
# kubeconfig works too: the Secret steps only create, replace and delete.
#
# The script refuses a tenant whose di-tenant-<tenant> namespace still has the Postgres
# `directory` BackingService, i.e. the Postgres-era guest on authproto, however the kubeconfig and
# tenant were chosen. Replacing that guest is the signed-off cutover in
# docs/guest-http-api.md#authproto-cutover.
#
# Order: build, then delete `identity-control`, deploy, and write the values. The CLI rewrites
# that Secret with only its control token and, as a tenant developer, cannot replace a copy that
# holds more keys. Between the delete and the last step the guest answers 503 naming the missing
# settings. If a step after the delete fails, fix the cause and run
#   bun deploy/guest/runtime-secrets.ts apply --values <file> --kubeconfig <kc> --tenant <tenant>
# on its own: it recreates the Secret and rolls the workload.
set -eu

instance="${1:-}"
tenant="${2:-}"
values="${3:-}"
if [ -z "$instance" ] || [ -z "$tenant" ] || [ -z "$values" ]; then
  echo "usage: $0 <instance> <tenant> <values-file>" >&2
  exit 2
fi
if [ "$instance" = authproto ]; then
  echo "refusing to deploy the pglite guest to authproto; see docs/guest-http-api.md#authproto-cutover" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
state_dir="${DI_FRAMEWORK_KUBE_STATE_DIR:-$HOME/Library/Application Support/di-framework-kube}"
secrets="$root/deploy/guest/runtime-secrets.ts"

export IDENTITY_TENANT="$tenant"
export IDENTITY_KUBECONFIG="${IDENTITY_KUBECONFIG:-$state_dir/$instance/kubeconfig}"
export IDENTITY_KUBE_CONTEXT="${IDENTITY_KUBE_CONTEXT:-$(kubectl --kubeconfig "$IDENTITY_KUBECONFIG" config current-context)}"
export IDENTITY_REGISTRY_PUSH="${IDENTITY_REGISTRY_PUSH:-http://127.0.0.1:${REGISTRY_FORWARD_PORT:-25001}}"
export IDENTITY_REGISTRY_PULL="${IDENTITY_REGISTRY_PULL:-examples-registry.wasmcloud.svc.cluster.local:5000}"

# Values file: mode 0600, known and required names.
bun "$secrets" names --values "$values" >/dev/null
# The target tenant must not run the Postgres-era guest.
bun "$secrets" guard --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" --tenant "$tenant"

# Build before touching the cluster, so a build failure leaves the running guest and its Secret.
(cd "$root/apps/guest" && di-framework platform build)

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" \
  --namespace "di-tenant-$tenant" delete secret identity-control --ignore-not-found --wait=false

(cd "$root/apps/guest" && di-framework platform deploy identity --target identity --yes) || {
  echo "deploy failed after identity-control was deleted; once fixed, run: bun $secrets apply --values $values --kubeconfig <kubeconfig> --tenant $tenant" >&2
  exit 3
}

bun "$secrets" apply --values "$values" \
  --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" --tenant "$tenant"
