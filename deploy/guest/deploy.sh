#!/bin/sh
# Build the identity guest (pglite composed in) and deploy it to a di-framework-kube instance
# without Pulumi, then write its runtime secrets and roll it onto them.
#
# Usage: deploy/guest/deploy.sh <instance> <values-file>
#
#   <instance>     di-framework-kube instance name. Required; there is no default.
#   <values-file>  runtime secrets JSON (mode 0600), e.g. from
#                  `bun deploy/guest/runtime-secrets.ts generate --out <file> ...`
#
# The variables di-framework.deploy.toml interpolates for target `identity` default to the
# instance's admin kubeconfig and the in-cluster `examples-registry` behind a port-forward on
# REGISTRY_FORWARD_PORT; override any of them, plus IDENTITY_TENANT (default: identity), through
# the environment. A tenant developer kubeconfig works too: the Secret steps only create, replace
# and delete.
#
# Order matters. `di-framework platform deploy` rewrites `identity-control` with only its control
# token, and as a tenant developer it cannot replace a copy that holds more keys, so the Secret is
# deleted first and rewritten with the runtime secrets afterwards. Until then the guest answers
# 503 naming the missing settings. See docs/configuration.md#wasmcloud-guest.
#
# The `authproto` instance still runs the Postgres guest; moving it to pglite is a separate,
# signed-off cutover (docs/guest-http-api.md#authproto-cutover). This script refuses it.
set -eu

instance="${1:-}"
values="${2:-}"
if [ -z "$instance" ] || [ -z "$values" ]; then
  echo "usage: $0 <instance> <values-file>" >&2
  exit 2
fi
if [ "$instance" = authproto ]; then
  echo "refusing to deploy the pglite guest to authproto; see docs/guest-http-api.md#authproto-cutover" >&2
  exit 2
fi
[ -r "$values" ] || { echo "cannot read $values" >&2; exit 2; }

root="$(cd "$(dirname "$0")/../.." && pwd)"
state_dir="${DI_FRAMEWORK_KUBE_STATE_DIR:-$HOME/Library/Application Support/di-framework-kube}"
tenant="${IDENTITY_TENANT:-identity}"
export IDENTITY_TENANT="$tenant"

export IDENTITY_KUBECONFIG="${IDENTITY_KUBECONFIG:-$state_dir/$instance/kubeconfig}"
export IDENTITY_KUBE_CONTEXT="${IDENTITY_KUBE_CONTEXT:-$(kubectl --kubeconfig "$IDENTITY_KUBECONFIG" config current-context)}"
export IDENTITY_REGISTRY_PUSH="${IDENTITY_REGISTRY_PUSH:-http://127.0.0.1:${REGISTRY_FORWARD_PORT:-25001}}"
export IDENTITY_REGISTRY_PULL="${IDENTITY_REGISTRY_PULL:-examples-registry.wasmcloud.svc.cluster.local:5000}"

bun "$root/deploy/guest/runtime-secrets.ts" names --values "$values" >/dev/null

kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" \
  --namespace "di-tenant-$tenant" delete secret identity-control --ignore-not-found --wait=false

(cd "$root/apps/guest" && di-framework platform deploy identity --target identity --yes)

bun "$root/deploy/guest/runtime-secrets.ts" apply --values "$values" \
  --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" --tenant "$tenant"
