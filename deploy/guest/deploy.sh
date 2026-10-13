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
# kubeconfig works too: the Secret steps only create and replace, and since its namespaced Role
# may not list BackingServices in every namespace, the guard then skips the cluster-wide
# `directory` check with a warning and checks di-tenant-<tenant> only. It does not skip it for a
# target named authproto (the instance, or authproto's kubeconfig by path or API server): there a
# forbidden list refuses, so the cutover needs the admin kubeconfig.
#
# The script refuses a tenant whose di-tenant-<tenant> namespace still has the Postgres
# `directory` BackingService, i.e. the Postgres-era guest on authproto, however the kubeconfig and
# tenant were chosen. It treats the target as authproto when the instance is named `authproto`,
# when the kubeconfig is authproto's (its path in kube's state directory, or the same API server),
# or when the cluster has a `directory` BackingService in any namespace, whatever the instance
# argument says. Such a target is refused except for the signed-off cutover
# (docs/guest-http-api.md#authproto-cutover): a new tenant (never `identity`), confirmed with
# exactly IDENTITY_AUTHPROTO_CUTOVER=authproto/<tenant> in the environment, whose tenant host runs
# the exclusive-instance wash build. The check runs before the build, so a refusal changes nothing.
#
# The workload, and its `<workload>-control` Secret, are named by `name` in
# apps/guest/di-framework.config.json. That config encrypts the data directory at rest
# (pglite.encryption) and declares every runtime value, DI_PGLITE_KEY included, in
# controlSecretKeys, so `di-framework platform deploy` keeps the Secret instead of rewriting it.
# This needs cli-plugin-platform with cli-extensions#70 and #72 (the release after 6.1.2).
#
# Order: check the values against the config (every name declared, DI_PGLITE_KEY present; a
# plaintext guest only with IDENTITY_PGLITE_PLAINTEXT=1), build, deploy, then write the values and
# roll the workload onto them. The values file is only read: the data directory key it holds is
# never regenerated, so every deploy reuses it. On a first deploy the Secret does not exist yet;
# the CLI creates it with only its control keys, and until the last step the guest answers 503
# (the encryption layer refuses to start without its key, and changes nothing).
#
# The first deploy of a new workload usually outlasts the CLI's fixed readiness wait (30 x 2 s):
# the tenant host rolls to mount the new data directory. The CLI then exits 3 with "did not become
# ready". That case is expected, so this script polls the WorkloadDeployment's Ready condition for
# up to IDENTITY_READY_TIMEOUT seconds (default 300) and continues to the last step. It polls
# instead of `kubectl wait`, which exited at once without its error on these WorkloadDeployments
# in the proving-grounds harness. Waiting is safe: the key is in the values file, the Secret does
# not have it yet, and the layer refuses the empty directory without writing to it.
#
# If a step after the build fails, fix the cause and run
#   bun deploy/guest/runtime-secrets.ts apply --values <file> --kubeconfig <kc> --tenant <tenant>
# on its own: it rewrites the Secret and rolls the workload. That needs the WorkloadDeployment:
# when the deploy failed before it existed (on a brand-new tenant, typically a push that 404s
# while the tenant registry, WorkloadDeployment di-tenant-registry, is not Ready yet), the script
# says so and the recovery is to re-run this script instead.
set -eu

instance="${1:-}"
tenant="${2:-}"
values="${3:-}"
if [ -z "$instance" ] || [ -z "$tenant" ] || [ -z "$values" ]; then
  echo "usage: $0 <instance> <tenant> <values-file>" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/../.." && pwd)"
state_dir="${DI_FRAMEWORK_KUBE_STATE_DIR:-$HOME/Library/Application Support/di-framework-kube}"
# runtime-secrets.ts guard recognises authproto's kubeconfig in the same state directory.
export DI_FRAMEWORK_KUBE_STATE_DIR="$state_dir"
secrets="$root/deploy/guest/runtime-secrets.ts"

export IDENTITY_TENANT="$tenant"
export IDENTITY_KUBECONFIG="${IDENTITY_KUBECONFIG:-$state_dir/$instance/kubeconfig}"
export IDENTITY_KUBE_CONTEXT="${IDENTITY_KUBE_CONTEXT:-$(kubectl --kubeconfig "$IDENTITY_KUBECONFIG" config current-context)}"
export IDENTITY_REGISTRY_PUSH="${IDENTITY_REGISTRY_PUSH:-http://127.0.0.1:${REGISTRY_FORWARD_PORT:-25001}}"
export IDENTITY_REGISTRY_PULL="${IDENTITY_REGISTRY_PULL:-examples-registry.wasmcloud.svc.cluster.local:5000}"

# Values file (mode 0600, known names) against the guest config; prints the workload name.
workload="$(bun "$secrets" preflight --values "$values")"
# The target tenant must not run the Postgres-era guest; authproto (by name, kubeconfig or
# cluster) only as the confirmed cutover.
bun "$secrets" guard --instance "$instance" --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" --tenant "$tenant"

# Build before touching the cluster, so a build failure leaves the running guest and its Secret.
(cd "$root/apps/guest" && di-framework platform build)

# The recovery commands this script prints, ready to copy: every argument single-quoted (the
# default kubeconfig path contains "Application Support"), and the guard's environment carried,
# since `apply` runs the same guard: the cutover confirmation and the host image digest pin.
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
guard_env=
for name in IDENTITY_AUTHPROTO_CUTOVER IDENTITY_EXCLUSIVE_HOST_DIGEST; do
  eval "value=\${$name:-}"
  if [ -n "$value" ]; then guard_env="$guard_env$name=$(quote "$value") "; fi
done
recovery="${guard_env}bun $(quote "$secrets") apply --values $(quote "$values") --kubeconfig $(quote "$IDENTITY_KUBECONFIG") --context $(quote "$IDENTITY_KUBE_CONTEXT") --tenant $(quote "$tenant")"
redeploy="${guard_env}$(quote "$0") $(quote "$instance") $(quote "$tenant") $(quote "$values")"
deploy_log="$(mktemp "${TMPDIR:-/tmp}/identity-deploy.XXXXXX")"
trap 'rm -f "$deploy_log"' EXIT
if (cd "$root/apps/guest" && di-framework platform deploy "$workload" --target identity --yes) >"$deploy_log" 2>&1; then
  status=0
else
  status=$?
fi
cat "$deploy_log"
if [ "$status" -eq 3 ] && grep -q 'did not become ready' "$deploy_log"; then
  timeout="${IDENTITY_READY_TIMEOUT:-300}"
  echo "the CLI stopped waiting for $workload to become Ready (expected on a first deploy); waiting up to ${timeout}s" >&2
  waited=0
  until [ "$(kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" \
    --namespace "di-tenant-$tenant" get workloaddeployment "$workload" \
    -o 'jsonpath={.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ]; do
    if [ "$waited" -ge "$timeout" ]; then
      echo "$workload is not Ready after ${timeout}s; once it is, run: $recovery" >&2
      exit 3
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "$workload is Ready after ${waited}s more" >&2
elif [ "$status" -ne 0 ]; then
  # `apply` writes the Secret of an existing workload and rolls it. When the deploy failed before
  # the WorkloadDeployment existed (e.g. the push 404s on a brand-new tenant whose registry,
  # WorkloadDeployment di-tenant-registry, is not Ready yet), there is nothing to apply to: the
  # recovery is to re-run this deploy.
  if existing="$(kubectl --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" \
    --namespace "di-tenant-$tenant" get workloaddeployment "$workload" --ignore-not-found -o name 2>/dev/null)"; then
    if [ -n "$existing" ]; then
      echo "deploy of $workload failed (exit $status); once fixed, run: $recovery" >&2
    else
      echo "deploy of $workload failed (exit $status) before di-tenant-$tenant had a WorkloadDeployment $workload, so there is nothing for runtime-secrets.ts apply to update. On a new tenant, wait until WorkloadDeployment di-tenant-registry in di-tenant-$tenant is Ready. Once fixed, re-run the deploy: $redeploy" >&2
    fi
  else
    echo "deploy of $workload failed (exit $status), and kubectl could not tell whether WorkloadDeployment $workload exists in di-tenant-$tenant. Once fixed: if it exists, run: $recovery; if not, re-run the deploy: $redeploy" >&2
  fi
  exit 3
fi

bun "$secrets" apply --values "$values" \
  --kubeconfig "$IDENTITY_KUBECONFIG" --context "$IDENTITY_KUBE_CONTEXT" --tenant "$tenant"
