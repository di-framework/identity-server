const DNS_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** Remote lifecycle commands, kept separate so they can be exercised without SSH. */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function rootScript(script: string): string {
  return `sudo -n sh -c ${shellQuote(`set -eu\numask 077\n${script}`)}`;
}

export function k0sCommands(options: {
  scope: string;
  markerPath: string;
  host: string;
  apiPort: number;
}) {
  const { scope, markerPath, host, apiPort } = options;
  const configuration = JSON.stringify({
    apiVersion: 'k0s.k0sproject.io/v1beta1',
    kind: 'ClusterConfig',
    metadata: { name: 'k0s' },
    spec: { api: { port: apiPort, sans: [host] } },
  });
  const create = rootScript(`
MARKER=${shellQuote(markerPath)}
CONFIG="$MARKER.k0s.yaml"
mkdir -p "$(dirname "$MARKER")"
if ! command -v k0s >/dev/null 2>&1; then
  INSTALLER=$(mktemp)
  trap 'rm -f "$INSTALLER"' EXIT
  curl --proto '=https' --tlsv1.2 -sSf https://get.k0s.sh -o "$INSTALLER"
  sh "$INSTALLER"
  rm -f "$INSTALLER"
  trap - EXIT
fi
if ! systemctl cat k0scontroller.service >/dev/null; then
  if [ -f "$MARKER" ] && ! grep -qx 'owned=1' "$MARKER"; then
    echo 'Refusing to install over an adopted cluster marker' >&2
    exit 1
  fi
  printf '%s\n' ${shellQuote(configuration)} > "$CONFIG"
  # Record ownership before installation so a failed start can be retried safely.
  printf 'scope=%s\nowned=1\n' ${shellQuote(scope)} > "$MARKER"
  k0s install controller --enable-worker --no-taints --config "$CONFIG"
elif [ ! -f "$MARKER" ]; then
  printf 'scope=%s\nowned=0\n' ${shellQuote(scope)} > "$MARKER"
fi
chmod 600 "$MARKER"
if ! k0s status >/dev/null 2>&1; then
  k0s start
fi
attempt=0
until k0s kubectl get --raw=/readyz >/dev/null 2>&1 && k0s kubectl wait node --all --for=condition=Ready --timeout=5s >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 90 ]; then
    k0s status >&2 || true
    journalctl -u k0scontroller -n 200 --no-pager >&2 || true
    exit 1
  fi
  sleep 2
done
# Existing installations retain their configuration. Never advertise a fictitious port.
ADMIN_CONFIG=$(k0s kubeconfig admin)
ACTUAL_PORT=$(printf '%s\n' "$ADMIN_CONFIG" | sed -nE 's@^[[:space:]]*server: https://.*:([0-9]+)/?$@\\1@p')
if [ "$ACTUAL_PORT" != ${shellQuote(String(apiPort))} ]; then
  echo "Existing k0s API uses port $ACTUAL_PORT; set apiPort to that port or reconfigure k0s explicitly" >&2
  exit 1
fi
echo ${shellQuote(`k0s ready for ${scope}`)}
`);
  const remove = rootScript(`
MARKER=${shellQuote(markerPath)}
if [ ! -f "$MARKER" ]; then
  exit 0
fi
# A failed read must abort, not be confused with an adopted cluster.
OWNED=$(sed -n 's/^owned=//p' "$MARKER")
case "$OWNED" in
  1)
    k0s stop
    k0s reset
    ;;
  0) ;;
  *) echo 'Invalid k0s ownership marker; refusing cleanup' >&2; exit 1 ;;
esac
# Keep the marker and config when stop/reset fails so cleanup can be retried.
rm -f -- "$MARKER" "$MARKER.k0s.yaml"
`);
  return { create, update: create, delete: remove };
}

export function dnsCommands(options: {
  stateDirectory: string;
  zone: string;
  originalCorefile?: string;
}) {
  if (!DNS_NAME.test(options.zone)) throw new Error('dnsSinkZone must be a dotted DNS name');
  const zonePattern = options.zone.replaceAll('.', '\\.');
  const setup = `
STATE=${shellQuote(options.stateDirectory)}
mkdir -p "$STATE"
chmod 700 "$STATE"
read_current() {
  k0s kubectl -n kube-system get configmap coredns -o 'jsonpath={.data.Corefile}' > "$STATE/current"
  test -s "$STATE/current"
}
apply_corefile() {
  k0s kubectl -n kube-system create configmap coredns --from-file="Corefile=$1" --dry-run=client -o json > "$STATE/patch.json"
  k0s kubectl -n kube-system patch configmap coredns --type merge --patch-file "$STATE/patch.json"
  k0s kubectl -n kube-system rollout restart deploy/coredns
  k0s kubectl -n kube-system rollout status deploy/coredns --timeout=120s
}
`;
  const recovery =
    options.originalCorefile === undefined
      ? `
  if grep -q '^${zonePattern}:53 {' "$STATE/current"; then
    echo 'Legacy DNS override has no backup. Set corednsOriginalCorefilePath to the original Corefile before migrating.' >&2
    exit 1
  fi
  cp "$STATE/current" "$STATE/original.new"
`
      : `
  printf '%s' ${shellQuote(options.originalCorefile)} > "$STATE/original.new"
  test -s "$STATE/original.new"
`;
  const create = rootScript(`${setup}
read_current
if [ ! -f "$STATE/original" ]; then
${recovery}
  mv "$STATE/original.new" "$STATE/original"
elif [ -f "$STATE/applied" ] && ! cmp -s "$STATE/current" "$STATE/applied" && ! cmp -s "$STATE/current" "$STATE/original"; then
  echo 'CoreDNS changed outside this stack; refusing to overwrite it' >&2
  exit 1
fi
# Preserve every existing zone and setting, adding only this LAN workaround.
cat > "$STATE/next" <<'DI_DNS_BLOCK'
${options.zone}:53 {
    errors
    template ANY ANY {
        rcode NXDOMAIN
    }
}
DI_DNS_BLOCK
cat "$STATE/original" >> "$STATE/next"
mv "$STATE/next" "$STATE/applied"
apply_corefile "$STATE/applied"
`);
  const remove = rootScript(`${setup}
if [ ! -f "$STATE/original" ]; then
  echo 'No original Corefile backup; refusing to claim DNS restoration succeeded' >&2
  exit 1
fi
read_current
if cmp -s "$STATE/current" "$STATE/original" || { [ -f "$STATE/applied" ] && cmp -s "$STATE/current" "$STATE/applied"; }; then
  # Also retry the rollout when a previous restore applied but did not become ready.
  apply_corefile "$STATE/original"
else
  echo 'CoreDNS changed outside this stack; preserve/reconcile those changes before teardown' >&2
  exit 1
fi
rm -f "$STATE/original" "$STATE/applied" "$STATE/current" "$STATE/patch.json"
rmdir "$STATE"
`);
  return { create, update: create, delete: remove };
}
