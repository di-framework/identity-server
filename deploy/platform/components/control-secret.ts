/**
 * The identity guest's runtime secrets in its `<workload>-control` Secret, shared by the Pulumi
 * `RuntimeSecrets` resource and `deploy/guest/runtime-secrets.ts`. Everything here goes through
 * an injected `kubectl`, so the rules are tested without a cluster
 * (`deploy/guest/control-secret.test.ts`). No function puts a value in an argument list, a file,
 * a log or an error message: the Secret document travels on kubectl's stdin.
 *
 * Why this Secret: tenant admission lets a workload without an environment label reference only
 * `<workload>-control` through `localResources.environment.secretFrom`, and the platform refuses
 * secrets and URLs in wasi:config. A workload labelled with an environment may instead reference
 * `<name>.<env>` Secrets, which the CLI never rewrites; moving the values there would remove the
 * delete, deploy, rewrite and roll sequence below, and so would the CLI carrying extra keys in
 * the control Secret (di-framework/cli-extensions#69). Until one of those lands,
 * `di-framework platform deploy` (cli-plugin-platform 6.1.2) rewrites the control Secret with
 * only its control token on every deploy, so these values are written again after each deploy.
 */

export interface KubectlResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs kubectl (already bound to a kubeconfig and context) with `args`; `input` is its stdin. */
export type Kubectl = (args: string[], input?: string) => Promise<KubectlResult>;

/** Every name the guest reads from its environment (apps/guest/src/settings.ts). */
export const RUNTIME_SECRET_NAMES: readonly string[] = [
  'ISSUER_URL',
  'AUTH_PUBLIC_ORIGIN',
  'AUTH_ACTIVE_PRIVATE_JWK',
  'AUTH_PREVIOUS_PUBLIC_JWK_SET',
  'SMTP_HOST',
  'SMTP_USERNAME',
  'SMTP_PASSWORD',
  'AUTH_ACCESS_REDIRECT_URIS',
  'AUTH_BOOTSTRAP_OWNER_PASSWORD',
  'AUTH_BOOTSTRAP_VIEWER_PASSWORD',
  'AUTH_ACCESS_CLIENT_SECRET',
  'AUTH_DIRECTORY_CLIENT_SECRET',
  'AUTH_PROVISIONER_CLIENT_SECRET',
  'AUTH_CLI_CLIENT_ID',
  'AUTH_CLI_REDIRECT_URIS',
];
export const REQUIRED_RUNTIME_SECRETS: readonly string[] = [
  'ISSUER_URL',
  'AUTH_PUBLIC_ORIGIN',
  'AUTH_ACTIVE_PRIVATE_JWK',
];
/** WorkloadDeployment environment config entry that rolls the workload onto new values. */
export const REVISION_KEY = 'IDENTITY_RUNTIME_REVISION';
/** The Postgres BackingService the earlier guest (still on authproto) binds to. */
export const LEGACY_DATABASE = 'directory';

/** Parses a values file's text: a JSON object of known names to strings, with the required ones. */
export function parseRuntimeValues(text: string, source: string): Record<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${source} is not JSON`);
  }
  if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${source} must hold a JSON object of names to strings`);
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  const unknown = entries.filter(([name]) => !RUNTIME_SECRET_NAMES.includes(name));
  if (unknown.length > 0) {
    throw new Error(`unknown names in ${source}: ${unknown.map(([name]) => name).join(', ')}`);
  }
  const notStrings = entries.filter(([, value]) => typeof value !== 'string');
  if (notStrings.length > 0) {
    throw new Error(`values must be strings: ${notStrings.map(([name]) => name).join(', ')}`);
  }
  const values = parsed as Record<string, string>;
  const missing = REQUIRED_RUNTIME_SECRETS.filter((name) => !values[name]?.trim());
  if (missing.length > 0) throw new Error(`missing required names: ${missing.join(', ')}`);
  return values;
}

/** A values file must be readable by its owner only (mode 0600 or stricter). */
export function assertPrivateMode(mode: number, source: string): void {
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `${source} is readable or writable by group or others (mode ${(mode & 0o777).toString(8)}); chmod 600 it`,
    );
  }
}

/**
 * Refuses a tenant that still runs the Postgres-era guest. Its namespace holds the `directory`
 * BackingService; deploying the pglite guest there is the authproto cutover, which needs its own
 * sign-off (docs/guest-http-api.md#authproto-cutover). This is checked against the cluster, not
 * against instance or tenant names, so it holds however the target was chosen. A failed check
 * refuses too.
 */
export async function refuseLegacyTenant(kubectl: Kubectl, namespace: string): Promise<void> {
  const result = await kubectl([
    '--namespace',
    namespace,
    'get',
    'backingservices.platform.di-framework.dev',
    LEGACY_DATABASE,
    '--ignore-not-found',
    '-o',
    'name',
  ]);
  if (result.code !== 0) {
    throw new Error(
      `cannot check ${namespace} for the Postgres BackingService \`${LEGACY_DATABASE}\` (kubectl exit ${result.code}); refusing to deploy`,
    );
  }
  if (result.stdout.trim() !== '') {
    throw new Error(
      `${namespace} has the Postgres BackingService \`${LEGACY_DATABASE}\`, so it runs the Postgres-era identity guest. Replacing it is the authproto cutover (docs/guest-http-api.md#authproto-cutover); refusing to deploy`,
    );
  }
}

/** The whole control Secret: the CLI's two keys (with a fresh token) plus the runtime values. */
export function controlSecretDocument(
  namespace: string,
  workload: string,
  values: Record<string, string>,
  token: string,
): string {
  const encode = (value: string) => Buffer.from(value, 'utf8').toString('base64');
  const data: Record<string, string> = {
    DI_CONTROL_TOKEN: encode(token),
    DI_CONTROL_IDENTITY: encode(workload),
  };
  for (const [key, value] of Object.entries(values)) data[key] = encode(value);
  return JSON.stringify({
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: `${workload}-control`,
      namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'di-framework',
        'app.kubernetes.io/name': workload,
      },
    },
    type: 'Opaque',
    data,
  });
}

/**
 * Writes the control Secret blind, as the CLI does: tenant developers may create and replace
 * Secrets but never read them. The document goes on stdin (`-f -`); nothing touches the disk.
 * Errors name the Secret and kubectl's exit code only.
 */
export async function writeControlSecret(
  kubectl: Kubectl,
  options: { namespace: string; workload: string; values: Record<string, string>; token: string },
): Promise<void> {
  const name = `${options.workload}-control`;
  const document = controlSecretDocument(
    options.namespace,
    options.workload,
    options.values,
    options.token,
  );
  const collection = `/api/v1/namespaces/${options.namespace}/secrets`;
  const created = await kubectl(['create', '--raw', collection, '-f', '-'], document);
  if (created.code === 0) return;
  if (!/AlreadyExists/.test(created.stderr)) {
    throw new Error(`creating ${options.namespace}/${name} failed (kubectl exit ${created.code})`);
  }
  const replaced = await kubectl(
    ['replace', '--raw', `${collection}/${name}`, '-f', '-'],
    document,
  );
  if (replaced.code !== 0) {
    throw new Error(
      `replacing ${options.namespace}/${name} failed (kubectl exit ${replaced.code})`,
    );
  }
}

/**
 * Rolls the workload by setting only `IDENTITY_RUNTIME_REVISION` in its environment config. The
 * other entries (`DI_PGLITE_DATA_DIR` and the rest the CLI renders) stay. The map itself is added
 * only when kubectl reports that its path does not exist; any other failure is reported as is.
 */
export async function rollWorkload(
  kubectl: Kubectl,
  options: { namespace: string; workload: string; revision: string },
): Promise<void> {
  const environment = '/spec/template/spec/components/0/localResources/environment';
  const patch = (operations: unknown[]) =>
    kubectl([
      '--namespace',
      options.namespace,
      'patch',
      'workloaddeployment',
      options.workload,
      '--type',
      'json',
      '-p',
      JSON.stringify(operations),
    ]);
  const first = await patch([
    { op: 'add', path: `${environment}/config/${REVISION_KEY}`, value: options.revision },
  ]);
  if (first.code === 0) return;
  if (!/missing path|does not exist|doesn't exist|nonexistent/i.test(first.stderr)) {
    throw new Error(
      `rolling workloaddeployment/${options.workload} failed: ${first.stderr.trim().slice(0, 300)}`,
    );
  }
  // Only reached when the map is absent, so adding it drops nothing.
  const second = await patch([
    { op: 'add', path: `${environment}/config`, value: { [REVISION_KEY]: options.revision } },
  ]);
  if (second.code !== 0) {
    throw new Error(
      `rolling workloaddeployment/${options.workload} failed: ${second.stderr.trim().slice(0, 300)}`,
    );
  }
}

/** Guard, write, roll. Returns the names written and the revision. */
export async function applyRuntimeSecrets(
  kubectl: Kubectl,
  options: {
    tenant: string;
    workload: string;
    values: Record<string, string>;
    token: string;
    revision: string;
  },
): Promise<{ names: string[]; revision: string }> {
  const namespace = `di-tenant-${options.tenant}`;
  await refuseLegacyTenant(kubectl, namespace);
  await writeControlSecret(kubectl, { ...options, namespace });
  await rollWorkload(kubectl, {
    namespace,
    workload: options.workload,
    revision: options.revision,
  });
  return { names: Object.keys(options.values).sort(), revision: options.revision };
}

/**
 * Deletes the control Secret before a CLI deploy, after refusing a tenant that still runs the
 * Postgres-era guest. The CLI rewrites `<workload>-control` with only its control token, and a
 * tenant developer's replace is refused while it holds more keys. A plain delete: tenant
 * developers may delete Secrets but not read them.
 */
export async function resetControlSecret(
  kubectl: Kubectl,
  options: { namespace: string; name: string },
): Promise<void> {
  await refuseLegacyTenant(kubectl, options.namespace);
  const deleted = await kubectl([
    '--namespace',
    options.namespace,
    'delete',
    'secret',
    options.name,
    '--ignore-not-found',
    '--wait=false',
  ]);
  if (deleted.code !== 0) {
    throw new Error(`deleting ${options.name} failed: ${deleted.stderr.trim().slice(-300)}`);
  }
}

/** The di-framework-kube instance that runs the Postgres-era guest; never a target here. */
export const LEGACY_INSTANCE = 'authproto';

/** kubectl run synchronously, for checks at Pulumi program evaluation, before any resource. */
export type SyncKubectl = (
  kubeconfig: string,
  context: string | undefined,
  args: string[],
) => KubectlResult;

export interface PreflightTarget {
  /** di-framework-kube instance name (`kubeInstance`). */
  instance: string;
  /** kube `--state-dir`; kube's default (`os.UserConfigDir()/di-framework-kube`) when unset. */
  stateDir: string;
  /** `kubeconfig` and `context` of an existing cluster, instead of the managed instance's. */
  kubeconfig?: string;
  context?: string;
}

/**
 * kube's default state directory: Go's `os.UserConfigDir()` joined with `di-framework-kube`
 * (kube internal/state DefaultDir).
 */
export function defaultKubeStateDir(
  platform: string,
  home: string,
  env: Readonly<Record<string, string | undefined>>,
): string {
  if (platform === 'darwin') return `${home}/Library/Application Support/di-framework-kube`;
  if (platform === 'win32')
    return `${env.AppData ?? `${home}\\AppData\\Roaming`}\\di-framework-kube`;
  return `${env.XDG_CONFIG_HOME || `${home}/.config`}/di-framework-kube`;
}

/**
 * Runs before the Pulumi program registers any resource, so before `di-framework-kube up` (which
 * upgrades a managed instance in place and replaces its tenant declarations and host image),
 * the tenant host patches and Mailpit.
 *
 * - The instance name `authproto` is refused outright.
 * - The target cluster is the stack's `kubeconfig`, or else the managed instance's kubeconfig in
 *   kube's state directory. A managed instance whose directory does not exist yet is new and has
 *   nothing to protect. One that exists without a kubeconfig is refused (fail closed).
 * - Any `directory` BackingService in any namespace of that cluster refuses the run: `kube up`
 *   rewrites the whole platform install, not only the target tenant. A failed check refuses too.
 *
 * Returns what it checked, for the log.
 */
export function preflightCluster(
  target: PreflightTarget,
  io: { exists(path: string): boolean; kubectl: SyncKubectl },
): 'new-instance' | 'checked' {
  if (target.instance === LEGACY_INSTANCE) {
    throw new Error(
      `kubeInstance ${LEGACY_INSTANCE} runs the Postgres-era identity guest; deploying there is the cutover in docs/guest-http-api.md#authproto-cutover. Refusing`,
    );
  }
  let kubeconfig = target.kubeconfig;
  if (kubeconfig === undefined) {
    const instanceDir = `${target.stateDir}/${target.instance}`;
    if (!io.exists(instanceDir)) return 'new-instance';
    kubeconfig = `${instanceDir}/kubeconfig`;
    if (!io.exists(kubeconfig)) {
      throw new Error(
        `kube instance ${target.instance} exists in ${target.stateDir} but has no kubeconfig, so it cannot be checked for the Postgres guest; refusing`,
      );
    }
  }
  const result = io.kubectl(kubeconfig, target.context, [
    'get',
    'backingservices.platform.di-framework.dev',
    '--all-namespaces',
    '-o',
    'jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{"\\n"}{end}',
  ]);
  if (result.code !== 0) {
    throw new Error(
      `cannot list BackingServices on ${target.instance} (kubectl exit ${result.code}); refusing. Start the cluster and retry`,
    );
  }
  const legacy = result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.endsWith(`/${LEGACY_DATABASE}`));
  if (legacy.length > 0) {
    throw new Error(
      `${target.instance} has the Postgres BackingService ${legacy.join(', ')}, so it runs the Postgres-era identity guest. This program would upgrade that platform install and replace the guest; that is the cutover in docs/guest-http-api.md#authproto-cutover. Refusing`,
    );
  }
  return 'checked';
}
