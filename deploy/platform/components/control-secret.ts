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
 * the control Secret (di-framework/cli-extensions#69). cli-plugin-platform with #70 and #72 (after
 * 6.1.2) does the latter: every name here is declared in `controlSecretKeys` of
 * apps/guest/di-framework.config.json, and deploy keeps the Secret instead of rewriting it with
 * only its control token. The values are still written again after each deploy, which also rolls
 * the workload onto them.
 */

import { hkdfSync } from 'node:crypto';

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
  'IDENTITY_COLUMN_ENCRYPTION',
  'IDENTITY_COLUMN_KEY',
  'IDENTITY_BIDX_KEY',
];
/**
 * The pglite-encfs master key and, during a rotation, the key it replaces (di-framework/platform
 * `platform/pglite-encfs`). The layer reads them from the guest's environment, which the platform
 * fills from the same control Secret; the guest itself never reads them.
 */
export const PGLITE_KEY = 'DI_PGLITE_KEY';
export const PGLITE_PREVIOUS_KEY = 'DI_PGLITE_KEY_PREVIOUS';
export const PGLITE_KEY_NAMES: readonly string[] = [PGLITE_KEY, PGLITE_PREVIOUS_KEY];
/** Every name a values file and the control Secret may hold besides the CLI's `DI_CONTROL_*`. */
export const VALUE_NAMES: readonly string[] = [...RUNTIME_SECRET_NAMES, ...PGLITE_KEY_NAMES];
/** Column encryption keys: 32 random bytes each, base64; separate from each other. */
export const COLUMN_KEY_NAMES: readonly string[] = ['IDENTITY_COLUMN_KEY', 'IDENTITY_BIDX_KEY'];
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
  const unknown = entries.filter(([name]) => !VALUE_NAMES.includes(name));
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
  assertColumnEncryption(values, source);
  assertPgliteKeys(values, source);
  return values;
}

/**
 * Column encryption values: each key decodes to at least 32 bytes, the two keys differ, and
 * `IDENTITY_COLUMN_ENCRYPTION=enabled` comes with both keys (the guest would answer 503 without
 * them). Errors name the setting, never its value.
 */
export function assertColumnEncryption(values: Record<string, string>, source: string): void {
  const flag = values.IDENTITY_COLUMN_ENCRYPTION?.trim() ?? '';
  if (flag !== '' && flag !== 'enabled' && flag !== 'disabled') {
    throw new Error(`IDENTITY_COLUMN_ENCRYPTION in ${source} must be enabled or disabled`);
  }
  for (const name of COLUMN_KEY_NAMES) {
    const key = values[name]?.trim();
    if (key && (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(key) || Buffer.from(key, 'base64').length < 32)) {
      throw new Error(`${name} in ${source} must be at least 32 random bytes, base64 encoded`);
    }
  }
  const [column, bidx] = COLUMN_KEY_NAMES.map((name) => values[name]?.trim() ?? '');
  if (column && column === bidx) {
    throw new Error(`IDENTITY_COLUMN_KEY and IDENTITY_BIDX_KEY in ${source} must differ`);
  }
  if (flag === 'enabled' && (!column || !bidx)) {
    throw new Error(
      `IDENTITY_COLUMN_ENCRYPTION=enabled in ${source} needs IDENTITY_COLUMN_KEY and IDENTITY_BIDX_KEY`,
    );
  }
}

/**
 * Decodes a pglite-encfs master key as the layer does: exactly 32 bytes, standard or URL-safe
 * base64 (not mixed), padding optional, surrounding whitespace ignored. Undefined when invalid.
 */
export function decodePgliteKey(text: string): Buffer | undefined {
  const trimmed = text.trim();
  if (!/^(?:[A-Za-z0-9+/]{43}|[A-Za-z0-9_-]{43})=?$/.test(trimmed)) return undefined;
  const bare = trimmed.replace(/=$/, '');
  const bytes = Buffer.from(bare.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
  // Non-canonical trailing bits decode to the same bytes; the layer refuses them, so do we.
  const canonical = bytes.toString('base64').replace(/=$/, '');
  return canonical === bare.replaceAll('-', '+').replaceAll('_', '/') ? bytes : undefined;
}

/** A new pglite-encfs master key: 32 random bytes, base64. */
export function newPgliteKey(random: (size: number) => Buffer): string {
  return random(32).toString('base64');
}

/**
 * The key-check value (KCV) of a pglite-encfs master key, hex: HKDF-SHA256 with salt
 * `di-framework/encfs/v1` and info `key-check-value`, 16 bytes. It is what the layer writes to
 * bytes 8..24 of the data directory's `.di-encfs` marker and to bytes 32..48 of every file header,
 * so it says which key opens which volume or backup. It is one-way and safe to record.
 */
export function pgliteKeyCheckValue(key: string): string {
  const master = decodePgliteKey(key);
  if (master === undefined) throw new Error(`${PGLITE_KEY} must be 32 random bytes, base64`);
  const kcv = Buffer.from(
    hkdfSync('sha256', master, 'di-framework/encfs/v1', 'key-check-value', 16),
  ).toString('hex');
  master.fill(0);
  return kcv;
}

/**
 * pglite-encfs keys in a values file: each set key is 32 bytes of base64, the previous key comes
 * only with a current key and differs from it. Errors name the setting, never its value.
 */
export function assertPgliteKeys(values: Record<string, string>, source: string): void {
  for (const name of PGLITE_KEY_NAMES) {
    const key = values[name];
    if (key !== undefined && decodePgliteKey(key) === undefined) {
      throw new Error(`${name} in ${source} must be 32 random bytes, base64 encoded`);
    }
  }
  const previous = values[PGLITE_PREVIOUS_KEY];
  if (previous === undefined) return;
  const current = values[PGLITE_KEY];
  if (current === undefined) {
    throw new Error(`${PGLITE_PREVIOUS_KEY} in ${source} needs ${PGLITE_KEY} (the new key)`);
  }
  if (pgliteKeyCheckValue(current) === pgliteKeyCheckValue(previous)) {
    throw new Error(`${PGLITE_KEY} and ${PGLITE_PREVIOUS_KEY} in ${source} must differ`);
  }
}

/**
 * Adds a pglite-encfs key to `values` when it has none and returns whether it did. An existing key
 * is never replaced: a new key cannot read a data directory written under the old one.
 */
export function ensurePgliteKey(values: Record<string, string>, newKey: () => string): boolean {
  if (values[PGLITE_KEY] !== undefined) return false;
  values[PGLITE_KEY] = newKey();
  return true;
}

/** The KCVs of the keys a values file holds, by name, for custody records. */
export function pgliteKeyCheckValues(values: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    PGLITE_KEY_NAMES.filter((name) => values[name] !== undefined).map((name) => [
      name,
      pgliteKeyCheckValue(values[name] as string),
    ]),
  );
}

/** The guest's `di-framework.config.json` as far as a deploy depends on it. */
export interface GuestConfig {
  /** Project name: the WorkloadDeployment and the `<name>-control` Secret. */
  name: string;
  /** The pinned pglite-encfs layer, or undefined when the data directory is plaintext. */
  encryption?: string;
  controlSecretKeys: string[];
}

/** Environment switch for a plaintext (development) guest; see docs/configuration.md. */
export const PLAINTEXT_OPT_OUT = 'IDENTITY_PGLITE_PLAINTEXT';
const ENCFS_IMAGE = /^ghcr\.io\/di-framework\/pglite-encfs@sha256:[0-9a-f]{64}$/;

export function parseGuestConfig(text: string, source: string): GuestConfig {
  const config = JSON.parse(text) as {
    name?: unknown;
    controlSecretKeys?: unknown;
    pglite?: { encryption?: { image?: unknown; wasm?: unknown } };
  };
  if (typeof config.name !== 'string' || !/^[a-z][a-z0-9-]*$/.test(config.name)) {
    throw new Error(`${source} needs a "name" (lower-case letters, digits and dashes)`);
  }
  const keys = config.controlSecretKeys ?? [];
  if (!Array.isArray(keys) || keys.some((key) => typeof key !== 'string')) {
    throw new Error(`${source} "controlSecretKeys" must be an array of names`);
  }
  const encryption = config.pglite?.encryption;
  if (encryption !== undefined && encryption.wasm !== undefined) {
    throw new Error(`${source} pglite.encryption.wasm is a local build; deploy a pinned image`);
  }
  if (encryption !== undefined && !ENCFS_IMAGE.test(String(encryption.image))) {
    throw new Error(
      `${source} pglite.encryption.image must pin ghcr.io/di-framework/pglite-encfs by digest`,
    );
  }
  return {
    name: config.name,
    ...(encryption === undefined ? {} : { encryption: String(encryption.image) }),
    controlSecretKeys: keys as string[],
  };
}

/**
 * Whether `values` can be deployed with `config`, before anything on the cluster changes:
 * - every value name is declared in `controlSecretKeys`, so `di-framework platform deploy` keeps
 *   the control Secret instead of refusing it for holding keys it did not write;
 * - an encrypted guest has its `DI_PGLITE_KEY` (without it the layer refuses to start);
 * - a plaintext guest is deployed only with the explicit development opt-out, and never with a
 *   values file that holds a pglite key, since its data directory would be encrypted.
 * Returns the KCVs of the keys, for the log.
 */
export function assertDeployable(
  config: GuestConfig,
  values: Record<string, string>,
  options: { allowPlaintext: boolean; source: string },
): Record<string, string> {
  const undeclared = Object.keys(values).filter((name) => !config.controlSecretKeys.includes(name));
  if (undeclared.length > 0) {
    throw new Error(
      `controlSecretKeys in di-framework.config.json does not declare ${undeclared.join(', ')} from ${options.source}`,
    );
  }
  if (config.encryption !== undefined) {
    if (values[PGLITE_KEY] === undefined) {
      throw new Error(
        `${options.source} has no ${PGLITE_KEY}, which the encrypted data directory needs; add one with \`runtime-secrets.ts pglite-key\` (a new volume only)`,
      );
    }
    return pgliteKeyCheckValues(values);
  }
  if (!options.allowPlaintext) {
    throw new Error(
      `di-framework.config.json has no pglite.encryption, so the data directory would be plaintext. That is for development only: set ${PLAINTEXT_OPT_OUT}=1 to deploy it anyway`,
    );
  }
  const keys = PGLITE_KEY_NAMES.filter((name) => values[name] !== undefined);
  if (keys.length > 0) {
    throw new Error(
      `${options.source} holds ${keys.join(', ')}, so its data directory is encrypted; a plaintext build cannot read it`,
    );
  }
  return {};
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

/** The stack's kube target settings as configured (any of them may be unset or empty). */
export interface KubeTargetConfig {
  kubeInstance?: string;
  kubeStateDir?: string;
  kubeconfig?: string;
  context?: string;
}

/** The one resolved kube target that both the preflight and `KubeInstance` (`runKube`) use. */
export interface KubeTarget {
  instance: string;
  /** The configured state directory, absolute; undefined lets kube use its default. */
  configuredStateDir?: string;
  /** The state directory kube will actually use: `configuredStateDir` or kube's default. */
  stateDir: string;
  /** An existing cluster's kubeconfig, absolute. */
  kubeconfig?: string;
  context?: string;
}

/**
 * Normalises the kube settings once. kube's runner treats an empty string as unset (no
 * `--state-dir`, no `--kubeconfig`), so the preflight must too; otherwise `kubeStateDir: ""`
 * would point the check at `/<instance>` while kube upgrades the instance in its default
 * directory. Paths are made absolute against the program's directory, so the dynamic provider's
 * working directory cannot change which instance kube sees.
 */
export function resolveKubeTarget(
  config: KubeTargetConfig,
  host: {
    resolve(path: string): string;
    platform: string;
    home: string;
    env: Readonly<Record<string, string | undefined>>;
  },
): KubeTarget {
  const set = (value: string | undefined) => value?.trim() || undefined;
  const configuredStateDir = set(config.kubeStateDir);
  const kubeconfig = set(config.kubeconfig);
  const stateDir = configuredStateDir === undefined ? undefined : host.resolve(configuredStateDir);
  return {
    instance: set(config.kubeInstance) ?? 'identity',
    configuredStateDir: stateDir,
    stateDir: stateDir ?? defaultKubeStateDir(host.platform, host.home, host.env),
    kubeconfig: kubeconfig === undefined ? undefined : host.resolve(kubeconfig),
    context: set(config.context),
  };
}
