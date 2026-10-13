/**
 * Places an imported, encrypted data directory into a tenant workload's platform storage on the
 * kube node before the guest's first start (docs/guest-http-api.md#authproto-cutover).
 * `install.ts` is the CLI.
 *
 * Where the directory goes is the platform's rule (di-framework/platform
 * `platform/platform/src/tenancy/workload-storage.ts`): the controller mounts
 * `<storageRoot>/di-tenants/<tenant uid>/workloads/<key>` into the tenant host at
 * `/var/lib/di-framework/workloads/<key>`, and a root init container hands that directory (not its
 * contents) to the host uid 65532. The guest sees it as `/data`. `<key>` is the workload's
 * `di-framework.dev/workload` label, else its `di-framework.dev/application` label, else its name
 * (`storageKey`); cli-plugin-platform sets `di-framework.dev/application` to the config's `name`,
 * so for the identity guest it is `identity`. The files are copied there owned by 65532,
 * directories 0700 and files 0600.
 *
 * Every function takes an injected kubectl; nothing here prints or returns file contents.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Kubectl } from '../platform/components/control-secret.ts';

/** The tenant host's uid (workload-storage.ts HOST_UID). */
export const HOST_UID = 65532;
const TENANTS = 'tenants.platform.di-framework.dev';
const UID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;

export interface LocalFile {
  /** Path relative to the data directory, `/`-separated. */
  path: string;
  size: number;
  sha256: string;
}

export interface LocalTree {
  directories: string[];
  files: LocalFile[];
  bytes: number;
  /** KCV in the `.di-encfs` marker (bytes 8..24), hex. */
  markerKcv: string;
}

/** Lists the data directory to install; it must hold the encfs marker. */
export function localTree(dir: string): LocalTree {
  const marker = readFileSync(join(dir, '.di-encfs'));
  if (marker.length < 24) throw new Error(`${dir}/.di-encfs is not an encfs marker`);
  const tree: LocalTree = {
    directories: [],
    files: [],
    bytes: 0,
    markerKcv: marker.subarray(8, 24).toString('hex'),
  };
  const walk = (path: string, relative: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : 1,
    )) {
      const child = join(path, entry.name);
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        tree.directories.push(name);
        walk(child, name);
      } else if (entry.isFile()) {
        const data = readFileSync(child);
        tree.files.push({
          path: name,
          size: data.length,
          sha256: createHash('sha256').update(data).digest('hex'),
        });
        tree.bytes += data.length;
      } else {
        throw new Error(`${name} is neither a file nor a directory; refusing to install it`);
      }
    }
  };
  walk(dir, '');
  return tree;
}

/** A POSIX ustar archive of the tree (owner 65532, directories 0700, files 0600). */
export function tarball(dir: string, tree: LocalTree): Uint8Array {
  const blocks: Buffer[] = [];
  const header = (name: string, size: number, type: '0' | '5') => {
    const block = Buffer.alloc(512);
    let path = name;
    let prefix = '';
    if (Buffer.byteLength(path) > 100) {
      const split = path.lastIndexOf('/', path.length - 1);
      prefix = path.slice(0, split);
      path = path.slice(split + 1);
      if (Buffer.byteLength(prefix) > 155 || Buffer.byteLength(path) > 100) {
        throw new Error(`${name} is too long for a tar header`);
      }
    }
    const octal = (value: number, width: number) =>
      `${value.toString(8).padStart(width - 1, '0')}\0`;
    block.write(path, 0, 100, 'utf8');
    block.write(octal(type === '5' ? 0o700 : 0o600, 8), 100, 8, 'ascii');
    block.write(octal(HOST_UID, 8), 108, 8, 'ascii');
    block.write(octal(HOST_UID, 8), 116, 8, 'ascii');
    block.write(octal(size, 12), 124, 12, 'ascii');
    block.write(octal(0, 12), 136, 12, 'ascii');
    block.write('        ', 148, 8, 'ascii');
    block.write(type, 156, 1, 'ascii');
    block.write('ustar\0', 257, 6, 'ascii');
    block.write('00', 263, 2, 'ascii');
    block.write(prefix, 345, 155, 'utf8');
    let sum = 0;
    for (const byte of block) sum += byte;
    block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    return block;
  };
  for (const name of tree.directories) blocks.push(header(`${name}/`, 0, '5'));
  for (const file of tree.files) {
    const data = readFileSync(join(dir, file.path));
    if (data.length !== file.size) throw new Error(`${file.path} changed while installing`);
    blocks.push(header(file.path, data.length, '0'), data);
    const pad = (512 - (data.length % 512)) % 512;
    if (pad > 0) blocks.push(Buffer.alloc(pad));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

/** The tenant's uid, from its cluster-scoped Tenant object. */
export async function tenantUid(kubectl: Kubectl, tenant: string): Promise<string> {
  const result = await kubectl(['get', TENANTS, tenant, '-o', 'jsonpath={.metadata.uid}']);
  const uid = result.stdout.trim();
  if (result.code !== 0 || !UID.test(uid)) {
    throw new Error(`cannot read Tenant ${tenant} (kubectl exit ${result.code}); create it first`);
  }
  return uid;
}

/**
 * The node's storage root, from the host paths the platform already mounts
 * (`<root>/di-tenants/<uid>/...`, workload storage and backing services alike). Fails unless
 * every such path agrees on one root.
 */
export async function discoverStorageRoot(kubectl: Kubectl): Promise<string> {
  const result = await kubectl([
    'get',
    'deployments',
    '--all-namespaces',
    '-o',
    'jsonpath={range .items[*]}{range .spec.template.spec.volumes[*]}{.hostPath.path}{"\\n"}{end}{end}',
  ]);
  if (result.code !== 0) {
    throw new Error(`cannot list deployments (kubectl exit ${result.code}); pass --storage-root`);
  }
  const roots = new Set<string>();
  for (const line of result.stdout.split('\n')) {
    const match = /^(\/.+?)\/di-tenants\/[0-9a-f-]{36}(\/|$)/.exec(line.trim());
    if (match?.[1]) roots.add(match[1]);
  }
  if (roots.size !== 1) {
    throw new Error(
      `found ${roots.size === 0 ? 'no' : 'several'} platform storage roots (${[...roots].join(', ')}); pass --storage-root`,
    );
  }
  return [...roots][0] as string;
}

/** The node directory the platform mounts as the workload's `/data`. */
export function workloadStoragePath(root: string, uid: string, workload: string): string {
  if (!root.startsWith('/') || root.includes('..')) throw new Error(`invalid storage root ${root}`);
  if (!UID.test(uid)) throw new Error(`invalid tenant uid ${uid}`);
  if (!KEY.test(workload) || workload.length > 50) throw new Error(`invalid workload ${workload}`);
  return `${root.replace(/\/+$/, '')}/di-tenants/${uid}/workloads/${workload}`;
}

/** The node the helper pod runs on: the only node, or the one passed. */
export async function singleNode(kubectl: Kubectl): Promise<string> {
  const result = await kubectl(['get', 'nodes', '-o', 'jsonpath={.items[*].metadata.name}']);
  const nodes = result.stdout.trim().split(/\s+/).filter(Boolean);
  if (result.code !== 0 || nodes.length !== 1) {
    throw new Error(`expected one node, found ${nodes.length}; pass --node`);
  }
  return nodes[0] as string;
}

/**
 * The helper pod: the fixed image the platform's own storage init uses, root with only CHOWN
 * (hand the files to the host uid) and DAC_OVERRIDE (write into a directory the host uid may
 * already own), pinned to the node, with exactly the target directory mounted at `/target`
 * (`DirectoryOrCreate`). The archive is extracted without its owners, so root owns the files
 * while their modes are set, and only then are they handed over. It sleeps until removed.
 */
export function helperPod(options: {
  name: string;
  namespace: string;
  node: string;
  image: string;
  target: string;
}): Record<string, unknown> {
  return {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: {
      name: options.name,
      namespace: options.namespace,
      labels: { 'app.kubernetes.io/name': 'identity-cutover-install' },
    },
    spec: {
      nodeName: options.node,
      restartPolicy: 'Never',
      automountServiceAccountToken: false,
      containers: [
        {
          name: 'install',
          image: options.image,
          imagePullPolicy: 'IfNotPresent',
          command: ['sleep', '3600'],
          securityContext: {
            runAsUser: 0,
            runAsGroup: 0,
            runAsNonRoot: false,
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: { drop: ['ALL'], add: ['CHOWN', 'DAC_OVERRIDE'] },
          },
          volumeMounts: [{ name: 'target', mountPath: '/target' }],
        },
      ],
      volumes: [{ name: 'target', hostPath: { path: options.target, type: 'DirectoryOrCreate' } }],
    },
  };
}

/** `sha256sum` lines (`<hex>  ./<path>`) from the node, against the local tree. */
export function compareDigests(
  tree: LocalTree,
  remote: string,
): { matched: number; missing: string[]; changed: string[]; extra: string[] } {
  const seen = new Map<string, string>();
  for (const line of remote.split('\n')) {
    const match = /^([0-9a-f]{64}) {2}\.\/(.+)$/.exec(line.trim());
    if (match?.[1] && match[2]) seen.set(match[2], match[1]);
  }
  const missing: string[] = [];
  const changed: string[] = [];
  let matched = 0;
  for (const file of tree.files) {
    const digest = seen.get(file.path);
    if (digest === undefined) missing.push(file.path);
    else if (digest !== file.sha256) changed.push(file.path);
    else matched += 1;
    seen.delete(file.path);
  }
  return { matched, missing, changed, extra: [...seen.keys()].sort() };
}

/** The names in an `ls -A` listing. */
export function entries(listing: string): string[] {
  return listing
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

/** kubectl that may take binary stdin (the archive). */
export type InstallKubectl = (
  args: string[],
  input?: string | Uint8Array,
) => Promise<{ code: number | null; stdout: string; stderr: string }>;

export interface InstallOptions {
  data: string;
  /** The values file's DI_PGLITE_KEY KCV. */
  kcv: string;
  tenant: string;
  workload: string;
  storageRoot?: string;
  node?: string;
  image: string;
  namespace: string;
  /** Install although the tenant already has the WorkloadDeployment (its host may race us). */
  allowExistingWorkload: boolean;
  yes: boolean;
  podName: string;
}

/**
 * The install (install.ts). Reads and checks everything first (marker KCV against the values,
 * the tenant's `directory`, the tenant uid, the storage root, the node, no WorkloadDeployment
 * yet); without `yes` it stops there. With `yes` it runs the helper pod, refuses a non-empty
 * target before sending anything, extracts the archive, sets the modes below the target (and the
 * target's own 0700 only when root owns it, i.e. kubelet just created it) then owner, compares every
 * digest and owner, and always deletes the pod: a failed delete is an error that names the pod.
 */
export async function installCommand(
  options: InstallOptions,
  deps: {
    kubectl: InstallKubectl;
    refuseLegacyTenant: (namespace: string) => Promise<void>;
    log: (line: string) => void;
    warn: (line: string) => void;
  },
): Promise<'dry-run' | 'installed'> {
  const tree = localTree(options.data);
  if (tree.markerKcv !== options.kcv) {
    throw new Error(
      `${options.data} is encrypted under KCV ${tree.markerKcv}, the values file's key has KCV ${options.kcv}; refusing`,
    );
  }
  const kubectl: Kubectl = (args, input) =>
    deps.kubectl(args, input).then((result) => ({ ...result }));
  await deps.refuseLegacyTenant(`di-tenant-${options.tenant}`);
  const uid = await tenantUid(kubectl, options.tenant);
  const root = options.storageRoot ?? (await discoverStorageRoot(kubectl));
  const target = workloadStoragePath(root, uid, options.workload);
  const node = options.node ?? (await singleNode(kubectl));
  const existing = await kubectl([
    '--namespace',
    `di-tenant-${options.tenant}`,
    'get',
    'workloaddeployment',
    options.workload,
    '--ignore-not-found',
    '-o',
    'name',
  ]);
  if (existing.code !== 0) {
    throw new Error(
      `cannot check for WorkloadDeployment ${options.workload} (kubectl exit ${existing.code})`,
    );
  }
  if (existing.stdout.trim() && !options.allowExistingWorkload) {
    throw new Error(
      `WorkloadDeployment ${options.workload} already exists in di-tenant-${options.tenant}; its host may initialise the directory first. Install before deploying, or pass --allow-existing-workload`,
    );
  }
  deps.log(`tenant ${options.tenant} (uid ${uid}), node ${node}`);
  deps.log(`target ${target} (the guest's /data)`);
  deps.log(
    `source ${options.data}: ${tree.files.length} files, ${tree.directories.length} directories, ${tree.bytes} bytes; .di-encfs KCV ${tree.markerKcv} = values KCV`,
  );
  if (!options.yes) {
    deps.log('dry run: nothing changed. Re-run with --yes to install.');
    return 'dry-run';
  }

  const pod = options.podName;
  const namespace = options.namespace;
  const manifest = helperPod({ name: pod, namespace, node, image: options.image, target });
  const created = await kubectl(['create', '-f', '-'], JSON.stringify(manifest));
  if (created.code !== 0) throw new Error(`cannot create the helper pod: ${created.stderr.trim()}`);
  const exec = async (script: string, input?: Uint8Array) => {
    const result = await deps.kubectl(
      ['--namespace', namespace, 'exec', ...(input ? ['-i'] : []), pod, '--', 'sh', '-c', script],
      input,
    );
    if (result.code !== 0) {
      throw new Error(
        `helper step failed (exit ${result.code}): ${result.stderr.trim().slice(0, 300)}`,
      );
    }
    return result.stdout;
  };
  let failed: unknown;
  try {
    const ready = await kubectl([
      '--namespace',
      namespace,
      'wait',
      '--for=condition=Ready',
      `pod/${pod}`,
      '--timeout=180s',
    ]);
    if (ready.code !== 0) throw new Error(`the helper pod did not start: ${ready.stderr.trim()}`);
    const present = entries(await exec('ls -A /target'));
    if (present.length > 0) {
      throw new Error(`${target} is not empty (${present.length} entries); refusing to install`);
    }
    // Who owns the target itself: root when kubelet just created it, the host uid when the
    // platform's storage init already handed it over. Without FOWNER root cannot chmod a
    // directory it does not own, so the target's own mode is set only in the first case.
    const [ownerBefore, modeBefore] = (await exec("stat -c '%u %a' /target")).trim().split(/\s+/);
    const fresh = ownerBefore === '0';
    await exec('tar -x -o -f - -C /target', tarball(options.data, tree));
    await exec(
      'cd /target && find . -mindepth 1 -type d -exec chmod 700 {} + && ' +
        'find . -mindepth 1 -type f -exec chmod 600 {} + && ' +
        `${fresh ? 'chmod 700 . && ' : ''}chown -R ${HOST_UID}:${HOST_UID} .`,
    );
    const modeAfter = (await exec('stat -c %a /target')).trim();
    if (fresh && modeAfter !== '700') {
      throw new Error(`${target} has mode ${modeAfter} after the install, not 700`);
    }
    if (!fresh) {
      deps.log(
        `the target was owned by uid ${ownerBefore} before the install (the platform's storage init); its mode ${modeBefore} is left as it was`,
      );
    }
    const digests = compareDigests(
      tree,
      await exec('cd /target && find . -type f -exec sha256sum {} +'),
    );
    const foreign = entries(await exec(`cd /target && find . ! -user ${HOST_UID}`));
    deps.log(
      `installed: ${digests.matched}/${tree.files.length} files match, ${digests.missing.length} missing, ${digests.changed.length} changed, ${digests.extra.length} extra; ${foreign.length} not owned by ${HOST_UID}`,
    );
    if (
      digests.missing.length + digests.changed.length + digests.extra.length + foreign.length >
      0
    ) {
      throw new Error('the installed directory does not match; do not start the guest on it');
    }
  } catch (error) {
    failed = error;
  }
  const removed = await kubectl(['--namespace', namespace, 'delete', 'pod', pod, '--wait=false']);
  if (removed.code !== 0) {
    const message = `could not delete the helper pod ${namespace}/${pod} (kubectl exit ${removed.code}); it mounts ${target} as root. Delete it by hand: kubectl --namespace ${namespace} delete pod ${pod}`;
    if (failed) deps.warn(message);
    else throw new Error(message);
  }
  if (failed) throw failed;
  return 'installed';
}
