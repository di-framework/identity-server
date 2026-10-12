#!/usr/bin/env bun
/**
 * Installs an imported, encrypted identity data directory into a NEW tenant's workload storage
 * on the kube node, before the guest's first start. docs/guest-http-api.md#authproto-cutover is
 * the runbook; install-core.ts has the platform's storage layout.
 *
 *   bun deploy/cutover/install.ts --data <data-dir> --values <values.json>
 *       --kubeconfig <path> [--context <name>] --tenant <name> [--workload identity]
 *       [--storage-root <path>] [--node <name>] [--image busybox:1.37.0]
 *       [--namespace kube-system] [--yes]
 *
 * Without --yes it is a dry run: it reads the tenant's uid, the node's storage root (from the
 * host paths the platform already mounts, or --storage-root), the node, and checks the tenant,
 * then prints the plan and changes nothing. With --yes it also:
 *
 *   1. starts a helper pod on the node (the image the platform's storage init uses, root with
 *      CHOWN, FOWNER and DAC_OVERRIDE only) with `<root>/di-tenants/<uid>/workloads` mounted;
 *   2. refuses unless `workloads/<workload>` is absent or empty;
 *   3. streams the directory in as a tar archive on kubectl's stdin;
 *   4. sets owner 65532:65532 (the tenant host's uid), directories 0700, files 0600;
 *   5. compares every file's SHA-256 on the node with the local file, and the owner;
 *   6. deletes the helper pod (also on failure).
 *
 * Refuses: a tenant with the Postgres `directory` BackingService; a data directory whose
 * `.di-encfs` KCV is not the values file's DI_PGLITE_KEY KCV; an existing, non-empty target.
 * Prints paths, counts and KCVs only. The guest's WorkloadDeployment may not exist yet; deploy
 * it with deploy/guest/deploy.sh afterwards.
 */
import { readFileSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  assertPrivateMode,
  type Kubectl,
  PGLITE_KEY,
  parseRuntimeValues,
  pgliteKeyCheckValue,
  refuseLegacyTenant,
} from '../platform/components/control-secret.ts';
import {
  compareDigests,
  discoverStorageRoot,
  entries,
  HOST_UID,
  helperPod,
  localTree,
  singleNode,
  tarball,
  tenantUid,
  workloadStoragePath,
} from './install-core.ts';

const { values: args } = parseArgs({
  options: {
    data: { type: 'string' },
    values: { type: 'string' },
    kubeconfig: { type: 'string' },
    context: { type: 'string' },
    tenant: { type: 'string' },
    workload: { type: 'string', default: 'identity' },
    'storage-root': { type: 'string' },
    node: { type: 'string' },
    image: { type: 'string', default: 'busybox:1.37.0' },
    namespace: { type: 'string', default: 'kube-system' },
    yes: { type: 'boolean', default: false },
  },
});

function required(name: keyof typeof args): string {
  const value = args[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`--${name} is required`);
  return value;
}

const kubectl: Kubectl = async (argv, input) => {
  const child = Bun.spawn(
    [
      'kubectl',
      '--kubeconfig',
      required('kubeconfig'),
      ...(args.context ? ['--context', args.context] : []),
      ...argv,
    ],
    {
      stdin: input === undefined ? 'ignore' : new Blob([input]),
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
  const [stdout, stderr] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { code: await child.exited, stdout, stderr };
};

/** kubectl exec in the helper pod, with optional binary stdin. */
async function exec(pod: string, script: string, input?: Uint8Array): Promise<string> {
  const child = Bun.spawn(
    [
      'kubectl',
      '--kubeconfig',
      required('kubeconfig'),
      ...(args.context ? ['--context', args.context] : []),
      '--namespace',
      args.namespace as string,
      'exec',
      ...(input ? ['-i'] : []),
      pod,
      '--',
      'sh',
      '-c',
      script,
    ],
    { stdin: input ? new Blob([input]) : 'ignore', stdout: 'pipe', stderr: 'pipe' },
  );
  const [stdout, stderr] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  const code = await child.exited;
  if (code !== 0)
    throw new Error(`helper step failed (exit ${code}): ${stderr.trim().slice(0, 300)}`);
  return stdout;
}

async function main(): Promise<void> {
  const data = required('data');
  const tenant = required('tenant');
  const workload = args.workload as string;
  const valuesPath = required('values');
  assertPrivateMode(statSync(valuesPath).mode, valuesPath);
  const values = parseRuntimeValues(readFileSync(valuesPath, 'utf8'), valuesPath);
  const key = values[PGLITE_KEY];
  if (!key) throw new Error(`${valuesPath} has no ${PGLITE_KEY}`);
  const kcv = pgliteKeyCheckValue(key);
  const tree = localTree(data);
  if (tree.markerKcv !== kcv) {
    throw new Error(
      `${data} is encrypted under KCV ${tree.markerKcv}, the values file's key has KCV ${kcv}; refusing`,
    );
  }
  await refuseLegacyTenant(kubectl, `di-tenant-${tenant}`);
  const uid = await tenantUid(kubectl, tenant);
  const root = args['storage-root'] ?? (await discoverStorageRoot(kubectl));
  const target = workloadStoragePath(root, uid, workload);
  const node = args.node ?? (await singleNode(kubectl));
  const existing = await kubectl([
    '--namespace',
    `di-tenant-${tenant}`,
    'get',
    'workloaddeployment',
    workload,
    '--ignore-not-found',
    '-o',
    'name',
  ]);
  console.log(`tenant ${tenant} (uid ${uid}), node ${node}`);
  console.log(`target ${target} (the guest's /data)`);
  console.log(
    `source ${data}: ${tree.files.length} files, ${tree.directories.length} directories, ${tree.bytes} bytes; .di-encfs KCV ${tree.markerKcv} = values KCV`,
  );
  if (existing.stdout.trim()) {
    console.log(
      `note: WorkloadDeployment ${workload} already exists in di-tenant-${tenant}; the target must still be empty`,
    );
  }
  if (!args.yes) {
    console.log('dry run: nothing changed. Re-run with --yes to install.');
    return;
  }

  const pod = `identity-cutover-install-${Date.now().toString(36)}`;
  const namespace = args.namespace as string;
  const manifest = helperPod({
    name: pod,
    namespace,
    node,
    image: args.image as string,
    workloadsDir: target.slice(0, target.lastIndexOf('/')),
  });
  const created = await kubectl(['create', '-f', '-'], JSON.stringify(manifest));
  if (created.code !== 0) throw new Error(`cannot create the helper pod: ${created.stderr.trim()}`);
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
    const dir = `/workloads/${workload}`;
    const present = entries(await exec(pod, `mkdir -p ${dir} && ls -A ${dir}`));
    if (present.length > 0) {
      throw new Error(`${target} is not empty (${present.length} entries); refusing to install`);
    }
    await exec(pod, `tar -x -f - -C ${dir}`, tarball(data, tree));
    await exec(
      pod,
      `cd ${dir} && chown -R ${HOST_UID}:${HOST_UID} . && find . -type d -exec chmod 700 {} + && find . -type f -exec chmod 600 {} +`,
    );
    const digests = compareDigests(
      tree,
      await exec(pod, `cd ${dir} && find . -type f -exec sha256sum {} +`),
    );
    const foreign = entries(await exec(pod, `cd ${dir} && find . ! -user ${HOST_UID}`));
    console.log(
      `installed: ${digests.matched}/${tree.files.length} files match, ${digests.missing.length} missing, ${digests.changed.length} changed, ${digests.extra.length} extra; ${foreign.length} not owned by ${HOST_UID}`,
    );
    if (
      digests.missing.length + digests.changed.length + digests.extra.length + foreign.length >
      0
    ) {
      throw new Error('the installed directory does not match; do not start the guest on it');
    }
    console.log(
      `next: IDENTITY_AUTHPROTO_CUTOVER=... deploy/guest/deploy.sh <instance> ${tenant} ${valuesPath}`,
    );
  } finally {
    await kubectl(['--namespace', namespace, 'delete', 'pod', pod, '--wait=false']);
  }
}

try {
  await main();
} catch (error) {
  console.error(`install: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 2;
}
