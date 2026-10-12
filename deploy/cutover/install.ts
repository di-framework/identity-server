#!/usr/bin/env bun
/**
 * Installs an imported, encrypted identity data directory into a NEW tenant's workload storage
 * on the kube node, before the guest's first start. docs/guest-http-api.md#authproto-cutover is
 * the runbook; install-core.ts has the platform's storage layout.
 *
 *   bun deploy/cutover/install.ts --data <data-dir> --values <values.json>
 *       --kubeconfig <path> [--context <name>] --tenant <name> [--workload identity]
 *       [--storage-root <path>] [--node <name>] [--image busybox:1.37.0]
 *       [--namespace kube-system] [--allow-existing-workload] [--yes]
 *
 * Without --yes it is a dry run: it reads the tenant's uid, the node's storage root (from the
 * host paths the platform already mounts, or --storage-root), the node, and checks the tenant,
 * then prints the plan and changes nothing. With --yes it also:
 *
 *   1. starts a helper pod on the node (the image the platform's storage init uses, root with
 *      CHOWN and DAC_OVERRIDE only) with exactly `<root>/di-tenants/<uid>/workloads/<workload>`
 *      mounted;
 *   2. refuses unless that directory is empty, before sending anything;
 *   3. streams the directory in as a tar archive on kubectl's stdin, extracted without owners;
 *   4. sets directories 0700 and files 0600, then owner 65532:65532 (the tenant host's uid);
 *   5. compares every file's SHA-256 on the node with the local file, and the owner;
 *   6. deletes the helper pod, also on failure; a failed delete is an error naming the pod.
 *
 * Refuses: a tenant with the Postgres `directory` BackingService; a data directory whose
 * `.di-encfs` KCV is not the values file's DI_PGLITE_KEY KCV; a non-empty target; a tenant that
 * already has the WorkloadDeployment (its host could initialise the directory first) unless
 * --allow-existing-workload. Prints paths, counts and KCVs only. Deploy the guest with
 * deploy/guest/deploy.sh afterwards.
 */
import { readFileSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  assertPrivateMode,
  PGLITE_KEY,
  parseRuntimeValues,
  pgliteKeyCheckValue,
  refuseLegacyTenant,
} from '../platform/components/control-secret.ts';
import { type InstallKubectl, installCommand } from './install-core.ts';

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
    'allow-existing-workload': { type: 'boolean', default: false },
    yes: { type: 'boolean', default: false },
  },
});

function required(name: keyof typeof args): string {
  const value = args[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`--${name} is required`);
  return value;
}

/** kubectl bound to the kubeconfig and context; stdout is returned, never printed. */
const kubectl: InstallKubectl = async (argv, input) => {
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

try {
  const valuesPath = required('values');
  assertPrivateMode(statSync(valuesPath).mode, valuesPath);
  const values = parseRuntimeValues(readFileSync(valuesPath, 'utf8'), valuesPath);
  const key = values[PGLITE_KEY];
  if (!key) throw new Error(`${valuesPath} has no ${PGLITE_KEY}`);
  await installCommand(
    {
      data: required('data'),
      kcv: pgliteKeyCheckValue(key),
      tenant: required('tenant'),
      workload: args.workload as string,
      storageRoot: args['storage-root'],
      node: args.node,
      image: args.image as string,
      namespace: args.namespace as string,
      allowExistingWorkload: args['allow-existing-workload'] as boolean,
      yes: args.yes as boolean,
      podName: `identity-cutover-install-${Date.now().toString(36)}`,
    },
    {
      kubectl,
      refuseLegacyTenant: (namespace) =>
        refuseLegacyTenant((argv, input) => kubectl(argv, input), namespace),
      log: (line) => console.log(line),
      warn: (line) => console.error(line),
    },
  );
} catch (error) {
  console.error(`install: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 2;
}
