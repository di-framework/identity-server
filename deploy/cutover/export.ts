#!/usr/bin/env bun
/**
 * Exports the Postgres-era identity database (authproto's `directory` BackingService) for the
 * cutover to the pglite guest. docs/guest-http-api.md#authproto-cutover is the runbook.
 *
 *   bun deploy/cutover/export.ts --out <dir>
 *       --kubeconfig <path> [--context <name>] --namespace <ns> (--pod <name> | --service <name>)
 *       [--container <name>] [--user app] [--database app] [--no-backup]
 *   bun deploy/cutover/export.ts --out <dir> --podman <container> [--user ...] [--database ...]
 *
 * psql and pg_dump run inside the database pod (`kubectl exec`) or a local Postgres container
 * (`podman exec`, for rehearsals); the SQL goes on their stdin. `--service directory` finds the
 * pod by its `app=di-bs-<service>` label. Only reads: one read-only statement for the
 * inventory, one for the snapshot, and `pg_dump -Fc` for the backup.
 *
 * Writes <dir> (mode 0700, must be new or empty), every file mode 0600, through a sibling that is
 * renamed into place only when complete (a failed export leaves nothing behind):
 *   manifest.json      source schema version, tables, columns, row counts, digests; no values
 *   tables/<t>.json    each table's rows as JSON text
 *   values.json        the deploy.sh values file: every identity_runtime_secret setting row
 *   state.json         the bootstrap fingerprint rows, carried into the new database
 *   directory.dump     pg_dump -Fc of the whole source database (rollback backup)
 *
 * values.json, state.json, tables/ and directory.dump hold secrets and PII: keep <dir> on an
 * encrypted volume and destroy it after the cutover. Nothing is printed but names and counts.
 * Refuses a schema outside V13..V15 and runtime rows the new guest has no setting for.
 */
import { parseArgs } from 'node:util';
import { type ExportTarget, exportCommand, type Run } from './export-core.ts';

const { values: args } = parseArgs({
  options: {
    out: { type: 'string' },
    kubeconfig: { type: 'string' },
    context: { type: 'string' },
    namespace: { type: 'string' },
    pod: { type: 'string' },
    service: { type: 'string' },
    container: { type: 'string' },
    podman: { type: 'string' },
    user: { type: 'string', default: 'app' },
    database: { type: 'string', default: 'app' },
    'no-backup': { type: 'boolean', default: false },
  },
});

function required(name: keyof typeof args): string {
  const value = args[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`--${name} is required`);
  return value;
}

/** Runs a process to completion; stdout is returned, never printed. */
const run: Run = async (argv, input) => {
  const child = Bun.spawn(argv, {
    stdin: input === undefined ? 'ignore' : new Blob([input]),
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr] = await Promise.all([
    new Response(child.stdout).bytes(),
    new Response(child.stderr).text(),
  ]);
  return { code: await child.exited, stdout, stderr };
};

try {
  const target: ExportTarget = args.podman
    ? { podman: args.podman }
    : {
        kubeconfig: required('kubeconfig'),
        context: args.context,
        namespace: required('namespace'),
        pod: args.pod,
        service: args.service,
        container: args.container,
      };
  await exportCommand(
    {
      out: required('out'),
      target,
      user: args.user as string,
      database: args.database as string,
      backup: !args['no-backup'],
      createdAt: new Date().toISOString(),
    },
    { run, log: (line) => console.log(line) },
  );
} catch (error) {
  console.error(`export: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 2;
}
