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
 * Writes <dir> (mode 0700, must be new or empty), every file mode 0600:
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
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { privateFile, readSource, type SourceSession, sha256, writeExport } from './export-core.ts';

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

async function run(
  argv: string[],
  input?: string,
): Promise<{ code: number; stdout: Uint8Array; stderr: string }> {
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
}

/** kubectl bound to the kubeconfig and namespace. */
const kubectl = (...rest: string[]) => [
  'kubectl',
  '--kubeconfig',
  required('kubeconfig'),
  ...(args.context ? ['--context', args.context] : []),
  '--namespace',
  required('namespace'),
  ...rest,
];

async function execPrefix(): Promise<string[]> {
  if (args.podman) return ['podman', 'exec', '-i', args.podman];
  let pod = args.pod;
  if (!pod) {
    const service = required('service');
    const listed = await run(
      kubectl(
        'get',
        'pods',
        '-l',
        `app=di-bs-${service}`,
        '-o',
        'jsonpath={range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\\n"}{end}',
      ),
    );
    const pods = new TextDecoder().decode(listed.stdout).split('\n').filter(Boolean);
    if (listed.code !== 0 || pods.length !== 1) {
      throw new Error(
        `expected one Running pod labelled app=di-bs-${service}, found ${pods.length} (kubectl exit ${listed.code}); pass --pod`,
      );
    }
    pod = pods[0] as string;
  }
  return kubectl('exec', '-i', pod, ...(args.container ? ['-c', args.container] : []), '--');
}

function failure(what: string, result: { code: number; stderr: string }): Error {
  // psql and pg_dump errors name objects, not values; keep them short anyway.
  return new Error(`${what} failed (exit ${result.code}): ${result.stderr.trim().slice(0, 400)}`);
}

async function main(): Promise<void> {
  const out = required('out');
  const prefix = await execPrefix();
  const psql = [
    ...prefix,
    'psql',
    '-X',
    '-q',
    '-A',
    '-t',
    '-v',
    'ON_ERROR_STOP=1',
    '-U',
    args.user as string,
    '-d',
    args.database as string,
    '-f',
    '-',
  ];
  const session: SourceSession = async (sql) => {
    const result = await run(psql, `BEGIN READ ONLY;\n${sql};\nCOMMIT;\n`);
    if (result.code !== 0) throw failure('psql', result);
    return new TextDecoder().decode(result.stdout).replace(/\n$/, '');
  };
  const snapshot = await readSource(session);
  const backup = args['no-backup']
    ? undefined
    : async (dir: string) => {
        const result = await run([
          ...prefix,
          'pg_dump',
          '-Fc',
          '-U',
          args.user as string,
          '-d',
          args.database as string,
        ]);
        if (result.code !== 0) throw failure('pg_dump', result);
        const file = 'directory.dump';
        privateFile(join(dir, file), result.stdout);
        return { file, sha256: sha256(result.stdout) };
      };
  const manifest = await writeExport(out, snapshot, {
    createdAt: new Date().toISOString(),
    backup,
  });
  console.log(`exported ${out} (mode 0700; files 0600; holds secrets and PII)`);
  console.log(
    `source schema V${manifest.source.version} (identity_schema_migrations max ${manifest.source.guestHistoryMax}, _migrations ${manifest.source.runnerHistoryMax ?? 'absent'}, server ${manifest.source.serverVersionNum})`,
  );
  for (const table of manifest.tables) console.log(`  ${table.name}: ${table.count} rows`);
  console.log(`values.json: ${manifest.runtimeRows.values.join(', ')}`);
  console.log(`state.json: ${manifest.runtimeRows.state.join(', ') || 'none'}`);
  console.log(`not carried: ${manifest.runtimeRows.dropped.join(', ') || 'none'}`);
  console.log(`backup: ${manifest.backup ? `${manifest.backup.file} (pg_dump -Fc)` : 'none'}`);
  console.log(
    `next: bun deploy/guest/runtime-secrets.ts pglite-key --values ${join(out, 'values.json')}`,
  );
}

try {
  await main();
} catch (error) {
  console.error(`export: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 2;
}
