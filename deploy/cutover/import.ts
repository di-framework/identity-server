#!/usr/bin/env bun
/**
 * Builds the new guest's encrypted pglite data directory from a cutover export, offline.
 * docs/guest-http-api.md#authproto-cutover is the runbook.
 *
 *   bun deploy/cutover/import.ts --export <dir> --values <values.json> --out <data-dir>
 *       [--provider <encrypted provider wasm>] [--guest <identity.wasm>] [--runner <wasm>]
 *
 * It runs the guest's own engine and encryption layer: the encrypted provider that
 * `di-framework platform build` (cli-plugin-platform 6.2.0 or later) composed for this guest
 * (`apps/guest/.di-framework/di-framework-pglite.encrypted.wasm`), checked to carry the
 * pglite-encfs marker section and to be embedded byte for byte in the built guest
 * (`apps/guest/dist/identity.wasm`, the component deploy.sh pushes). It is plugged into the
 * pglite runner (`deploy/cutover/pglite-runner`, built with cargo if missing) with `wac plug`,
 * and run with `wasmtime run`, `<data-dir>` preopened as `/data` and `DI_PGLITE_KEY` from the
 * values file inherited through the environment (never an argument). The database root is
 * `/data/pglite`, the guest's `DI_PGLITE_DATA_DIR`; the session database is `template1`, the
 * provider's only one (di-framework/platform#212).
 *
 * The import migrates the new database to the export's source version with the guest's
 * migration code, loads every table and the bootstrap fingerprint rows in one transaction, and
 * checks the row counts against the manifest inside it. The guest applies the later
 * migrations on its first start. Afterwards every file of <data-dir> is checked to be encfs
 * ciphertext under the key's KCV, and searched for plaintext.
 *
 * <data-dir> must be new or empty; it ends up mode 0700, ready for install.ts. Prints names,
 * counts and the KCV only. Engine output is not printed; pglite-encfs lines on stderr are.
 */
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { embeddedMigrations } from '../../apps/guest/src/migrations.ts';
import {
  assertPrivateMode,
  PGLITE_KEY,
  parseRuntimeValues,
  pgliteKeyCheckValue,
} from '../platform/components/control-secret.ts';
import { privateDirectory } from './export-core.ts';
import { importExport, loadExport, verifyCiphertext } from './import-core.ts';
import { checkProvider, composeRunner, DEFAULTS, describe, startRunner } from './runner.ts';

const { values: args } = parseArgs({
  options: {
    export: { type: 'string' },
    values: { type: 'string' },
    out: { type: 'string' },
    provider: { type: 'string', default: DEFAULTS.provider },
    guest: { type: 'string', default: DEFAULTS.guest },
    runner: { type: 'string', default: DEFAULTS.runner },
  },
});

function required(name: keyof typeof args): string {
  const value = args[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`--${name} is required`);
  return value;
}

/** Plaintext that must not appear on disk: engine strings and the users' logins and emails. */
function needlesOf(rows: Map<string, string>): string[] {
  const users = JSON.parse(rows.get('users') ?? '[]') as Array<Record<string, unknown>>;
  const fromUsers = users.flatMap((user) =>
    [user.login, user.email].filter(
      (value): value is string => typeof value === 'string' && value.length >= 6,
    ),
  );
  return ['PostgreSQL', 'pg_catalog', 'template1', ...fromUsers];
}

async function main(): Promise<void> {
  const exportDir = required('export');
  const valuesPath = required('values');
  const out = resolve(required('out'));
  const loaded = loadExport(exportDir);
  assertPrivateMode(statSync(valuesPath).mode, valuesPath);
  const values = parseRuntimeValues(readFileSync(valuesPath, 'utf8'), valuesPath);
  const key = values[PGLITE_KEY];
  if (!key) {
    throw new Error(
      `${valuesPath} has no ${PGLITE_KEY}; run \`bun deploy/guest/runtime-secrets.ts pglite-key --values ${valuesPath}\` first`,
    );
  }
  const kcv = pgliteKeyCheckValue(key);
  console.log(`${PGLITE_KEY} KCV ${kcv}`);
  checkProvider(args.provider as string, args.guest as string);
  const work = mkdtempSync(join(tmpdir(), 'identity-cutover-'));
  try {
    const composed = composeRunner({
      provider: args.provider as string,
      runner: args.runner as string,
      out: join(work, 'runner.composed.wasm'),
    });
    privateDirectory(out);
    const runner = await startRunner(composed, out, key);
    let report: Awaited<ReturnType<typeof importExport>>;
    try {
      report = await importExport(runner.database, loaded, embeddedMigrations);
      await runner.database.exec('CHECKPOINT');
    } finally {
      const code = await runner.stop();
      if (code !== 0) console.error(`wasmtime exited ${code}`);
    }
    console.log(`imported into ${out} (source schema V${report.sourceVersion})`);
    console.log(`migrations applied: V1..V${report.migrationsApplied.at(-1)}`);
    for (const table of report.tables) {
      console.log(`  ${table.name}: ${table.imported}/${table.expected} rows`);
    }
    console.log(`bootstrap state rows: ${report.stateRows.join(', ') || 'none'}`);
    console.log(`identity_runtime_secret rows V16 would delete: ${report.rowsV16WouldDelete}`);
    const disk = verifyCiphertext(out, kcv, needlesOf(loaded.rows));
    console.log(
      `on disk: ${disk.files} files, ${disk.encrypted} encfs ciphertext under KCV ${kcv}, ${disk.empty} empty, ${disk.plaintext.length} without a header; .di-encfs KCV matches: ${disk.markerKcvMatches}; plaintext needles found: ${disk.needlesFound}`,
    );
    if (disk.plaintext.length > 0 || !disk.markerKcvMatches || disk.needlesFound > 0) {
      throw new Error(
        'the data directory is not fully encrypted under this key; do not install it',
      );
    }
    console.log(`next: bun deploy/cutover/install.ts --data ${out} ... (dry run first)`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

try {
  await main();
} catch (error) {
  console.error(`import: ${describe(error)}`);
  process.exitCode = 2;
}
