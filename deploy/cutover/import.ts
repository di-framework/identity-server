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
 * <data-dir> must be new or empty; it ends up mode 0700, ready for install.ts. A failed import
 * removes the partly written <data-dir> again. Prints names,
 * counts and the KCV only. Engine output is not printed; pglite-encfs lines on stderr are.
 */
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { embeddedMigrations } from '../../apps/guest/src/migrations.ts';
import {
  composeRunner,
  DEFAULTS,
  describe,
  importCommand,
  runSync,
  startRunner,
  tool,
  wasmtimeArgv,
} from './runner.ts';

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

try {
  const warn = (line: string) => console.error(line);
  await importCommand(
    {
      exportDir: required('export'),
      valuesPath: required('values'),
      out: resolve(required('out')),
      provider: args.provider as string,
      guest: args.guest as string,
      migrations: embeddedMigrations,
    },
    {
      compose: (out) =>
        composeRunner(
          { provider: args.provider as string, runner: args.runner as string, out },
          {
            run: runSync,
            tool: (name) => tool(name, process.env),
            log: (line) => console.log(line),
          },
        ),
      start: (composed, dataDir, key) => startRunner(wasmtimeArgv(composed, dataDir), key, warn),
      log: (line) => console.log(line),
      warn,
    },
  );
} catch (error) {
  console.error(`import: ${describe(error)}`);
  process.exitCode = 2;
}
