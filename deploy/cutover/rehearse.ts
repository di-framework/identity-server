#!/usr/bin/env bun
/**
 * Boots the identity guest's code on a COPY of an imported data directory, before it is
 * installed anywhere, and checks that the cutover keeps what it must.
 * docs/guest-http-api.md#authproto-cutover is the runbook.
 *
 *   bun deploy/cutover/rehearse.ts --data <data-dir> --values <values.json> [--export <dir>]
 *       [--provider ...] [--guest ...] [--runner ...]
 *
 * The copy is opened through the guest's encrypted provider under wasmtime (runner.ts), and
 * rehearse-core.ts runs the guest's request handler on it. Checks (rehearse-core.ts
 * `rehearseChecks`):
 *
 *   - /ready is 200 with every check true, and the schema is at the latest migration;
 *   - the stored bootstrap fingerprint is unchanged, so the guest did not reconcile bootstrap;
 *   - only bootstrap state is left in identity_runtime_secret (V16 deleted nothing it needed);
 *   - the bootstrap organization (the values' AUTH_BOOTSTRAP_ORGANIZATION_SLUG, else the
 *     compiled-in default) exists;
 *   - discovery's issuer is ISSUER_URL and the JWKS serves the kid of AUTH_ACTIVE_PRIVATE_JWK;
 *   - the bootstrap owner and viewer (logins from the values, else the compiled-in defaults)
 *     sign in with the values' bootstrap passwords. A user who changed that password since
 *     bootstrap is a `note`, not a failure, when (and only when) --export proves the stored hash
 *     was carried unchanged; see `classifySignIn` for why the owner gets the same rule;
 *   - the access, directory and provisioner clients authenticate with the values' secrets;
 *   - with --export, every table still has the exported row count, and each bootstrap user's
 *     stored password hash equals the export's (SHA-256 digests compared, never printed).
 *
 * The copy is deleted afterwards; <data-dir> is never opened. Prints check names and results
 * only (`ok`, `note`, `FAIL`). Exit 1 when a check fails; a `note` does not fail.
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  assertPrivateMode,
  PGLITE_KEY,
  parseRuntimeValues,
} from '../platform/components/control-secret.ts';
import { loadExport } from './import-core.ts';
import { type CheckResult, formatResult, rehearseChecks } from './rehearse-core.ts';
import {
  checkProvider,
  composeRunner,
  DATABASE_ROOT,
  DEFAULTS,
  describe,
  runSync,
  startRunner,
  tool,
  wasmtimeArgv,
} from './runner.ts';

const { values: args } = parseArgs({
  options: {
    data: { type: 'string' },
    values: { type: 'string' },
    export: { type: 'string' },
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

async function main(): Promise<void> {
  const valuesPath = required('values');
  assertPrivateMode(statSync(valuesPath).mode, valuesPath);
  const values = parseRuntimeValues(readFileSync(valuesPath, 'utf8'), valuesPath);
  const key = values[PGLITE_KEY];
  if (!key) throw new Error(`${valuesPath} has no ${PGLITE_KEY}`);
  const loaded = args.export ? loadExport(args.export) : undefined;
  checkProvider(args.provider as string, args.guest as string);
  let results: CheckResult[] = [];
  const work = mkdtempSync(join(tmpdir(), 'identity-rehearsal-'));
  try {
    const copy = join(work, 'data');
    cpSync(required('data'), copy, { recursive: true });
    const composed = composeRunner(
      {
        provider: args.provider as string,
        runner: args.runner as string,
        out: join(work, 'runner.composed.wasm'),
      },
      { run: runSync, tool: (name) => tool(name, process.env), log: (line) => console.log(line) },
    );
    const runner = await startRunner(wasmtimeArgv(composed, copy), key, (line) =>
      console.error(line),
    );
    try {
      results = await rehearseChecks(runner.database, values, loaded, {
        databaseRoot: DATABASE_ROOT,
      });
    } finally {
      await runner.stop();
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  for (const result of results) console.log(formatResult(result));
  if (results.some((result) => result.status === 'fail')) process.exitCode = 1;
}

try {
  await main();
} catch (error) {
  console.error(`rehearse: ${describe(error)}`);
  process.exitCode = 2;
}
