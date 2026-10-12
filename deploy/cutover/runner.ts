/**
 * The guest's encrypted pglite provider under wasmtime, for the cutover tools (import.ts and
 * rehearse.ts): the provider `di-framework platform build` composed for this guest, plugged into
 * the pglite runner (`pglite-runner/`) and served to the guest's own adapter through `bridge.ts`.
 *
 * The data directory is preopened as `/data`; `DI_PGLITE_KEY` reaches the encryption layer
 * through `wasmtime run --env DI_PGLITE_KEY`, inherited from the child's environment, never an
 * argument. Engine output is dropped; `pglite-encfs:` lines on stderr are passed to `warn`.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { SqlDatabase } from '../../apps/guest/src/database.ts';
import { pgliteDatabase } from '../../apps/guest/src/database.ts';
import type { EmbeddedMigration } from '../../apps/guest/src/flyway.ts';
import {
  assertPrivateMode,
  PGLITE_KEY,
  parseRuntimeValues,
  pgliteKeyCheckValue,
} from '../platform/components/control-secret.ts';
import { bridgeModule, type Channel, replyLine } from './bridge.ts';
import { privateDirectory } from './export-core.ts';
import { importExport, loadExport, needlesOf, verifyCiphertext } from './import-core.ts';

export const ROOT = resolve(import.meta.dir, '..', '..');
const RUNNER_DIR = join(import.meta.dir, 'pglite-runner');
export const DEFAULTS = {
  provider: join(ROOT, 'apps/guest/.di-framework/di-framework-pglite.encrypted.wasm'),
  guest: join(ROOT, 'apps/guest/dist/identity.wasm'),
  runner: join(RUNNER_DIR, 'target/wasm32-wasip2/release/identity-pglite-runner.wasm'),
};
/** The guest's `DI_PGLITE_DATA_DIR` inside the `/data` preopen. */
export const DATABASE_ROOT = '/data/pglite';

const ENCFS_SECTION = Buffer.from('di-framework:pglite-encfs');

/** The provider must be encrypted and be byte for byte the one inside the built guest. */
export function checkProvider(provider: string, guest: string): void {
  const bytes = readFileSync(provider);
  if (!bytes.includes(ENCFS_SECTION)) {
    throw new Error(`${provider} has no di-framework:pglite-encfs section: it is not encrypted`);
  }
  if (!readFileSync(guest).includes(bytes)) {
    throw new Error(
      `${provider} is not the provider inside ${guest}; run \`di-framework platform build\` in apps/guest and retry`,
    );
  }
}

/** A tool's path: `WAC` for wac, else PATH. */
export function tool(name: string, env: Readonly<Record<string, string | undefined>>): string {
  const found = (name === 'wac' ? env.WAC : undefined) ?? Bun.which(name, { PATH: env.PATH });
  if (!found) throw new Error(`${name} not found on PATH`);
  return found;
}

/** Runs a command to completion and returns its stdout; a failure names the exit and stderr. */
export function runSync(argv: string[], cwd?: string): string {
  const child = Bun.spawnSync(argv, { cwd, stdout: 'pipe', stderr: 'pipe' });
  if (child.exitCode !== 0) {
    throw new Error(
      `${argv[0]} failed (exit ${child.exitCode}): ${child.stderr.toString().trim()}`,
    );
  }
  return child.stdout.toString();
}

/** The runner (built with cargo if missing) with `provider` plugged in, written to `out`. */
export function composeRunner(
  options: { provider: string; runner: string; out: string },
  deps: {
    run: (argv: string[], cwd?: string) => string;
    tool: (name: string) => string;
    log: (line: string) => void;
  },
): string {
  if (!existsSync(options.runner)) {
    deps.log('building the pglite runner (cargo, wasm32-wasip2)...');
    deps.run(['cargo', 'build', '--locked', '--release', '--target', 'wasm32-wasip2'], RUNNER_DIR);
  }
  deps.run([
    deps.tool('wac'),
    'plug',
    '--plug',
    options.provider,
    options.runner,
    '-o',
    options.out,
  ]);
  const wit = deps.run([deps.tool('wasm-tools'), 'component', 'wit', options.out]);
  if (/(^|\s)import (wasi:sockets|di-framework:pglite)/m.test(wit)) {
    throw new Error('the composed runner still imports the database or sockets');
  }
  return options.out;
}

/** `wasmtime run` of the composed runner with `dataDir` as `/data` and the key inherited. */
export function wasmtimeArgv(composed: string, dataDir: string): string[] {
  return ['wasmtime', 'run', '--dir', `${dataDir}::/data`, '--env', PGLITE_KEY, composed];
}

const LOST = '{"err":{"tag":"connection-lost","val":"runner exited"}}';

export interface Runner {
  database: SqlDatabase;
  /** Closes the connection if open, ends the runner and returns its exit code. */
  stop(): Promise<number>;
}

/**
 * Starts `argv` (the runner under wasmtime) with only PATH, HOME and the key in its environment,
 * and opens the guest's database through it.
 */
export async function startRunner(
  argv: string[],
  key: string,
  warn: (line: string) => void,
): Promise<Runner> {
  const child = Bun.spawn(argv, {
    env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', [PGLITE_KEY]: key },
    stdin: 'pipe',
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const replies: string[] = [];
  const waiting: Array<(line: string) => void> = [];
  let ended = false;
  const lines = async (stream: ReadableStream<Uint8Array>, onLine: (line: string) => void) => {
    const decoder = new TextDecoder();
    let buffer = '';
    for await (const chunk of stream) {
      buffer += decoder.decode(chunk, { stream: true });
      for (let index = buffer.indexOf('\n'); index >= 0; index = buffer.indexOf('\n')) {
        onLine(buffer.slice(0, index));
        buffer = buffer.slice(index + 1);
      }
    }
    if (buffer) onLine(buffer);
  };
  const stdout = lines(child.stdout, (line) => {
    const reply = replyLine(line);
    if (reply === undefined) return;
    const next = waiting.shift();
    if (next) next(reply);
    else replies.push(reply);
  }).finally(() => {
    ended = true;
    for (const next of waiting.splice(0)) next(LOST);
  });
  const stderr = lines(child.stderr, (line) => {
    if (line.startsWith('pglite-encfs:')) warn(line);
  });
  const channel: Channel = {
    send(line) {
      if (ended) return;
      child.stdin.write(`${line}\n`);
      child.stdin.flush();
    },
    receive() {
      const ready = replies.shift();
      if (ready !== undefined) return Promise.resolve(ready);
      if (ended) return Promise.resolve(LOST);
      return new Promise((resolve) => waiting.push(resolve));
    },
  };
  const stop = async () => {
    if (!ended) child.stdin.end();
    await Promise.all([stdout, stderr]);
    return await child.exited;
  };
  try {
    // The guest's own opener, on the guest's database root.
    const database = await pgliteDatabase(bridgeModule(channel), () => ({
      DI_PGLITE_DATA_DIR: DATABASE_ROOT,
    }))();
    return {
      database,
      async stop() {
        await Promise.resolve(database.close?.()).catch(() => undefined);
        return stop();
      },
    };
  } catch (error) {
    await stop();
    throw error;
  }
}

/**
 * A driver error without values: provider errors become their tag and SQLSTATE (a PostgreSQL
 * message can quote a row), the tools' own messages pass through.
 */
export function describe(error: unknown): string {
  if (error instanceof Error) {
    const record = error as Error & { tag?: string; code?: string };
    if (record.tag !== undefined) {
      return `pglite ${record.tag}${record.code ? ` (SQLSTATE ${record.code})` : ''}`;
    }
    return error.message;
  }
  return String(error);
}

/**
 * The whole import (import.ts): checks the values and the provider, composes and starts the
 * runner on a new `out`, imports, checkpoints, and checks the directory on disk. A failure after
 * `out` was created removes it again (it is a partly initialised encrypted directory), and says
 * so. Logs names, counts and the KCV only.
 */
export async function importCommand(
  options: {
    exportDir: string;
    valuesPath: string;
    out: string;
    provider: string;
    guest: string;
    migrations: readonly EmbeddedMigration[];
  },
  deps: {
    compose: (out: string) => string;
    start: (composed: string, dataDir: string, key: string) => Promise<Runner>;
    log: (line: string) => void;
    warn: (line: string) => void;
  },
): Promise<void> {
  const loaded = loadExport(options.exportDir);
  assertPrivateMode(statSync(options.valuesPath).mode, options.valuesPath);
  const values = parseRuntimeValues(readFileSync(options.valuesPath, 'utf8'), options.valuesPath);
  const key = values[PGLITE_KEY];
  if (!key) {
    throw new Error(
      `${options.valuesPath} has no ${PGLITE_KEY}; run \`bun deploy/guest/runtime-secrets.ts pglite-key --values ${options.valuesPath}\` first`,
    );
  }
  const kcv = pgliteKeyCheckValue(key);
  deps.log(`${PGLITE_KEY} KCV ${kcv}`);
  checkProvider(options.provider, options.guest);
  const work = mkdtempSync(join(tmpdir(), 'identity-cutover-'));
  let created = false;
  try {
    const composed = deps.compose(join(work, 'runner.composed.wasm'));
    privateDirectory(options.out);
    created = true;
    const runner = await deps.start(composed, options.out, key);
    let report: Awaited<ReturnType<typeof importExport>>;
    try {
      report = await importExport(runner.database, loaded, options.migrations);
      await runner.database.exec('CHECKPOINT');
    } finally {
      const code = await runner.stop();
      if (code !== 0) deps.warn(`the runner exited ${code}`);
    }
    deps.log(`imported into ${options.out} (source schema V${report.sourceVersion})`);
    deps.log(`migrations applied: V1..V${report.migrationsApplied.at(-1)}`);
    for (const table of report.tables) {
      deps.log(`  ${table.name}: ${table.imported}/${table.expected} rows`);
    }
    deps.log(`bootstrap state rows: ${report.stateRows.join(', ') || 'none'}`);
    deps.log(`identity_runtime_secret rows V16 would delete: ${report.rowsV16WouldDelete}`);
    const disk = verifyCiphertext(options.out, kcv, needlesOf(loaded.rows));
    deps.log(
      `on disk: ${disk.files} files, ${disk.encrypted} encfs ciphertext under KCV ${kcv}, ${disk.empty} empty, ${disk.plaintext.length} without a header; .di-encfs KCV matches: ${disk.markerKcvMatches}; plaintext needles found: ${disk.needlesFound}`,
    );
    if (disk.plaintext.length > 0 || !disk.markerKcvMatches || disk.needlesFound > 0) {
      throw new Error('the data directory is not fully encrypted under this key');
    }
    deps.log(`next: bun deploy/cutover/rehearse.ts --data ${options.out} ... then install.ts`);
  } catch (error) {
    if (created) {
      rmSync(options.out, { recursive: true, force: true });
      throw new Error(`${describe(error)}; removed the partly written ${options.out}`);
    }
    throw error;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
