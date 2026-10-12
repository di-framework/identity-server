/**
 * The guest's encrypted pglite provider under wasmtime, for the cutover tools (import.ts and
 * rehearse.ts): the provider `di-framework platform build` composed for this guest, plugged into
 * the pglite runner (`pglite-runner/`) and served to the guest's own adapter through `bridge.ts`.
 *
 * The data directory is preopened as `/data`; `DI_PGLITE_KEY` reaches the encryption layer
 * through `wasmtime run --env DI_PGLITE_KEY`, inherited from this process's child environment,
 * never an argument. Engine output is dropped; `pglite-encfs:` lines on stderr are printed.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { SqlDatabase } from '../../apps/guest/src/database.ts';
import { pgliteDatabase } from '../../apps/guest/src/database.ts';
import { PGLITE_KEY } from '../platform/components/control-secret.ts';
import { bridgeModule, type Channel, replyLine } from './bridge.ts';

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

function tool(name: string): string {
  const found = (name === 'wac' ? process.env.WAC : undefined) ?? Bun.which(name);
  if (!found) throw new Error(`${name} not found on PATH`);
  return found;
}

function runSync(argv: string[], cwd?: string): string {
  const child = Bun.spawnSync(argv, { cwd, stdout: 'pipe', stderr: 'pipe' });
  if (child.exitCode !== 0) {
    throw new Error(
      `${argv[0]} failed (exit ${child.exitCode}): ${child.stderr.toString().trim()}`,
    );
  }
  return child.stdout.toString();
}

/** The runner (built with cargo if missing) with `provider` plugged in, written to `out`. */
export function composeRunner(options: { provider: string; runner: string; out: string }): string {
  if (!existsSync(options.runner)) {
    console.log('building the pglite runner (cargo, wasm32-wasip2)...');
    runSync(['cargo', 'build', '--locked', '--release', '--target', 'wasm32-wasip2'], RUNNER_DIR);
  }
  runSync([tool('wac'), 'plug', '--plug', options.provider, options.runner, '-o', options.out]);
  const wit = runSync([tool('wasm-tools'), 'component', 'wit', options.out]);
  if (/(^|\s)import (wasi:sockets|di-framework:pglite)/m.test(wit)) {
    throw new Error('the composed runner still imports the database or sockets');
  }
  return options.out;
}

const LOST = '{"err":{"tag":"connection-lost","val":"runner exited"}}';

export interface Runner {
  database: SqlDatabase;
  /** Closes the connection if open, ends the runner and returns wasmtime's exit code. */
  stop(): Promise<number>;
}

/** Starts the composed runner on `dataDir` and opens the guest's database through it. */
export async function startRunner(composed: string, dataDir: string, key: string): Promise<Runner> {
  const child = Bun.spawn(
    ['wasmtime', 'run', '--dir', `${dataDir}::/data`, '--env', PGLITE_KEY, composed],
    {
      env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', [PGLITE_KEY]: key },
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
    },
  );
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
    if (line.startsWith('pglite-encfs:')) console.error(line);
  });
  const channel: Channel = {
    send(line) {
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
    child.stdin.end();
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
        try {
          await database.close?.();
        } catch {
          // Already closed; ending the runner rolls back anything open.
        }
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
