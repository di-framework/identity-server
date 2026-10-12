/**
 * A stand-in for the pglite runner (pglite-runner/, under wasmtime) for tests: the same
 * JSON-lines protocol on stdin/stdout, served by the in-process PGlite fixture.
 *
 *   bun fake-runner.ts <data-dir> [marker|exit|plain]
 *
 * `marker` writes the encfs root marker for DI_PGLITE_KEY into <data-dir> (as the encryption
 * layer does on an empty directory), `plain` also writes a plaintext file there, `exit` ends at
 * once with status 3. Engine-like noise goes to stdout and an encfs line to stderr.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { WasmPgRow, WasmPgValue } from '../../../../apps/guest/src/database.ts';
import { pgliteFixture } from '../../../../apps/guest/tests/support/pglite.ts';
import { pgliteKeyCheckValue } from '../../../platform/components/control-secret.ts';
import { fromWire, toWire } from '../../bridge.ts';

type Connection = Record<string, (...args: unknown[]) => unknown>;
type Fixture = ReturnType<typeof pgliteFixture>;

/** One request line to one reply (without the `@pglite ` prefix), as the Rust runner answers. */
export async function serveLine(
  fixture: Fixture,
  state: { connection?: Connection },
  line: string,
): Promise<string> {
  const request = JSON.parse(line) as {
    op: string;
    sql?: string;
    path?: string;
    name?: string;
    params?: Array<{ tag: string; val?: unknown }>;
  };
  if (request.op === 'open') {
    // The fixture returns the connection itself, or an `err` result.
    const opened = (await fixture.module.open(request.path as string)) as Record<string, unknown>;
    if (opened.tag === 'err') return JSON.stringify({ err: opened.val });
    state.connection = opened as Connection;
    return JSON.stringify({ ok: null });
  }
  const db = state.connection as Connection;
  const params = (request.params ?? []).map(fromWire);
  const method = request.op.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());
  const args = request.name ? [request.name] : request.sql ? [request.sql, params] : [];
  const result = (await db[method]?.(...args)) as { tag: string; val: unknown };
  if (result.tag === 'err') return JSON.stringify({ err: result.val });
  const encodeRow = (row: WasmPgRow) =>
    row.map(([name, value]) => [name, toWire(value as WasmPgValue)]);
  const ok =
    request.op === 'run'
      ? String(result.val)
      : request.op === 'query'
        ? (result.val as WasmPgRow[]).map(encodeRow)
        : request.op === 'first'
          ? result.val
            ? encodeRow(result.val as WasmPgRow)
            : null
          : null;
  return JSON.stringify({ ok });
}

if (import.meta.main) {
  const [dataDir, mode = 'marker'] = process.argv.slice(2) as [string, string?];
  if (mode === 'exit') process.exit(3);
  const key = process.env.DI_PGLITE_KEY ?? '';
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(
    join(dataDir, '.di-encfs'),
    Buffer.concat([Buffer.from('DIPGENC0'), Buffer.from(pgliteKeyCheckValue(key), 'hex')]),
  );
  if (mode === 'plain') writeFileSync(join(dataDir, 'PG_VERSION'), 'PostgreSQL 17');
  const fixture = pgliteFixture();
  const state: { connection?: Connection } = {};
  process.stderr.write('pglite-encfs: fake layer ready\nother engine stderr\n');
  process.stdout.write('engine noise on stdout\n');
  let buffer = '';
  for await (const chunk of process.stdin) {
    buffer += chunk.toString();
    for (let index = buffer.indexOf('\n'); index >= 0; index = buffer.indexOf('\n')) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (line.trim()) process.stdout.write(`@pglite ${await serveLine(fixture, state, line)}\n`);
    }
  }
  await fixture.shutdown();
}
