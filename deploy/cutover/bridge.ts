/**
 * `di-framework:pglite/database@0.2.0` as a `WasmPgliteModule`, served by the pglite runner
 * (`pglite-runner/`, a wasip2 command with the guest's encrypted provider plugged in) over its
 * stdin and stdout. The importer hands this module to `createWasmPgliteDatabase`, the guest's own
 * adapter, so the import runs the guest's SQL path on the guest's engine and encryption layer.
 *
 * Protocol: one JSON request per line; one reply per line, prefixed with `@pglite ` (the engine
 * also writes to stdout, and those lines are skipped). `integer` values travel as decimal
 * strings, `real` as strings and `blob` as hex. Replies and requests carry SQL, parameters and
 * rows, so neither is ever logged.
 */
import type {
  WasmPgliteConnection,
  WasmPgliteModule,
  WasmPgRow,
  WasmPgValue,
} from '../../apps/guest/src/database.ts';

/** One line out, and the next reply line in (without the prefix). */
export interface Channel {
  send(line: string): void;
  receive(): Promise<string>;
}

export const REPLY_PREFIX = '@pglite ';

type WireValue = { tag: string; val?: unknown };
type Reply = { ok: unknown } | { err: { tag: string; val?: unknown } };

export function toWire(value: WasmPgValue): WireValue {
  switch (value.tag) {
    case 'null':
      return { tag: 'null' };
    case 'integer':
    case 'real':
      return { tag: value.tag, val: String(value.val) };
    case 'blob':
      return { tag: 'blob', val: Buffer.from(Uint8Array.from(value.val)).toString('hex') };
    default:
      return { tag: value.tag, val: value.val };
  }
}

export function fromWire(value: WireValue): WasmPgValue {
  switch (value.tag) {
    case 'null':
      return { tag: 'null' };
    case 'integer':
      return { tag: 'integer', val: BigInt(value.val as string) };
    case 'real':
      return { tag: 'real', val: Number(value.val) };
    case 'blob':
      return { tag: 'blob', val: Uint8Array.from(Buffer.from(value.val as string, 'hex')) };
    default:
      return value as WasmPgValue;
  }
}

const rowFromWire = (row: Array<[string, WireValue]>): WasmPgRow =>
  row.map(([name, value]) => [name, fromWire(value)]);

/** Lines from the runner's stdout: replies are returned, everything else is engine output. */
export function replyLine(line: string): string | undefined {
  return line.startsWith(REPLY_PREFIX) ? line.slice(REPLY_PREFIX.length) : undefined;
}

/** The module, with calls sent one at a time (the adapter already serializes them). */
export function bridgeModule(channel: Channel): WasmPgliteModule {
  let queue: Promise<unknown> = Promise.resolve();
  const call = <T>(request: Record<string, unknown>, map: (ok: unknown) => T) => {
    const next = queue.then(async () => {
      channel.send(JSON.stringify(request));
      const reply = JSON.parse(await channel.receive()) as Reply;
      return 'ok' in reply
        ? { tag: 'ok' as const, val: map(reply.ok) }
        : { tag: 'err' as const, val: reply.err };
    });
    queue = next.catch(() => undefined);
    return next;
  };
  const unit = () => undefined;
  const statement = (op: string) => (sql: string, params: WasmPgValue[]) => ({
    op,
    sql,
    params: params.map(toWire),
  });
  const connection: WasmPgliteConnection = {
    exec: (sql) => call({ op: 'exec', sql }, unit),
    run: (sql, params) => call(statement('run')(sql, params), (ok) => BigInt(ok as string)),
    query: (sql, params) =>
      call(statement('query')(sql, params), (ok) =>
        (ok as Array<Array<[string, WireValue]>>).map(rowFromWire),
      ),
    first: (sql, params) =>
      call(statement('first')(sql, params), (ok) =>
        ok === null ? undefined : rowFromWire(ok as Array<[string, WireValue]>),
      ),
    begin: () => call({ op: 'begin' }, unit),
    commit: () => call({ op: 'commit' }, unit),
    rollback: () => call({ op: 'rollback' }, unit),
    savepoint: (name) => call({ op: 'savepoint', name }, unit),
    releaseSavepoint: (name) => call({ op: 'release-savepoint', name }, unit),
    rollbackToSavepoint: (name) => call({ op: 'rollback-to-savepoint', name }, unit),
    close: () => call({ op: 'close' }, unit),
  } as WasmPgliteConnection;
  return {
    open: (path) =>
      call({ op: 'open', path }, () => connection) as ReturnType<WasmPgliteModule['open']>,
  };
}
