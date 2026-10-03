/** A `wasmcloud:postgres` value the guest can pass as a query parameter. */
export interface PgText {
  tag: 'text';
  val: string;
}

export function text(value: string): PgText {
  return { tag: 'text', val: value };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Encode a repository parameter as the Postgres type the column expects.
 * The host binds in binary, so a text payload in a uuid or boolean slot is rejected.
 */
export function pgValue(value: unknown): { tag: string; val?: unknown } {
  if (value == null) return { tag: 'null' };
  if (typeof value === 'string') {
    return UUID.test(value) ? { tag: 'uuid', val: value } : text(value);
  }
  if (typeof value === 'boolean') return { tag: 'bool', val: value };
  if (typeof value === 'bigint') return { tag: 'int8', val: Number(value) };
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('PostgreSQL parameter is not a finite number');
    if (Number.isInteger(value)) {
      return value >= -2147483648 && value <= 2147483647
        ? { tag: 'int4', val: value }
        : { tag: 'int8', val: value };
    }
    return { tag: 'numeric', val: String(value) };
  }
  if (value instanceof Date) return { tag: 'timestamp-tz', val: timestampTz(value) };
  if (value instanceof Uint8Array) return { tag: 'bytea', val: [...value] };
  return { tag: 'jsonb', val: JSON.stringify(value) };
}

export function postgresError(cause: unknown): Error {
  if (cause instanceof Error && cause.message.startsWith('PostgreSQL')) return cause;
  const source = cause instanceof Error && 'payload' in cause ? cause.payload : cause;
  const code = nestedString(source, 'code');
  const message = nestedString(source, 'message') ?? scalarVal(source);
  const tag = tagOf(source);
  const labeled = tag !== undefined && tag !== 'err' && tag !== 'ok';
  const error = codedMessage(code, message, labeled ? tag : undefined);
  console.error(error.message);
  return error;
}

function codedMessage(
  code: string | undefined,
  message: string | undefined,
  tag: string | undefined,
): Error {
  if (code && message) return new Error(`PostgreSQL ${code} ${message}`);
  if (code) return new Error(`PostgreSQL ${code}`);
  if (tag && message) return new Error(`PostgreSQL ${tag} ${message}`);
  if (tag) return new Error(`PostgreSQL ${tag}`);
  if (message) return new Error(`PostgreSQL ${message}`);
  return new Error('PostgreSQL rejected the statement');
}

export function isUniqueViolation(error: unknown): boolean {
  const text = error instanceof Error ? error.message : '';
  return text.includes('23505') || text.toLowerCase().includes('duplicate key');
}

/** Turn one cell of a `pg-value` variant into a JSON value. */
export function pgScalar(value: unknown): unknown {
  if (value == null || typeof value !== 'object' || !('tag' in value)) return value;
  const tagged = value as { tag: unknown; val?: unknown };
  if (tagged.tag === 'null') return null;
  if (tagged.tag === 'varchar' || tagged.tag === 'text' || tagged.tag === 'name') {
    return characters(tagged.val);
  }
  if (tagged.tag === 'json' || tagged.tag === 'jsonb') {
    if (typeof tagged.val !== 'string') return tagged.val ?? null;
    try {
      return JSON.parse(tagged.val) as unknown;
    } catch {
      return tagged.val;
    }
  }
  if (tagged.tag === 'timestamp' || tagged.tag === 'timestamp-tz') return timestampIso(tagged.val);
  if (tagged.tag === 'bool' || tagged.tag === 'boolean') return tagged.val === true;
  return tagged.val === undefined ? null : tagged.val;
}

export function assertBatch(result: unknown): void {
  if (isErr(result)) throw postgresError(result);
}

export async function readRows(result: unknown): Promise<Record<string, unknown>[]> {
  const value = isOk(result) ? result.val : result;
  if (isErr(result)) throw postgresError(result);
  if (!Array.isArray(value) || value.length < 2) {
    throw new Error('PostgreSQL query returned an unexpected result');
  }
  const columns = value[0];
  const rawRows = await collect(value[1]);
  await finish(value[2]);
  return rawRows.map((row) => record(columns, row));
}

function isErr(result: unknown): result is { tag: 'err'; val?: unknown } {
  return isTag(result, 'err');
}

function isOk(result: unknown): result is { tag: 'ok'; val?: unknown } {
  return isTag(result, 'ok');
}

function isTag(result: unknown, tag: string): boolean {
  if (result == null || typeof result !== 'object') return false;
  return 'tag' in result && result.tag === tag;
}

async function collect(stream: unknown): Promise<unknown[]> {
  if (stream == null || typeof stream !== 'object') {
    throw new Error('PostgreSQL query did not return a row stream');
  }
  const rows: unknown[] = [];
  if (Symbol.asyncIterator in stream || Symbol.iterator in stream) {
    for await (const row of stream as AsyncIterable<unknown>) rows.push(row);
    return rows;
  }
  const readable = stream as { read?: (count?: number) => Promise<unknown> };
  if (typeof readable.read !== 'function') {
    throw new Error('PostgreSQL query did not return a row stream');
  }
  for (;;) {
    const chunk = await readable.read(64);
    if (!Array.isArray(chunk) || chunk.length === 0) break;
    rows.push(...chunk);
  }
  return rows;
}

async function finish(done: unknown): Promise<void> {
  if (done == null) return;
  let completion: unknown = done;
  if (typeof done === 'object' && 'read' in done && typeof done.read === 'function') {
    completion = await done.read();
  } else if (typeof (done as Promise<unknown>).then === 'function') {
    completion = await (done as Promise<unknown>);
  }
  if (isErr(completion)) throw postgresError(completion);
}

function record(columns: unknown, row: unknown): Record<string, unknown> {
  if (!Array.isArray(columns) || !Array.isArray(row)) {
    throw new Error('PostgreSQL query returned an unexpected row');
  }
  const out: Record<string, unknown> = {};
  for (const [index, column] of columns.entries()) {
    if (typeof column === 'string') out[column] = pgScalar(row[index]);
  }
  return out;
}

function timestampTz(value: Date): unknown {
  return {
    timestamp: {
      date: {
        tag: 'ymd',
        val: [value.getUTCFullYear(), value.getUTCMonth() + 1, value.getUTCDate()],
      },
      time: {
        hour: value.getUTCHours(),
        min: value.getUTCMinutes(),
        sec: value.getUTCSeconds(),
        micro: Math.floor(value.getUTCMilliseconds() * 1000),
      },
    },
    offset: { tag: 'eastern-hemisphere-secs', val: 0 },
  };
}

function timestampIso(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (value == null || typeof value !== 'object') return null;
  const record = value as { timestamp?: unknown; val?: unknown };
  const timestamp = (record.timestamp ?? record.val) as
    | {
        date?: { tag?: string; val?: unknown };
        time?: { hour?: number; min?: number; sec?: number; micro?: number };
      }
    | undefined;
  const date = timestamp?.date;
  const ymd = date?.tag === 'ymd' && Array.isArray(date.val) ? date.val : undefined;
  if (!ymd || ymd.length < 3) return null;
  const time = timestamp?.time;
  const pad = (part: number, width = 2) => String(part).padStart(width, '0');
  const year = pad(Number(ymd[0]), 4);
  const month = pad(Number(ymd[1]));
  const day = pad(Number(ymd[2]));
  const hour = pad(time?.hour ?? 0);
  const minute = pad(time?.min ?? 0);
  const second = pad(time?.sec ?? 0);
  const milli = pad(Math.floor((time?.micro ?? 0) / 1000), 3);
  return `${year}-${month}-${day}T${hour}:${minute}:${second}.${milli}Z`;
}

function characters(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (isByteTuple(value)) return characters(value[1]);
  const bytes = byteList(value);
  if (!bytes) return null;
  return new TextDecoder().decode(Uint8Array.from(bytes));
}

function isByteTuple(value: unknown): value is [unknown, unknown] {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    (value[0] == null || typeof value[0] === 'number') &&
    typeof value[1] !== 'number'
  );
}

function byteList(value: unknown): number[] | undefined {
  if (value instanceof Uint8Array) return [...value];
  if (Array.isArray(value) && value.every((item) => typeof item === 'number')) return value;
  if (value == null || typeof value !== 'object') return undefined;
  const keys = Object.keys(value)
    .filter((key) => /^\d+$/.test(key))
    .sort((left, right) => Number(left) - Number(right));
  if (keys.length === 0) return undefined;
  return keys.map((key) => Number((value as Record<string, unknown>)[key]));
}

function tagOf(value: unknown): string | undefined {
  if (value == null || typeof value !== 'object' || !('tag' in value)) return undefined;
  return typeof value.tag === 'string' ? value.tag : undefined;
}

function scalarVal(value: unknown): string | undefined {
  if (value == null || typeof value !== 'object' || !('val' in value)) return undefined;
  return typeof value.val === 'string' ? value.val : undefined;
}

function nestedString(value: unknown, key: string, depth = 0): string | undefined {
  if (depth > 6 || value == null || typeof value !== 'object') return undefined;
  const record = value as Record<string, unknown>;
  const direct = record[key];
  if (typeof direct === 'string' && direct !== '') return direct;
  return nestedString(record.val, key, depth + 1);
}
