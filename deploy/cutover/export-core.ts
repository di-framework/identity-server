/**
 * Reads a Postgres-era identity database and writes a cutover export directory
 * (docs/guest-http-api.md#authproto-cutover). `export.ts` is the CLI around it.
 *
 * Every row is read by one statement, so the counts, the rows, the histories and the runtime
 * secret rows are one snapshot. Rows travel as JSON text that PostgreSQL itself produced
 * (`json_agg`), are written to the export unparsed, and are loaded by the importer with
 * `json_populate_recordset`, so every value keeps PostgreSQL's own text form.
 *
 * The directory is created with mode 0700 and every file with 0600. Values are written only to
 * files, never to stdout, a log or an error message.
 */
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { parseJsonQuietly, parseRuntimeValues } from '../platform/components/control-secret.ts';
import {
  EXCLUDED_TABLES,
  type ExportManifest,
  GUEST_HISTORY,
  identifier,
  RUNNER_HISTORY,
  RUNTIME_SECRET_TABLE,
  type RuntimeRow,
  type SplitRuntimeRows,
  sourceVersion,
  splitRuntimeRows,
  type TableManifest,
} from './source.ts';

/** Runs one SQL statement on the source and returns its single text cell (`psql -XAtq`). */
export type SourceSession = (sql: string) => Promise<string>;

/** Every base table in `public` with its columns in table order, and the server version. */
export const INVENTORY_SQL = `SELECT json_build_object(
  'server', current_setting('server_version_num'),
  'tables', coalesce((
    SELECT json_agg(json_build_object('name', c.relname, 'columns', (
      SELECT json_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute a
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    )) ORDER BY c.relname)
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
  ), '[]'::json)
)::text`;

export interface Inventory {
  server: string;
  tables: Array<{ name: string; columns: string[] }>;
}

/** `json_build_object` takes at most 100 arguments; one per table pair plus the fixed keys. */
const MAX_TABLES = 40;

/**
 * The snapshot statement for the tables the inventory found: each data table's count and rows
 * (as JSON text), both histories when present, and the runtime secret rows.
 */
export function snapshotSql(inventory: Inventory): string {
  const names = new Set(inventory.tables.map((table) => table.name));
  if (!names.has(RUNTIME_SECRET_TABLE)) {
    throw new Error(`the source has no ${RUNTIME_SECRET_TABLE}; it is older than V13`);
  }
  const data = inventory.tables.filter((table) => !EXCLUDED_TABLES.includes(table.name));
  if (data.length > MAX_TABLES) throw new Error(`the source has ${data.length} tables; too many`);
  const history = (table: string) =>
    names.has(table)
      ? `(SELECT coalesce(json_agg(version::text), '[]'::json) FROM ${identifier(table)})`
      : 'NULL::json';
  const tables = data.map(({ name }) => {
    const quoted = identifier(name);
    return `'${name}', json_build_object('count', (SELECT count(*) FROM ${quoted}), 'rows', (SELECT coalesce(json_agg(t), '[]'::json)::text FROM ${quoted} t))`;
  });
  return `SELECT json_build_object(
  'guest', ${history(GUEST_HISTORY)},
  'runner', ${history(RUNNER_HISTORY)},
  'runtime', (SELECT coalesce(json_agg(json_build_object('name', name, 'value', value) ORDER BY name), '[]'::json) FROM ${identifier(RUNTIME_SECRET_TABLE)}),
  'tables', json_build_object(${tables.join(',\n    ')})
)::text`;
}

export interface Snapshot {
  version: number;
  guestHistoryMax: number;
  runnerHistoryMax: number | null;
  serverVersionNum: string;
  tables: Array<{ name: string; columns: string[]; count: number; rows: string }>;
  runtime: SplitRuntimeRows;
}

interface RawSnapshot {
  guest: string[] | null;
  runner: string[] | null;
  runtime: RuntimeRow[];
  tables: Record<string, { count: number | string; rows: string }>;
}

/**
 * Reads the source: inventory, then one snapshot statement. Refuses a schema version outside
 * the supported range and runtime rows the new guest cannot take, before anything is written.
 */
export async function readSource(session: SourceSession): Promise<Snapshot> {
  const inventory = parseJsonQuietly<Inventory>(
    await session(INVENTORY_SQL),
    'the inventory psql returned',
  );
  for (const table of inventory.tables) {
    identifier(table.name);
    for (const column of table.columns) identifier(column);
  }
  const raw = parseJsonQuietly<RawSnapshot>(
    await session(snapshotSql(inventory)),
    'the snapshot psql returned',
  );
  const version = sourceVersion({ guest: raw.guest, runner: raw.runner });
  const runtime = splitRuntimeRows(raw.runtime);
  const max = (list: string[] | null) =>
    list === null || list.length === 0
      ? null
      : Math.max(...list.map((value) => Number(/\d+/.exec(value)?.[0])));
  return {
    version,
    guestHistoryMax: max(raw.guest) as number,
    runnerHistoryMax: max(raw.runner),
    serverVersionNum: inventory.server,
    tables: inventory.tables
      .filter((table) => !EXCLUDED_TABLES.includes(table.name))
      .map((table) => {
        const entry = raw.tables[table.name] as RawSnapshot['tables'][string];
        return { ...table, count: Number(entry.count), rows: entry.rows };
      }),
    runtime,
  };
}

const sha256 = (data: string | Uint8Array) => createHash('sha256').update(data).digest('hex');

/** Creates `dir` with mode 0700, or accepts an existing empty directory and tightens it. */
export function privateDirectory(dir: string): void {
  if (existsSync(dir)) {
    if (!statSync(dir).isDirectory() || readdirSync(dir).length > 0) {
      throw new Error(`${dir} exists and is not an empty directory; refusing to write into it`);
    }
  } else {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  chmodSync(dir, 0o700);
}

/** Writes one file with mode 0600; refuses to replace an existing file. */
export function privateFile(path: string, data: string | Uint8Array): void {
  writeFileSync(path, data, { mode: 0o600, flag: 'wx' });
}

/**
 * Writes the export directory `out`: `tables/<name>.json`, `values.json` (the deploy.sh values
 * file: every runtime secret row under its own name), `state.json` (bootstrap state rows) and
 * `manifest.json`. `backup`, when given, writes a pg_dump of the source into the directory and
 * returns its file name and digest; it runs after the data files and before the manifest.
 *
 * Everything is written into a new 0700 sibling of `out` and renamed to `out` only once the
 * backup and the manifest are written, so `out` either holds a complete export or does not
 * exist. On any error the sibling, with whatever secrets it already held, is removed. `out`
 * must not exist or be an empty directory; missing parents are created mode 0700. The values
 * are checked as `runtime-secrets.ts` checks a values file before anything is written.
 */
export async function writeExport(
  out: string,
  snapshot: Snapshot,
  options: {
    createdAt: string;
    backup?: (dir: string) => Promise<{ file: string; sha256: string }>;
  },
): Promise<ExportManifest> {
  parseRuntimeValues(JSON.stringify(snapshot.runtime.values), 'the runtime secret rows');
  const replaceEmpty = assertFreshTarget(out);
  mkdirSync(dirname(out), { recursive: true, mode: 0o700 });
  const dir = mkdtempSync(join(dirname(out), `.${basename(out)}.partial-`));
  try {
    chmodSync(dir, 0o700);
    const manifest = await fillExport(dir, snapshot, options);
    if (replaceEmpty) rmdirSync(out);
    renameSync(dir, out);
    return manifest;
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`${reason}; the partial export was removed, ${out} was not written`);
  }
}

/** `out` may not exist yet, or be an empty directory (then true: it is replaced). */
function assertFreshTarget(out: string): boolean {
  if (!existsSync(out)) return false;
  if (!statSync(out).isDirectory() || readdirSync(out).length > 0) {
    throw new Error(`${out} exists and is not an empty directory; refusing to write into it`);
  }
  return true;
}

async function fillExport(
  dir: string,
  snapshot: Snapshot,
  options: Parameters<typeof writeExport>[2],
): Promise<ExportManifest> {
  const tablesDir = join(dir, 'tables');
  privateDirectory(tablesDir);
  const tables: TableManifest[] = snapshot.tables.map((table) => {
    privateFile(join(tablesDir, `${table.name}.json`), table.rows);
    return {
      name: table.name,
      columns: table.columns,
      count: table.count,
      sha256: sha256(table.rows),
    };
  });
  privateFile(join(dir, 'values.json'), `${JSON.stringify(snapshot.runtime.values, null, 2)}\n`);
  privateFile(join(dir, 'state.json'), `${JSON.stringify(snapshot.runtime.state, null, 2)}\n`);
  const manifest: ExportManifest = {
    format: 1,
    createdAt: options.createdAt,
    source: {
      version: snapshot.version,
      guestHistoryMax: snapshot.guestHistoryMax,
      runnerHistoryMax: snapshot.runnerHistoryMax,
      serverVersionNum: snapshot.serverVersionNum,
    },
    tables,
    runtimeRows: {
      values: Object.keys(snapshot.runtime.values).sort(),
      state: Object.keys(snapshot.runtime.state).sort(),
      dropped: [...snapshot.runtime.dropped].sort(),
    },
    backup: options.backup ? await options.backup(dir) : null,
  };
  privateFile(join(dir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

/** A process run to completion: exit code, raw stdout, stderr text. */
export type Run = (
  argv: string[],
  input?: string,
) => Promise<{ code: number; stdout: Uint8Array; stderr: string }>;

/** Where psql and pg_dump run: the database pod, or a local container for rehearsals. */
export type ExportTarget =
  | { podman: string }
  | {
      kubeconfig: string;
      context?: string;
      namespace: string;
      pod?: string;
      service?: string;
      container?: string;
    };

/** A failed psql or pg_dump: exit code and at most 400 characters of stderr. */
export function failure(what: string, result: { code: number; stderr: string }): Error {
  // psql and pg_dump errors name objects, not values; keep them short anyway.
  return new Error(`${what} failed (exit ${result.code}): ${result.stderr.trim().slice(0, 400)}`);
}

async function execPrefix(run: Run, target: ExportTarget): Promise<string[]> {
  if ('podman' in target) return ['podman', 'exec', '-i', target.podman];
  const kubectl = (...rest: string[]) => [
    'kubectl',
    '--kubeconfig',
    target.kubeconfig,
    ...(target.context ? ['--context', target.context] : []),
    '--namespace',
    target.namespace,
    ...rest,
  ];
  let pod = target.pod;
  if (!pod) {
    if (!target.service) throw new Error('--pod or --service is required');
    const listed = await run(
      kubectl(
        'get',
        'pods',
        '-l',
        `app=di-bs-${target.service}`,
        '-o',
        'jsonpath={range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\\n"}{end}',
      ),
    );
    const pods = new TextDecoder().decode(listed.stdout).split('\n').filter(Boolean);
    if (listed.code !== 0 || pods.length !== 1) {
      throw new Error(
        `expected one Running pod labelled app=di-bs-${target.service}, found ${pods.length} (kubectl exit ${listed.code}); pass --pod`,
      );
    }
    pod = pods[0] as string;
  }
  return kubectl('exec', '-i', pod, ...(target.container ? ['-c', target.container] : []), '--');
}

/**
 * The whole export (export.ts): psql for the inventory and the snapshot, each in a read-only
 * transaction with the SQL on stdin, then `writeExport` with `pg_dump -Fc` as the backup unless
 * `backup` is false. Logs names and counts only.
 */
export async function exportCommand(
  options: {
    out: string;
    target: ExportTarget;
    user: string;
    database: string;
    backup: boolean;
    createdAt: string;
  },
  deps: { run: Run; log: (line: string) => void },
): Promise<ExportManifest> {
  const prefix = await execPrefix(deps.run, options.target);
  const login = ['-U', options.user, '-d', options.database];
  const psql = [
    ...prefix,
    'psql',
    '-X',
    '-q',
    '-A',
    '-t',
    '-v',
    'ON_ERROR_STOP=1',
    ...login,
    '-f',
    '-',
  ];
  const session: SourceSession = async (sql) => {
    const result = await deps.run(psql, `BEGIN READ ONLY;\n${sql};\nCOMMIT;\n`);
    if (result.code !== 0) throw failure('psql', result);
    return new TextDecoder().decode(result.stdout).replace(/\n$/, '');
  };
  const snapshot = await readSource(session);
  const backup = options.backup
    ? async (dir: string) => {
        const result = await deps.run([...prefix, 'pg_dump', '-Fc', ...login]);
        if (result.code !== 0) throw failure('pg_dump', result);
        const file = 'directory.dump';
        privateFile(join(dir, file), result.stdout);
        return { file, sha256: sha256(result.stdout) };
      }
    : undefined;
  const manifest = await writeExport(options.out, snapshot, {
    createdAt: options.createdAt,
    backup,
  });
  const { source } = manifest;
  deps.log(`exported ${options.out} (mode 0700; files 0600; holds secrets and PII)`);
  deps.log(
    `source schema V${source.version} (identity_schema_migrations max ${source.guestHistoryMax}, _migrations ${source.runnerHistoryMax ?? 'absent'}, server ${source.serverVersionNum})`,
  );
  for (const table of manifest.tables) deps.log(`  ${table.name}: ${table.count} rows`);
  deps.log(`values.json: ${manifest.runtimeRows.values.join(', ')}`);
  deps.log(`state.json: ${manifest.runtimeRows.state.join(', ') || 'none'}`);
  deps.log(`not carried: ${manifest.runtimeRows.dropped.join(', ') || 'none'}`);
  deps.log(`backup: ${manifest.backup ? `${manifest.backup.file} (pg_dump -Fc)` : 'none'}`);
  deps.log(
    `next: bun deploy/guest/runtime-secrets.ts pglite-key --values ${join(options.out, 'values.json')}`,
  );
  return manifest;
}

export { sha256 };
