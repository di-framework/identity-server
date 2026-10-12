/**
 * Loads a cutover export into a new, empty identity database and checks the encrypted data
 * directory it produced (docs/guest-http-api.md#authproto-cutover). `import.ts` is the CLI that
 * runs this on the guest's own pglite provider and encryption layer under wasmtime.
 *
 * The new database is migrated to the source's version with the guest's own migration code, so
 * `identity_schema_migrations` reads exactly as if the guest had created it. The data then goes
 * in through `json_populate_recordset` in one transaction, with the row counts checked inside it.
 * The guest applies V(source+1)..V20 on its first start.
 *
 * Errors name tables and counts only, never values.
 */
import { createHash } from 'node:crypto';
import { closeSync, openSync, readdirSync, readFileSync, readSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { SqlDatabase } from '../../apps/guest/src/database.ts';
import type { EmbeddedMigration } from '../../apps/guest/src/flyway.ts';
import { applySchema } from '../../apps/guest/src/migrations.ts';
import { assertPrivateMode, parseJsonQuietly } from '../platform/components/control-secret.ts';
import {
  EXCLUDED_TABLES,
  type ExportManifest,
  identifier,
  parseManifest,
  RUNTIME_SECRET_TABLE,
  STATE_ROW_NAMES,
  V16_KEPT_ROW_NAMES,
} from './source.ts';

export interface LoadedExport {
  manifest: ExportManifest;
  /** Table name to its rows as JSON text, exactly as exported. */
  rows: Map<string, string>;
  /** Bootstrap state rows to carry. */
  state: Record<string, string>;
}

/** Reads an export directory, checking modes, the manifest and every table file's digest. */
export function loadExport(dir: string): LoadedExport {
  assertDirectoryPrivate(dir);
  const read = (path: string) => {
    assertPrivateMode(statSync(path).mode, path);
    return readFileSync(path, 'utf8');
  };
  const manifest = parseManifest(read(join(dir, 'manifest.json')), join(dir, 'manifest.json'));
  const rows = new Map<string, string>();
  for (const table of manifest.tables) {
    const path = join(dir, 'tables', `${table.name}.json`);
    const text = read(path);
    if (createHash('sha256').update(text).digest('hex') !== table.sha256) {
      throw new Error(`${path} does not match its digest in the manifest`);
    }
    rows.set(table.name, text);
  }
  const state = parseJsonQuietly<Record<string, string>>(
    read(join(dir, 'state.json')),
    join(dir, 'state.json'),
  );
  const unexpected = Object.keys(state).filter((name) => !STATE_ROW_NAMES.includes(name));
  if (unexpected.length > 0) {
    throw new Error(`state.json holds rows that are not bootstrap state: ${unexpected.join(', ')}`);
  }
  return { manifest, rows, state };
}

function assertDirectoryPrivate(dir: string): void {
  if ((statSync(dir).mode & 0o077) !== 0) {
    throw new Error(`${dir} must be mode 0700; it holds secrets`);
  }
}

interface TargetTable {
  name: string;
  columns: string[];
}

const TARGET_TABLES_SQL = `SELECT c.relname AS name, (
    SELECT json_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute a
    WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
  ) AS columns
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
  ORDER BY c.relname`;

const FOREIGN_KEYS_SQL = `SELECT child.relname AS child, parent.relname AS parent
  FROM pg_constraint k
  JOIN pg_class child ON child.oid = k.conrelid
  JOIN pg_class parent ON parent.oid = k.confrelid
  JOIN pg_namespace n ON n.oid = child.relnamespace
  WHERE k.contype = 'f' AND n.nspname = 'public'`;

/** Tables ordered so every referenced table comes before the tables that reference it. */
export function loadOrder(
  tables: readonly string[],
  references: ReadonlyArray<{ child: string; parent: string }>,
): string[] {
  const pending = new Map(tables.map((name) => [name, new Set<string>()]));
  for (const { child, parent } of references) {
    if (child !== parent && pending.has(parent)) pending.get(child)?.add(parent);
  }
  const order: string[] = [];
  while (pending.size > 0) {
    const ready = [...pending.keys()]
      .filter((name) => [...(pending.get(name) as Set<string>)].every((p) => !pending.has(p)))
      .sort();
    if (ready.length === 0) {
      throw new Error(`foreign keys form a cycle among ${[...pending.keys()].sort().join(', ')}`);
    }
    for (const name of ready) {
      order.push(name);
      pending.delete(name);
    }
  }
  return order;
}

export interface ImportReport {
  sourceVersion: number;
  migrationsApplied: string[];
  tables: Array<{ name: string; expected: number; imported: number }>;
  stateRows: string[];
  /** `identity_runtime_secret` rows V16 would delete at the guest's first start. */
  rowsV16WouldDelete: number;
}

const columnsOf = (value: unknown): string[] =>
  (typeof value === 'string' ? parseJsonQuietly(value, 'a column list') : value) as string[];

/**
 * Sequences and identity columns whose position the import would not carry. V1..V15 have none
 * (every key is a uuid, a varchar or composite); a schema that gains one must reset it after
 * the load, so the import refuses until it does.
 */
const COUNTERS_SQL = `SELECT
  (SELECT count(*)::int FROM pg_sequences WHERE schemaname = 'public') AS sequences,
  (SELECT count(*)::int FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
     JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND a.attnum > 0 AND NOT a.attisdropped
     AND (a.attidentity <> '' OR a.attgenerated <> '')) AS identities`;

/**
 * Migrates the empty database `db` to the export's source version and loads the export. Refuses
 * a database that already has tables, and a schema whose tables or columns differ from the
 * export's.
 */
export async function importExport(
  db: SqlDatabase,
  loaded: LoadedExport,
  migrations: readonly EmbeddedMigration[],
): Promise<ImportReport> {
  const { manifest } = loaded;
  const existing = await db.first<{ n: unknown }>(
    "SELECT count(*)::int AS n FROM pg_tables WHERE schemaname = 'public'",
  );
  if (Number(existing?.n) !== 0) {
    throw new Error('the target database already has tables; the import needs a new, empty one');
  }
  const version = manifest.source.version;
  const wanted = migrations.filter((migration) => Number(migration.version) <= version);
  const applied = await applySchema(db, wanted);
  const expectedVersions = Array.from({ length: version }, (_, index) => String(index + 1));
  if (applied.join(',') !== expectedVersions.join(',')) {
    throw new Error(`migrating the new database to V${version} applied ${applied.join(', ')}`);
  }

  const counters = await db.first<{ sequences: unknown; identities: unknown }>(COUNTERS_SQL);
  if (Number(counters?.sequences) !== 0 || Number(counters?.identities) !== 0) {
    throw new Error(
      `V${version} has ${Number(counters?.sequences)} sequences and ${Number(counters?.identities)} identity or generated columns, which this import does not carry; refusing`,
    );
  }
  const target = (await db.query<{ name: string; columns: unknown }>(TARGET_TABLES_SQL))
    .map((row) => ({ name: String(row.name), columns: columnsOf(row.columns) }))
    .filter((table) => !EXCLUDED_TABLES.includes(table.name));
  assertSameSchema(target, manifest);

  const references = await db.query<{ child: string; parent: string }>(FOREIGN_KEYS_SQL);
  const order = loadOrder(
    target.map((table) => table.name),
    references,
  );
  const byName = new Map(manifest.tables.map((table) => [table.name, table]));
  const tables: ImportReport['tables'] = [];
  const stateRows = Object.keys(loaded.state).sort();
  let rowsV16WouldDelete = 0;
  await db.transaction(async (tx) => {
    for (const name of order) {
      const table = byName.get(name) as ExportManifest['tables'][number];
      const columns = table.columns.map(identifier).join(', ');
      await tx.run(
        `INSERT INTO ${identifier(name)} (${columns}) SELECT ${columns} FROM json_populate_recordset(NULL::${identifier(name)}, CAST(? AS json))`,
        [loaded.rows.get(name)],
      );
    }
    for (const name of stateRows) {
      await tx.run(`INSERT INTO ${identifier(RUNTIME_SECRET_TABLE)} (name, value) VALUES (?, ?)`, [
        name,
        loaded.state[name],
      ]);
    }
    for (const name of order) {
      const expected = (byName.get(name) as ExportManifest['tables'][number]).count;
      const row = await tx.first<{ n: unknown }>(
        `SELECT count(*)::int AS n FROM ${identifier(name)}`,
      );
      const imported = Number(row?.n);
      tables.push({ name, expected, imported });
      if (imported !== expected) {
        throw new Error(`${name}: imported ${imported} rows, the export has ${expected}`);
      }
    }
    const kept = V16_KEPT_ROW_NAMES.map((name) => `'${name}'`).join(', ');
    const doomed = await tx.first<{ n: unknown }>(
      `SELECT count(*)::int AS n FROM ${identifier(RUNTIME_SECRET_TABLE)} WHERE name NOT IN (${kept})`,
    );
    rowsV16WouldDelete = Number(doomed?.n);
    if (rowsV16WouldDelete !== 0) {
      throw new Error(`${RUNTIME_SECRET_TABLE} would lose ${rowsV16WouldDelete} rows to V16`);
    }
  });
  return {
    sourceVersion: version,
    migrationsApplied: applied,
    tables,
    stateRows,
    rowsV16WouldDelete,
  };
}

function assertSameSchema(target: readonly TargetTable[], manifest: ExportManifest): void {
  const exported = new Map(manifest.tables.map((table) => [table.name, table.columns]));
  const targetNames = new Set(target.map((table) => table.name));
  const missing = [...exported.keys()].filter((name) => !targetNames.has(name)).sort();
  const extra = [...targetNames].filter((name) => !exported.has(name)).sort();
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(
      `the export's tables differ from V${manifest.source.version}'s: ` +
        `not in the new schema: ${missing.join(', ') || 'none'}; not in the export: ${extra.join(', ') || 'none'}`,
    );
  }
  for (const table of target) {
    const sorted = (list: readonly string[]) => [...list].sort().join(',');
    if (sorted(table.columns) !== sorted(exported.get(table.name) as string[])) {
      throw new Error(`${table.name}: the export's columns differ from the new schema's`);
    }
  }
}

/** Plaintext that must not appear on disk: engine strings and the users' logins and emails. */
export function needlesOf(rows: ReadonlyMap<string, string>): string[] {
  const users = parseJsonQuietly<Array<Record<string, unknown>>>(
    rows.get('users') ?? '[]',
    'the exported users',
  );
  const fromUsers = users.flatMap((user) =>
    [user.login, user.email].filter(
      (value): value is string => typeof value === 'string' && value.length >= 6,
    ),
  );
  return ['PostgreSQL', 'pg_catalog', 'template1', ...fromUsers];
}

/** What `verifyCiphertext` found on disk. Counts only. */
export interface CiphertextReport {
  files: number;
  encrypted: number;
  empty: number;
  /** Non-empty regular files without an encfs header under the key's KCV. */
  plaintext: string[];
  markerKcvMatches: boolean;
  /** Needles found in some file's raw bytes (by index, never the needle). */
  needlesFound: number;
}

const HEADER_MAGIC = Buffer.from('DIPGENC1');
const MARKER = '.di-encfs';

/**
 * Walks a pglite-encfs data directory (the directory mounted at `/data`): every non-empty
 * regular file must start with the encfs header whose KCV (bytes 32..48) is the key's, and the
 * root `.di-encfs` marker (bytes 8..24) must hold the same KCV
 * (di-framework/platform `platform/pglite-encfs/README.md`). `needles` are plaintext strings
 * that must not appear in any file; only how many did is reported.
 */
export function verifyCiphertext(
  dir: string,
  kcvHex: string,
  needles: readonly string[] = [],
): CiphertextReport {
  const kcv = Buffer.from(kcvHex, 'hex');
  const marker = readFileSync(join(dir, MARKER));
  const report: CiphertextReport = {
    files: 0,
    encrypted: 0,
    empty: 0,
    plaintext: [],
    markerKcvMatches: marker.length >= 24 && marker.subarray(8, 24).equals(kcv),
    needlesFound: 0,
  };
  const found = new Set<number>();
  const needleBytes = needles.filter((needle) => needle.length > 0).map((n) => Buffer.from(n));
  const walk = (path: string, relative: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(child, name);
        continue;
      }
      if (!entry.isFile() || name === MARKER) continue;
      report.files += 1;
      const size = statSync(child).size;
      if (size === 0) {
        report.empty += 1;
        continue;
      }
      const header = Buffer.alloc(48);
      const fd = openSync(child, 'r');
      try {
        readSync(fd, header, 0, 48, 0);
      } finally {
        closeSync(fd);
      }
      if (header.subarray(0, 8).equals(HEADER_MAGIC) && header.subarray(32, 48).equals(kcv)) {
        report.encrypted += 1;
      } else {
        report.plaintext.push(name);
      }
      if (needleBytes.length > 0) {
        const bytes = readFileSync(child);
        needleBytes.forEach((needle, index) => {
          if (bytes.includes(needle)) found.add(index);
        });
      }
    }
  };
  walk(dir, '');
  report.needlesFound = found.size;
  return report;
}
