/**
 * The Postgres-era identity database (authproto's `directory` BackingService) as the cutover
 * tools see it: which schema versions they accept, which tables they carry, and how the
 * `identity_runtime_secret` rows split into the new guest's values file and its bootstrap state.
 * docs/guest-http-api.md#authproto-cutover is the runbook.
 *
 * Nothing here logs, prints or puts a value in an error message: errors name tables, columns
 * and row names only.
 */
import { RUNTIME_SECRET_NAMES } from '../platform/components/control-secret.ts';

/**
 * Source schema versions the tools accept. V13 created `identity_runtime_secret`, which the
 * Postgres-era guest needs; V15 is the last migration that guest shipped (23be792, the commit
 * authproto was deployed from). V16 deletes the secret rows, so a database at V16 or later has
 * already lost them and is refused.
 */
export const SUPPORTED_SOURCE_VERSIONS = { min: 13, max: 15 } as const;

/** The guest's own migration history (apps/guest/src/migrations.ts). */
export const GUEST_HISTORY = 'identity_schema_migrations';
/** `@di-framework/repo`'s MigrationRunner history, present when the Bun server migrated it. */
export const RUNNER_HISTORY = '_migrations';
export const RUNTIME_SECRET_TABLE = 'identity_runtime_secret';

/**
 * Tables that are not copied as data: the histories (the importer re-creates the guest's by
 * applying the same migrations) and the runtime secret table (its rows are split below).
 */
export const EXCLUDED_TABLES: readonly string[] = [
  GUEST_HISTORY,
  RUNNER_HISTORY,
  '_migrations_lock',
  RUNTIME_SECRET_TABLE,
];

/**
 * `identity_runtime_secret` rows that are guest state rather than settings: the bootstrap
 * fingerprints. They are carried into the new database so the new guest, given the same
 * settings, finds the same fingerprint and does not reconcile bootstrap again. V16 keeps them.
 */
export const STATE_ROW_NAMES: readonly string[] = [
  'bootstrap_fingerprint',
  'bootstrap_client_fingerprints',
];
/** A reconcile lease: transient, expires on its own, never carried. V16 keeps the name. */
export const TRANSIENT_ROW_NAMES: readonly string[] = ['bootstrap_lease'];
/** Every name V16 keeps in `identity_runtime_secret`. */
export const V16_KEPT_ROW_NAMES: readonly string[] = [...STATE_ROW_NAMES, ...TRANSIENT_ROW_NAMES];

const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

/** A table or column name the tools will quote and interpolate; anything else is refused. */
export function identifier(name: string): string {
  if (!IDENTIFIER.test(name)) throw new Error(`unexpected identifier ${JSON.stringify(name)}`);
  return `"${name}"`;
}

export interface RuntimeRow {
  name: string;
  value: string;
}

export interface SplitRuntimeRows {
  /** Rows whose name is a runtime setting of the new guest: the values file, name for name. */
  values: Record<string, string>;
  /** Bootstrap state rows carried into the new database. */
  state: Record<string, string>;
  /** Names dropped on purpose (the transient lease). */
  dropped: string[];
}

/**
 * Splits `identity_runtime_secret` rows. The Postgres-era guest read every row as a setting
 * (`loadGuestSettings` merged the table over wasi:config), and each setting it could hold is a
 * name of the new guest's environment (`RUNTIME_SECRET_NAMES`), so the mapping is the identity
 * on names. Any other name is refused rather than dropped: it changed the old guest's settings,
 * and the new guest would silently run without it.
 */
export function splitRuntimeRows(rows: readonly RuntimeRow[]): SplitRuntimeRows {
  const values: Record<string, string> = {};
  const state: Record<string, string> = {};
  const dropped: string[] = [];
  const unknown: string[] = [];
  const seen = new Set<string>();
  for (const { name, value } of rows) {
    if (seen.has(name)) throw new Error(`${RUNTIME_SECRET_TABLE} has the row ${name} twice`);
    seen.add(name);
    if (RUNTIME_SECRET_NAMES.includes(name)) values[name] = value;
    else if (STATE_ROW_NAMES.includes(name)) state[name] = value;
    else if (TRANSIENT_ROW_NAMES.includes(name)) dropped.push(name);
    else unknown.push(name);
  }
  if (unknown.length > 0) {
    throw new Error(
      `${RUNTIME_SECRET_TABLE} has rows the new guest has no setting for: ${unknown.sort().join(', ')}. ` +
        'The old guest applied them as settings; refusing to drop them. Move each into wasi:config ' +
        '(apps/guest/src/bindings.ts) or delete the row on the source after review, then export again',
    );
  }
  return { values, state, dropped };
}

/** A migration version as either history records it (`15`, `V15`, `15.0` → 15). */
export function versionNumber(version: string): number {
  const match = /^V?(\d+)(?:\.0+)?$/.exec(version.trim());
  if (!match) throw new Error(`unexpected migration version ${JSON.stringify(version)}`);
  return Number(match[1]);
}

/**
 * The source's schema version from its histories. The guest's history (always present on a
 * Postgres-era guest database) must be exactly 1..N. The Bun server's history, if the server
 * ever migrated this database, must not be ahead of it. N must be in the supported range.
 */
export function sourceVersion(history: {
  guest: readonly string[] | null;
  runner: readonly string[] | null;
}): number {
  if (history.guest === null || history.guest.length === 0) {
    throw new Error(`the source has no ${GUEST_HISTORY}; it is not a Postgres-era guest database`);
  }
  const guest = history.guest.map(versionNumber).sort((a, b) => a - b);
  const version = guest[guest.length - 1] as number;
  const contiguous = guest.every((value, index) => value === index + 1);
  if (!contiguous) {
    throw new Error(`${GUEST_HISTORY} is not 1..${version} without gaps; refusing`);
  }
  const runner = (history.runner ?? []).map(versionNumber);
  const runnerMax = runner.length === 0 ? 0 : Math.max(...runner);
  if (runnerMax > version) {
    throw new Error(
      `${RUNNER_HISTORY} is at V${runnerMax}, ahead of ${GUEST_HISTORY} (V${version}); a Bun server migrated this database. Refusing`,
    );
  }
  const { min, max } = SUPPORTED_SOURCE_VERSIONS;
  if (version < min || version > max) {
    throw new Error(
      `the source schema is at V${version}; the cutover supports V${min}..V${max}` +
        (version > max ? ' (V16 and later have already deleted the runtime secret rows)' : ''),
    );
  }
  return version;
}

export interface TableManifest {
  name: string;
  /** Column names in table order. */
  columns: string[];
  /** Row count read in the same statement as the rows. */
  count: number;
  /** SHA-256 (hex) of `tables/<name>.json`. */
  sha256: string;
}

/** `manifest.json` of an export directory. Names, counts and digests only; no values. */
export interface ExportManifest {
  format: 1;
  createdAt: string;
  source: {
    /** The schema version the importer migrates the new database to before loading. */
    version: number;
    guestHistoryMax: number;
    runnerHistoryMax: number | null;
    serverVersionNum: string;
  };
  tables: TableManifest[];
  runtimeRows: { values: string[]; state: string[]; dropped: string[] };
  /** File name of the pg_dump backup taken with the export, when one was. */
  backup: { file: string; sha256: string } | null;
}

/** Parses and checks `manifest.json`. */
export function parseManifest(text: string, source: string): ExportManifest {
  const manifest = JSON.parse(text) as ExportManifest;
  if (manifest?.format !== 1) throw new Error(`${source} is not a cutover export manifest`);
  const { min, max } = SUPPORTED_SOURCE_VERSIONS;
  const version = manifest.source?.version;
  if (!Number.isInteger(version) || version < min || version > max) {
    throw new Error(`${source} records an unsupported source version`);
  }
  if (!Array.isArray(manifest.tables) || manifest.tables.length === 0) {
    throw new Error(`${source} lists no tables`);
  }
  for (const table of manifest.tables) {
    identifier(table.name);
    for (const column of table.columns) identifier(column);
    if (EXCLUDED_TABLES.includes(table.name)) {
      throw new Error(`${source} carries ${table.name}, which is never copied as data`);
    }
  }
  return manifest;
}
