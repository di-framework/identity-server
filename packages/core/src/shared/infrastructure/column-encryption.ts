import { createHmac } from 'node:crypto';
import { useContainer } from '@di-framework/core/container';
import { Component, Container } from '@di-framework/core/decorators';
import { IdentityError } from '../domain/identity-error.ts';
import { IDENTITY_SETTINGS } from '../domain/tokens.ts';
import type { IdentitySettings } from './identity-settings.ts';
import { PostgresGateway } from './postgres-gateway.ts';
import { Sql, sql } from './sql.ts';

/** Column and blind-index keys, base64 of at least 32 random bytes each. */
export interface ColumnKeys {
  column: string;
  bidx: string;
}

/**
 * pgcrypto's OpenPGP options for new ciphertext: AES-256, and salted S2K without iteration because
 * the key is 32 random bytes, not a password, with SHA-256 as the S2K digest. Integrity (MDC)
 * stays on and compression off, pgcrypto's defaults. Ciphertext length still follows plaintext
 * length.
 */
const PGP_OPTIONS = Sql.raw(`'cipher-algo=aes256, s2k-mode=1, s2k-digest-algo=sha256'`);

/** How long a process trusts a disabled state before reading it again (another may opt in). */
export const DISABLED_REFRESH_MS = 30_000;

/**
 * SQL for protected columns, for one statement. With keys (encryption enabled) new values are
 * written as `pgp_sym_encrypt` ciphertext in `<column>_enc` (plus an HMAC-SHA256 blind index for
 * looked-up columns) and the plaintext column is written NULL. Without keys every statement is
 * the plaintext one and calls no pgcrypto function. Reads and lookups always cover rows written
 * before encryption was enabled, which keep their plaintext.
 */
export class ColumnCipher {
  static readonly plaintext = new ColumnCipher(null);

  /**
   * `schema` is where pgcrypto is installed, as `regnamespace` text (already quoted when needed),
   * so its functions resolve whatever the `search_path`.
   */
  constructor(
    private readonly keys: ColumnKeys | null,
    private readonly schema = 'public',
  ) {}

  private fn(name: string): Sql {
    return Sql.raw(`${this.schema}.${name}`);
  }

  get enabled(): boolean {
    return this.keys !== null;
  }

  /** `pgp_sym_decrypt` of a bytea expression with the column key. */
  decrypt(ciphertext: Sql): Sql {
    return sql`${this.fn('pgp_sym_decrypt')}(${ciphertext}, ${this.keys?.column ?? null}::text)`;
  }

  /** Select expression: the decrypted ciphertext, else the legacy plaintext, as text. */
  read(column: string, as: string, options: { json?: boolean; enc?: string } = {}): Sql {
    const plain = options.json ? `${column}::text` : column;
    if (!this.keys) return Sql.raw(`${plain} AS ${as}`);
    const enc = options.enc ?? `${column}_enc`;
    return sql`coalesce(${this.decrypt(Sql.raw(enc))}, ${Sql.raw(plain)}) AS ${Sql.raw(as)}`;
  }

  /** Value for the plaintext column: the value itself, or NULL once encryption is enabled. */
  plain(value: string | null, options: { json?: boolean } = {}): Sql {
    if (this.keys || value === null) return Sql.raw('NULL');
    return options.json ? sql`${value}::text::jsonb` : sql`${value}::text`;
  }

  /** Value for `<column>_enc`: ciphertext once encryption is enabled, else NULL. */
  encrypt(value: string | null): Sql {
    if (!this.keys || value === null) return Sql.raw('NULL');
    return sql`${this.fn('pgp_sym_encrypt')}(${value}::text, ${this.keys.column}::text, ${PGP_OPTIONS})`;
  }

  /** Value for a `<column>_bidx` blind index of an already normalized value, or NULL. */
  blindIndex(normalized: string | null): Sql {
    if (!this.keys || normalized === null) return Sql.raw('NULL');
    return sql`${this.fn('hmac')}(${normalized}::text, ${this.keys.bidx}::text, 'sha256')`;
  }

  /**
   * Predicate for `column = plain` that also finds rows written after encryption was enabled,
   * through the blind index of `normalized`. `plain` defaults to `normalized`, for plaintext
   * columns that already hold the normalized value.
   */
  matches(column: string, bidx: string, normalized: string, plain = normalized): Sql {
    if (!this.keys) return sql`${Sql.raw(column)} = ${plain}`;
    return sql`(${Sql.raw(bidx)} = ${this.blindIndex(normalized)} OR ${Sql.raw(column)} = ${plain})`;
  }
}

/** Raised while encryption is enabled in the database but this process cannot use it. */
export class ColumnEncryptionUnavailable extends IdentityError {
  constructor(message: string) {
    super(503, message);
    this.name = 'ColumnEncryptionUnavailable';
  }
}

const KEY_CHECK_LABEL = 'identity column encryption key check v1';

/** HMAC-SHA256 of a fixed label under `key`, hex: identifies a key without revealing it. */
export function keyCheck(key: string): string {
  return createHmac('sha256', key).update(KEY_CHECK_LABEL).digest('hex');
}

interface StateRow {
  enabled: boolean;
  column_key_check: string | null;
  bidx_key_check: string | null;
}

/**
 * Opt-in column encryption state (`identity_column_encryption`, V18).
 *
 * - Disabled (the default): statements are the plaintext ones.
 * - `IDENTITY_COLUMN_ENCRYPTION=enabled` with `IDENTITY_COLUMN_KEY` and `IDENTITY_BIDX_KEY`:
 *   the first use proves pgcrypto works with these keys (an encrypt/decrypt and HMAC round trip),
 *   then enables it in the database, which records a check value per key. Enabling is one-way;
 *   a V18 trigger refuses turning it off, rekeying, or deleting the state.
 * - Enabled in the database (or key checks recorded): every statement needs both keys, matching
 *   the checks. Missing or different keys fail closed with 503; nothing falls back to plaintext.
 *   The V18 trigger also rejects plaintext writes to protected columns.
 *
 * A disabled state is read again after `DISABLED_REFRESH_MS`, and at once when the trigger refuses
 * a plaintext write (another instance opted in). The state is also re-read after a failure,
 * `IdentityModule.connect` or `IdentityModule.configure`.
 */
@Container()
export class ColumnEncryption {
  private state: Promise<ColumnCipher> | undefined;
  private refreshAt = Number.POSITIVE_INFINITY;

  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {
    db.onPlaintextRejected(() => this.reset());
  }

  /** Looked up on each load, like the database, so `IdentityModule.configure` applies. */
  private get settings(): IdentitySettings {
    return useContainer().resolve<IdentitySettings>(IDENTITY_SETTINGS);
  }

  /** The cipher for the next statement. Throws `ColumnEncryptionUnavailable` (503). */
  cipher(): Promise<ColumnCipher> {
    if (Date.now() >= this.refreshAt) this.reset();
    this.state ??= this.load().then(
      (cipher) => {
        if (!cipher.enabled) this.refreshAt = Date.now() + DISABLED_REFRESH_MS;
        return cipher;
      },
      (error: unknown) => {
        this.state = undefined;
        throw error;
      },
    );
    return this.state;
  }

  /** Forgets the loaded state, so the next statement reads it again. */
  reset(): void {
    this.state = undefined;
    this.refreshAt = Number.POSITIVE_INFINITY;
  }

  private async load(): Promise<ColumnCipher> {
    let row = await this.row();
    if (!latched(row)) {
      if (!this.settings.encryption.columns) return ColumnCipher.plaintext;
      const keys = this.requireKeys();
      const schema = await this.requirePgcrypto();
      await this.probe(new ColumnCipher(keys, schema), keys);
      await this.db.run(
        `UPDATE identity_column_encryption
         SET enabled = true, enabled_at = now(), column_key_check = ?, bidx_key_check = ?
         WHERE NOT enabled`,
        [keyCheck(keys.column), keyCheck(keys.bidx)],
      );
      row = await this.row();
    }
    const keys = this.requireKeys();
    if (
      row.column_key_check !== keyCheck(keys.column) ||
      row.bidx_key_check !== keyCheck(keys.bidx)
    ) {
      throw new ColumnEncryptionUnavailable(
        'IDENTITY_COLUMN_KEY or IDENTITY_BIDX_KEY differs from the keys column encryption was enabled with',
      );
    }
    return new ColumnCipher(keys, await this.pgcryptoSchema());
  }

  private async row(): Promise<StateRow> {
    const row = await this.db.one<StateRow>(
      `SELECT enabled, column_key_check, bidx_key_check FROM identity_column_encryption`,
    );
    if (!row) throw new ColumnEncryptionUnavailable('identity_column_encryption has no state row');
    return row;
  }

  private requireKeys(): ColumnKeys {
    const { columnKey, bidxKey } = this.settings.encryption;
    const missing = [
      ...(columnKey ? [] : ['IDENTITY_COLUMN_KEY']),
      ...(bidxKey ? [] : ['IDENTITY_BIDX_KEY']),
    ];
    if (missing.length > 0) {
      throw new ColumnEncryptionUnavailable(
        `column encryption is enabled but ${missing.join(' and ')} ${missing.length > 1 ? 'are' : 'is'} not set`,
      );
    }
    return { column: columnKey, bidx: bidxKey };
  }

  /** Installs pgcrypto if needed and returns its schema. */
  private async requirePgcrypto(): Promise<string> {
    try {
      await this.db.run('CREATE EXTENSION IF NOT EXISTS pgcrypto');
    } catch {
      throw new ColumnEncryptionUnavailable(
        'column encryption needs the pgcrypto extension, which this database engine does not provide',
      );
    }
    return this.pgcryptoSchema();
  }

  private async pgcryptoSchema(): Promise<string> {
    const row = await this.db.one<{ schema: string }>(
      `SELECT extnamespace::regnamespace::text AS schema FROM pg_extension WHERE extname = 'pgcrypto'`,
    );
    if (!row) {
      throw new ColumnEncryptionUnavailable(
        'column encryption is enabled but the pgcrypto extension is not installed',
      );
    }
    return row.schema;
  }

  /** Encrypt, decrypt and HMAC with the real keys before the irreversible latch. */
  private async probe(cipher: ColumnCipher, keys: ColumnKeys): Promise<void> {
    const probe = 'identity column encryption probe';
    const row = await this.db
      .one<{ round_trip: string | null; mac: string | null }>(
        sql`SELECT ${cipher.decrypt(cipher.encrypt(probe))} AS round_trip,
           encode(${cipher.blindIndex(probe)}, 'hex') AS mac`,
      )
      .catch(() => undefined);
    const mac = createHmac('sha256', keys.bidx).update(probe).digest('hex');
    if (row?.round_trip !== probe || row.mac !== mac) {
      throw new ColumnEncryptionUnavailable(
        'column encryption was not enabled: the pgcrypto round trip with these keys failed',
      );
    }
  }
}

/** Enabled, or key checks recorded: either one means ciphertext may exist. */
function latched(row: StateRow): boolean {
  return row.enabled || row.column_key_check !== null || row.bidx_key_check !== null;
}
