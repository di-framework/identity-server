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
 * the key is 32 random bytes, not a password. Integrity (MDC) stays on, pgcrypto's default.
 */
const PGP_OPTIONS = Sql.raw(`'cipher-algo=aes256, s2k-mode=1'`);

/**
 * SQL for protected columns, for one statement. With keys (encryption enabled) new values are
 * written as `pgp_sym_encrypt` ciphertext in `<column>_enc` (plus an HMAC-SHA256 blind index for
 * looked-up columns) and the plaintext column is written NULL. Without keys every statement is
 * the plaintext one and calls no pgcrypto function. Reads and lookups always cover rows written
 * before encryption was enabled, which keep their plaintext.
 */
export class ColumnCipher {
  static readonly plaintext = new ColumnCipher(null);

  constructor(private readonly keys: ColumnKeys | null) {}

  get enabled(): boolean {
    return this.keys !== null;
  }

  /** Select expression: the decrypted ciphertext, else the legacy plaintext, as text. */
  read(column: string, as: string, options: { json?: boolean; enc?: string } = {}): Sql {
    const plain = options.json ? `${column}::text` : column;
    if (!this.keys) return Sql.raw(`${plain} AS ${as}`);
    const enc = options.enc ?? `${column}_enc`;
    return sql`coalesce(pgp_sym_decrypt(${Sql.raw(enc)}, ${this.keys.column}::text), ${Sql.raw(plain)}) AS ${Sql.raw(as)}`;
  }

  /** Value for the plaintext column: the value itself, or NULL once encryption is enabled. */
  plain(value: string | null, options: { json?: boolean } = {}): Sql {
    if (this.keys || value === null) return Sql.raw('NULL');
    return options.json ? sql`${value}::text::jsonb` : sql`${value}::text`;
  }

  /** Value for `<column>_enc`: ciphertext once encryption is enabled, else NULL. */
  encrypt(value: string | null): Sql {
    if (!this.keys || value === null) return Sql.raw('NULL');
    return sql`pgp_sym_encrypt(${value}::text, ${this.keys.column}::text, ${PGP_OPTIONS})`;
  }

  /** Value for a `<column>_bidx` blind index of an already normalized value, or NULL. */
  blindIndex(normalized: string | null): Sql {
    if (!this.keys || normalized === null) return Sql.raw('NULL');
    return sql`hmac(${normalized}::text, ${this.keys.bidx}::text, 'sha256')`;
  }

  /**
   * Predicate for `column = plain` that also finds rows written after encryption was enabled,
   * through the blind index of `normalized`. `plain` defaults to `normalized`, for plaintext
   * columns that already hold the normalized value.
   */
  matches(column: string, bidx: string, normalized: string, plain = normalized): Sql {
    if (!this.keys) return sql`${Sql.raw(column)} = ${plain}`;
    return sql`(${Sql.raw(bidx)} = hmac(${normalized}::text, ${this.keys.bidx}::text, 'sha256') OR ${Sql.raw(column)} = ${plain})`;
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
 *   the first use enables it in the database, which records a check value per key. Enabling is
 *   one-way and needs pgcrypto.
 * - Enabled in the database: every statement needs both keys, and they must match the recorded
 *   checks. Missing or different keys fail closed with 503; nothing falls back to plaintext. The
 *   V18 trigger also rejects plaintext writes to protected columns while enabled.
 *
 * The state is read once per process and again after a failure, `IdentityModule.connect` or
 * `IdentityModule.configure`. Every instance must get the keys before any one opts in: an
 * instance that loaded the disabled state keeps writing plaintext, which the trigger refuses.
 */
@Container()
export class ColumnEncryption {
  private state: Promise<ColumnCipher> | undefined;

  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  /** Looked up on each load, like the database, so `IdentityModule.configure` applies. */
  private get settings(): IdentitySettings {
    return useContainer().resolve<IdentitySettings>(IDENTITY_SETTINGS);
  }

  /** The cipher for the next statement. Throws `ColumnEncryptionUnavailable` (503). */
  cipher(): Promise<ColumnCipher> {
    this.state ??= this.load().catch((error: unknown) => {
      this.state = undefined;
      throw error;
    });
    return this.state;
  }

  /** Forgets the loaded state, so the next statement reads it again. */
  reset(): void {
    this.state = undefined;
  }

  private async load(): Promise<ColumnCipher> {
    const { columns } = this.settings.encryption;
    let row = await this.row();
    if (!row.enabled) {
      if (!columns) return ColumnCipher.plaintext;
      const keys = this.requireKeys();
      await this.requirePgcrypto();
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
    return new ColumnCipher(keys);
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

  private async requirePgcrypto(): Promise<void> {
    try {
      await this.db.run('CREATE EXTENSION IF NOT EXISTS pgcrypto');
    } catch {
      throw new ColumnEncryptionUnavailable(
        'column encryption needs the pgcrypto extension, which this database engine does not provide',
      );
    }
  }
}
