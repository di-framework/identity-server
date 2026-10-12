import { useContainer } from '@di-framework/core/container';
import { Container } from '@di-framework/core/decorators';
import type { SqlDatabase } from '@di-framework/repo';
import { IdentityError } from '../domain/identity-error.ts';
import { IDENTITY_DATABASE } from '../domain/tokens.ts';
import { redactStatement } from './error-redaction.ts';
import type { Sql } from './sql.ts';

/** SQLSTATE the V18 trigger raises for a plaintext write while column encryption is enabled. */
export const PLAINTEXT_REJECTED = 'IDC01';

/** A statement: SQL text plus bindings, or a composed `Sql` fragment that carries its own. */
type Statement = string | Sql;

function bind(statement: Statement, params: unknown[]): [string, unknown[]] {
  return typeof statement === 'string'
    ? [statement, params]
    : [statement.text, [...statement.params]];
}

/**
 * Shared Postgres access for infrastructure adapters. The database is looked up on each call,
 * so `IdentityModule.connect` can replace it after adapters were constructed.
 */
@Container()
export class PostgresGateway {
  private readonly rejectionListeners = new Set<() => void>();

  private get database(): SqlDatabase {
    return useContainer().resolve<SqlDatabase>(IDENTITY_DATABASE);
  }

  async query<T>(statement: Statement, params: unknown[] = []): Promise<T[]> {
    try {
      return await this.database.query<T>(...bind(statement, params));
    } catch (error) {
      throw this.translate(redactStatement(error));
    }
  }

  async one<T>(statement: Statement, params: unknown[] = []): Promise<T | undefined> {
    try {
      const row = await this.database.first<T>(...bind(statement, params));
      return row ?? undefined;
    } catch (error) {
      throw this.translate(redactStatement(error));
    }
  }

  async run(statement: Statement, params: unknown[] = []): Promise<{ changes?: number }> {
    try {
      return await this.database.run(...bind(statement, params));
    } catch (error) {
      throw this.translate(redactStatement(error));
    }
  }

  async write(statement: Statement, params: unknown[] = []): Promise<void> {
    await this.writeCount(statement, params);
  }

  /** `write` that returns the changed row count; a unique violation is a 409. */
  async writeCount(statement: Statement, params: unknown[] = []): Promise<number> {
    try {
      return (await this.database.run(...bind(statement, params))).changes ?? 0;
    } catch (error) {
      throw this.isUnique(error)
        ? new IdentityError(409, 'Conflict')
        : this.translate(redactStatement(error));
    }
  }

  /** Runs `fn` in one transaction. Statements issued inside it, at any depth, join it. */
  transaction<T>(fn: () => Promise<T>): Promise<T> {
    return this.database.transaction(async () => fn());
  }

  async count(statement: Statement, params: unknown[] = []): Promise<number> {
    const row = await this.one<{ count: unknown }>(statement, params);
    return Number(row?.count ?? 0);
  }

  /**
   * A plaintext write the V18 trigger refused: this process has not loaded the enabled
   * encryption state (it started before another instance enabled it). Fail closed with 503.
   */
  private translate(error: unknown): unknown {
    const record = (error ?? {}) as { code?: unknown; errno?: unknown };
    if (record.code === PLAINTEXT_REJECTED || record.errno === PLAINTEXT_REJECTED) {
      for (const listener of this.rejectionListeners) listener();
      return new IdentityError(503, 'Column encryption was enabled by another instance; retry');
    }
    return error;
  }

  /** Called when the database refuses a plaintext write, so cached encryption state is re-read. */
  onPlaintextRejected(listener: () => void): void {
    this.rejectionListeners.add(listener);
  }

  isUnique(error: unknown): boolean {
    if (typeof error !== 'object' || error === null) return false;
    const record = error as { code?: unknown; errno?: unknown; message?: unknown };
    if (record.code === '23505' || record.errno === '23505') return true;
    return typeof record.message === 'string' && record.message.includes('duplicate key');
  }
}

/** Formats database timestamps for control-plane JSON. */
export const Timestamps = {
  iso(value: unknown): string {
    const date = value instanceof Date ? value : new Date(String(value));
    return date.toISOString();
  },

  ms(value: unknown): number {
    return (value instanceof Date ? value : new Date(String(value))).getTime();
  },

  isoOrNull(value: unknown): string | null {
    return value == null ? null : Timestamps.iso(value);
  },
};
