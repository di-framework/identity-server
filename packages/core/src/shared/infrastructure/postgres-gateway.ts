import { useContainer } from '@di-framework/core/container';
import { Container } from '@di-framework/core/decorators';
import type { SqlDatabase } from '@di-framework/repo';
import { IdentityError } from '../domain/identity-error.ts';
import { IDENTITY_DATABASE } from '../domain/tokens.ts';

/**
 * Shared Postgres access for infrastructure adapters. The database is looked up on each call,
 * so `IdentityModule.connect` can replace it after adapters were constructed.
 */
@Container()
export class PostgresGateway {
  private get database(): SqlDatabase {
    return useContainer().resolve<SqlDatabase>(IDENTITY_DATABASE);
  }

  query<T>(sql: string, params: unknown[] = []): Promise<T[]> {
    return this.database.query<T>(sql, params);
  }

  async one<T>(sql: string, params: unknown[] = []): Promise<T | undefined> {
    const row = await this.database.first<T>(sql, params);
    return row ?? undefined;
  }

  run(sql: string, params: unknown[] = []): Promise<{ changes?: number }> {
    return this.database.run(sql, params);
  }

  async write(sql: string, params: unknown[] = []): Promise<void> {
    try {
      await this.database.run(sql, params);
    } catch (error) {
      throw this.isUnique(error) ? new IdentityError(409, 'Conflict') : error;
    }
  }

  /** Runs `fn` in one transaction. Statements issued inside it, at any depth, join it. */
  transaction<T>(fn: () => Promise<T>): Promise<T> {
    return this.database.transaction(async () => fn());
  }

  async count(sql: string, params: unknown[] = []): Promise<number> {
    const row = await this.one<{ count: unknown }>(sql, params);
    return Number(row?.count ?? 0);
  }

  isUnique(error: unknown): boolean {
    if (typeof error !== 'object' || error === null) return false;
    const record = error as { code?: unknown; errno?: unknown; message?: unknown };
    if (record.code === '23505' || record.errno === '23505') return true;
    return typeof record.message === 'string' && record.message.includes('duplicate key');
  }
}

/** Formats database timestamps for control-plane JSON. */
export class Timestamps {
  static iso(value: unknown): string {
    const date = value instanceof Date ? value : new Date(String(value));
    return date.toISOString();
  }

  static ms(value: unknown): number {
    return (value instanceof Date ? value : new Date(String(value))).getTime();
  }

  static isoOrNull(value: unknown): string | null {
    return value == null ? null : Timestamps.iso(value);
  }
}
