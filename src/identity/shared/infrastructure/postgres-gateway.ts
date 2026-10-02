import { Component, Container } from '@di-framework/core/decorators';
import type { SqlDatabase } from '@di-framework/repo';
import { IdentityError } from '../domain/identity-error.ts';
import { IDENTITY_DATABASE } from '../domain/tokens.ts';

/** Shared Postgres access for infrastructure adapters. */
@Container()
export class PostgresGateway {
  constructor(@Component(IDENTITY_DATABASE) private readonly database: SqlDatabase) {}

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

  transaction<T>(fn: () => Promise<T>): Promise<T> {
    return this.database.transaction(async () => fn());
  }

  async count(sql: string, params: unknown[] = []): Promise<number> {
    const row = await this.one<{ count: unknown }>(sql, params);
    return Number(row?.count ?? 0);
  }

  isUnique(error: unknown): boolean {
    if (typeof error !== 'object' || error === null) return false;
    const record = error as { code?: unknown; message?: unknown };
    if (record.code === '23505') return true;
    return typeof record.message === 'string' && record.message.includes('duplicate key');
  }
}

/** Formats database timestamps for control-plane JSON. */
export class Timestamps {
  static iso(value: unknown): string {
    const date = value instanceof Date ? value : new Date(String(value));
    return date.toISOString();
  }
}
