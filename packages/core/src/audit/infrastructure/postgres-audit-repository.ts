import { Component, Container } from '@di-framework/core/decorators';
import {
  type ColumnCipher,
  ColumnEncryption,
} from '../../shared/infrastructure/column-encryption.ts';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
import { type Sql, sql } from '../../shared/infrastructure/sql.ts';
import type { AuditRepository, AuditWrite } from '../domain/audit-entry.ts';
import { AuditEntry } from '../domain/audit-entry.ts';

interface AuditRow {
  id: string;
  action: string;
  actor_client_id: string | null;
  target: string | null;
  correlation_id: string | null;
  before_metadata: string;
  after_metadata: string;
  created_at: unknown;
}

/** `before_metadata` and `after_metadata` are encrypted once column encryption is enabled. */
@Container()
export class PostgresAuditRepository implements AuditRepository {
  constructor(
    @Component(PostgresGateway) private readonly db: PostgresGateway,
    @Component(ColumnEncryption) private readonly encryption: ColumnEncryption,
  ) {}

  async append(entry: AuditWrite): Promise<void> {
    const cipher = await this.encryption.cipher();
    const before = JSON.stringify(entry.before ?? {});
    const after = JSON.stringify(entry.after ?? {});
    return this.db.write(
      sql`INSERT INTO auth_audit_records (
         id, action, actor_client_id, target, correlation_id, before_metadata, before_metadata_enc,
         after_metadata, after_metadata_enc
       ) VALUES (${crypto.randomUUID()}, ${entry.action}, ${entry.actor}, ${entry.target},
         ${entry.correlationId}, ${cipher.plain(before, { json: true })}, ${cipher.encrypt(before)},
         ${cipher.plain(after, { json: true })}, ${cipher.encrypt(after)})`,
    );
  }

  async idempotentTarget(action: string, key: string): Promise<string | undefined> {
    const row = await this.db.one<{ target: string | null }>(
      `SELECT target FROM auth_audit_records
       WHERE action = ? AND correlation_id = ?
       ORDER BY created_at ASC
       LIMIT 1`,
      [action, key],
    );
    if (!row?.target) return undefined;
    return row.target;
  }

  async list(): Promise<AuditEntry[]> {
    const cipher = await this.encryption.cipher();
    const rows = await this.db.query<AuditRow>(
      sql`SELECT ${columns(cipher)}
       FROM auth_audit_records
       ORDER BY created_at DESC
       LIMIT 500`,
    );
    return rows.map((row) => this.entry(row));
  }

  async find(id: string): Promise<AuditEntry | undefined> {
    const cipher = await this.encryption.cipher();
    const row = await this.db.one<AuditRow>(
      sql`SELECT ${columns(cipher)} FROM auth_audit_records WHERE id = ${id}`,
    );
    return row ? this.entry(row) : undefined;
  }

  private entry(row: AuditRow): AuditEntry {
    return new AuditEntry(
      String(row.id),
      row.action,
      row.actor_client_id,
      row.target,
      row.correlation_id,
      row.before_metadata,
      row.after_metadata,
      Timestamps.iso(row.created_at),
    );
  }
}

function columns(cipher: ColumnCipher): Sql {
  return sql`id::text AS id, action, actor_client_id, target, correlation_id,
    ${cipher.read('before_metadata', 'before_metadata', { json: true })},
    ${cipher.read('after_metadata', 'after_metadata', { json: true })}, created_at`;
}
