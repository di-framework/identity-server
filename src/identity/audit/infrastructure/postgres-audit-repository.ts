import { Component, Container } from '@di-framework/core/decorators';
import { PostgresGateway, Timestamps } from '../../shared/infrastructure/postgres-gateway.ts';
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

@Container()
export class PostgresAuditRepository implements AuditRepository {
  constructor(@Component(PostgresGateway) private readonly db: PostgresGateway) {}

  append(entry: AuditWrite): Promise<void> {
    return this.db.write(
      `INSERT INTO auth_audit_records (
         id, action, actor_client_id, target, correlation_id, before_metadata, after_metadata
       ) VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb)`,
      [
        crypto.randomUUID(),
        entry.action,
        entry.actor,
        entry.target,
        entry.correlationId,
        JSON.stringify(entry.before ?? {}),
        JSON.stringify(entry.after ?? {}),
      ],
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
    const rows = await this.db.query<AuditRow>(
      `SELECT id::text AS id, action, actor_client_id, target, correlation_id,
              before_metadata::text AS before_metadata, after_metadata::text AS after_metadata, created_at
       FROM auth_audit_records
       ORDER BY created_at DESC
       LIMIT 500`,
    );
    return rows.map(
      (row) =>
        new AuditEntry(
          String(row.id),
          row.action,
          row.actor_client_id,
          row.target,
          row.correlation_id,
          row.before_metadata,
          row.after_metadata,
          Timestamps.iso(row.created_at),
        ),
    );
  }
}
