import { Component, Container } from '@di-framework/core/decorators';
import { ServiceResult } from '../../shared/domain/service-result.ts';
import { AUDIT } from '../../shared/domain/tokens.ts';
import type { AuditEntry, AuditRepository } from '../domain/audit-entry.ts';

@Container()
export class AuditService {
  constructor(@Component(AUDIT) private readonly audit: AuditRepository) {}

  async list(): Promise<ServiceResult<ReturnType<AuditService['entry']>[]>> {
    const records = await this.audit.list();
    return new ServiceResult(
      200,
      records.map((record) => this.entry(record)),
    );
  }

  private entry(record: AuditEntry) {
    return {
      id: record.id,
      action: record.action,
      actor_client_id: record.actorClientId,
      target: record.target,
      correlation_id: record.correlationId,
      before_metadata: record.beforeMetadata,
      after_metadata: record.afterMetadata,
      created_at: record.createdAt,
    };
  }
}
