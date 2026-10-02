import { Component, Container } from '@di-framework/core/decorators';
import type { AuditEntry, AuditRepository } from '../../audit/domain/audit-entry.ts';
import { AUDIT } from '../../shared/domain/tokens.ts';
import {
  AdminAccessDenied,
  AdminPolicy,
  type AdminResult,
  type AuthorizationContext,
  failure,
  invalidId,
  ok,
  UUID_PATTERN,
} from './admin-policy.ts';

export interface AuditFilter {
  action?: string;
  actor?: string;
  target?: string;
  from?: string;
  to?: string;
}

const SENSITIVE = ['secret', 'password', 'token', 'hash', 'key', 'authorization', 'clientSecret'];

/** Replaces string values of sensitive keys with `[REDACTED]` (`redactSensitiveFields`). */
export function redact(json: string): string {
  if (!json.trim()) return '{}';
  let result = json;
  for (const key of SENSITIVE) {
    result = result.replace(new RegExp(`("?${key}"?\\s*:\\s*)"([^"]*)"`, 'gi'), '$1"[REDACTED]"');
  }
  return result;
}

/**
 * `/admin/audit/**` (`AdminAuditController.kt`): the newest 500 records, filtered in memory.
 * Owners see a record only when an owned slug appears in its target or metadata.
 */
@Container()
export class AuditAdminService {
  constructor(
    @Component(AdminPolicy) private readonly policy: AdminPolicy,
    @Component(AUDIT) private readonly audit: AuditRepository,
  ) {}

  async list(actorId: string, filter: AuditFilter = {}): Promise<AuditEntry[]> {
    await this.policy.check(actorId, 'AUDIT_VIEW');
    const context = await this.policy.context(actorId);
    const from = instant(filter.from);
    const to = instant(filter.to);
    const contains = (value: string | null, needle?: string) =>
      !needle || (value ?? '').toLowerCase().includes(needle.toLowerCase());
    return (await this.audit.list()).filter((record) => {
      const at = Date.parse(record.createdAt);
      return (
        contains(record.action, filter.action) &&
        (!filter.actor || contains(record.actorClientId, filter.actor)) &&
        (!filter.target || contains(record.target, filter.target)) &&
        (from === undefined || at >= from) &&
        (to === undefined || at <= to) &&
        inScope(record, context)
      );
    });
  }

  async detail(actorId: string, id: string): Promise<AdminResult<AuditEntry>> {
    if (!UUID_PATTERN.test(id)) return invalidId();
    await this.policy.check(actorId, 'AUDIT_VIEW');
    const record = await this.audit.find(id);
    if (!record) {
      return failure(404, 'Audit Record Not Found', `Audit record with ID ${id} does not exist.`);
    }
    if (!inScope(record, await this.policy.context(actorId))) {
      throw new AdminAccessDenied('AUDIT_VIEW');
    }
    return ok({
      ...record,
      beforeMetadata: redact(record.beforeMetadata),
      afterMetadata: redact(record.afterMetadata),
    });
  }
}

function inScope(record: AuditEntry, context: AuthorizationContext): boolean {
  if (context.isPlatformAdmin) return true;
  const haystacks = [record.target ?? '', record.beforeMetadata, record.afterMetadata].map(
    (value) => value.toLowerCase(),
  );
  return [...context.ownedOrgSlugs].some((slug) =>
    haystacks.some((value) => value.includes(slug.toLowerCase())),
  );
}

/** `Instant.parse`: an ISO-8601 instant, otherwise the bound is ignored. */
function instant(value: string | undefined): number | undefined {
  if (!value || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z$/.test(value)) return undefined;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? undefined : parsed;
}
