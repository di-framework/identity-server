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
 * Owners see a record only when it belongs to an organization they own (`auditOrganization`).
 * The auth server matches an owned slug anywhere in the target or metadata; that lets the owner
 * of slug `a` read any record whose JSON contains the letter, so this repository does not.
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
  const slug = auditOrganization(record);
  return slug !== undefined && context.ownedOrgSlugs.has(slug);
}

/**
 * The organization a record belongs to, read from the target format its action writes:
 * organization actions target the slug, HTML membership and client actions `{slug}:{id}`, JSON
 * membership actions `{slug}/{userId}`, and HTML invites carry `orgSlug` in their metadata.
 * Every other record (users, links, tokens, JSON clients) has no organization.
 */
export function auditOrganization(record: AuditEntry): string | undefined {
  const target = record.target ?? '';
  const action = record.action;
  if (/^admin\.(org\.|organization_)/.test(action)) return target || undefined;
  if (/^admin\.(membership|oauth_client)\./.test(action)) return prefix(target, ':');
  if (/^admin\.membership_/.test(action)) return prefix(target, '/');
  if (action === 'admin.user.invite') {
    const slug = metadata(record.afterMetadata).orgSlug;
    return typeof slug === 'string' && slug ? slug : undefined;
  }
  return undefined;
}

function prefix(target: string, separator: string): string | undefined {
  const index = target.indexOf(separator);
  return index > 0 ? target.slice(0, index) : undefined;
}

function metadata(json: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(json);
    return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** `Instant.parse`: an ISO-8601 instant, otherwise the bound is ignored. */
function instant(value: string | undefined): number | undefined {
  if (!value || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z$/.test(value)) return undefined;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? undefined : parsed;
}
