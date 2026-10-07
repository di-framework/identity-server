import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { AuthorizationRepository } from '../../authorization/domain/models.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import { SecurityNotificationService } from '../../notifications/application/security-notifications.ts';
import type { Clock } from '../../shared/domain/clock.ts';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import { IssuerCanonicalizer } from '../../shared/domain/issuer.ts';
import { ServiceResult } from '../../shared/domain/service-result.ts';
import { AUDIT, AUTHORIZATIONS, CLOCK, DIRECTORY, LINKS } from '../../shared/domain/tokens.ts';
import { Hashing, TOKEN_PATTERN } from '../../shared/infrastructure/crypto/hashing.ts';
import type { IdentityLink, LinkRepository } from '../domain/identity-link.ts';

/** Unlinking requires a sign-in within this window (`requireRecentAuthentication`). */
export const RECENT_AUTHENTICATION_MS = 15 * 60 * 1000;
/** Unlink confirmations live 300 seconds. */
export const UNLINK_TTL_MS = 300_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The caller of an account route. `sessionId` is absent for bearer-token callers. */
export interface AccountCaller {
  userId: string;
  sessionId?: string;
  lastAuthenticatedAt?: number | null;
}

/**
 * Linked identities and unlinking for the JSON account API and the account pages
 * (`IdentityLinkController`, `IdentityLinkService`). Unlinking needs a recent sign-in, a
 * single-use 5-minute confirmation bound to the user and session, and a remaining sign-in
 * method. Success revokes the account's persisted access and refresh tokens and queues a
 * security notification; the browser session stays.
 */
@Container()
export class LinkService {
  constructor(
    @Component(LINKS) private readonly links: LinkRepository,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(IssuerCanonicalizer) private readonly issuers: IssuerCanonicalizer,
    @Component(AUTHORIZATIONS) private readonly authorizations: AuthorizationRepository,
    @Component(SecurityNotificationService)
    private readonly notifications: SecurityNotificationService,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  async list(caller: AccountCaller | undefined): Promise<ServiceResult> {
    if (!caller || !UUID.test(caller.userId)) return new ServiceResult(403);
    const user = await this.directory.findUser(caller.userId);
    if (!user) return new ServiceResult(404);
    return new ServiceResult(200, await this.views(user.id));
  }

  async views(userId: string) {
    return (await this.links.list(userId)).map((link) => this.view(link));
  }

  /** `POST /api/v1/account/identity-links/unlink/prepare`. */
  async prepare(
    caller: AccountCaller | undefined,
    input: { issuer?: string; subject?: string },
  ): Promise<ServiceResult> {
    if (!caller || !UUID.test(caller.userId)) return new ServiceResult(403);
    if (!this.recent(caller)) return new ServiceResult(403);
    const issuer = this.issuer(input.issuer ?? '');
    if (issuer instanceof ServiceResult) return issuer;
    const subject = input.subject?.trim() ?? '';
    if (!subject) return new ServiceResult(400);
    const created = await this.createConfirmation(caller, issuer, subject);
    if (created instanceof ServiceResult) return created;
    return new ServiceResult(200, {
      confirmation_token: created.token,
      expires_in: UNLINK_TTL_MS / 1000,
      identity: this.view(created.link),
    });
  }

  /** `DELETE /api/v1/account/identity-links`. */
  async unlink(
    caller: AccountCaller | undefined,
    input: { issuer?: string; subject?: string; confirmationToken?: string },
  ): Promise<ServiceResult> {
    if (!caller || !UUID.test(caller.userId)) return new ServiceResult(403);
    if (!caller.sessionId || !input.confirmationToken) return new ServiceResult(400);
    const issuer = this.issuer(input.issuer ?? '');
    if (issuer instanceof ServiceResult) return issuer;
    const subject = input.subject?.trim() ?? '';
    if (!subject) return new ServiceResult(400);
    const result = await this.consume(caller, input.confirmationToken, { issuer, subject });
    if (result instanceof ServiceResult) return result;
    return new ServiceResult(200, {
      unlinked: true,
      issuer: result.issuer,
      subject_hint: hint(result.subject),
    });
  }

  /** `POST /account/identity-links/unlink/start`: returns the token the session keeps. */
  async startUnlink(caller: AccountCaller, linkId: string): Promise<string | ServiceResult> {
    if (!this.recent(caller)) return new ServiceResult(403);
    const link = UUID.test(linkId) ? await this.links.findById(linkId) : undefined;
    if (!link || link.userId !== caller.userId) return new ServiceResult(403);
    const created = await this.createConfirmation(caller, link.issuer, link.subject);
    return created instanceof ServiceResult ? created : created.token;
  }

  /** The identity a live confirmation for this user and session points at. */
  async pendingUnlink(caller: AccountCaller): Promise<ReturnType<LinkService['view']> | undefined> {
    if (!caller.sessionId) return undefined;
    const confirmation = await this.links.latestConfirmation(
      caller.userId,
      Hashing.sha256Hex(caller.sessionId),
    );
    if (!confirmation || confirmation.expiresAtMs <= this.clock.now()) return undefined;
    const link = await this.links.find(caller.userId, confirmation.issuer, confirmation.subject);
    return link ? this.view(link) : undefined;
  }

  /** `POST /account/identity-links/unlink/confirm`. True when the identity was removed. */
  async confirmUnlink(caller: AccountCaller, token: string | null | undefined): Promise<boolean> {
    if (!token || !caller.sessionId) return false;
    return !((await this.consume(caller, token)) instanceof ServiceResult);
  }

  private recent(caller: AccountCaller): boolean {
    const at = caller.lastAuthenticatedAt;
    return (
      Boolean(caller.sessionId) &&
      typeof at === 'number' &&
      this.clock.now() - at <= RECENT_AUTHENTICATION_MS
    );
  }

  private createConfirmation(
    caller: AccountCaller,
    issuer: string,
    subject: string,
  ): Promise<{ token: string; link: IdentityLink } | ServiceResult> {
    return this.directory.transaction(async () => {
      const user = await this.directory.lockUser(caller.userId);
      if (!user) return new ServiceResult(404);
      if (user.status !== 'active') return new ServiceResult(409);
      const link = await this.links.lockForUser(user.id, issuer, subject);
      if (!link) return new ServiceResult(404);
      const token = Hashing.token();
      await this.links.insertConfirmation({
        tokenHash: Hashing.sha256Hex(token),
        userId: user.id,
        sessionHash: Hashing.sha256Hex(caller.sessionId ?? ''),
        issuer,
        subject,
        expiresAt: new Date(this.clock.now() + UNLINK_TTL_MS),
      });
      return { token, link };
    });
  }

  /** Single-use: the confirmation is deleted before it is checked. */
  private async consume(
    caller: AccountCaller,
    token: string,
    expected?: { issuer: string; subject: string },
  ): Promise<IdentityLink | ServiceResult> {
    if (!TOKEN_PATTERN.test(token)) return new ServiceResult(400);
    const confirmation = await this.links.findConfirmation(Hashing.sha256Hex(token));
    if (!confirmation) return new ServiceResult(400);
    await this.links.deleteConfirmation(confirmation.tokenHash);
    if (
      confirmation.userId !== caller.userId ||
      confirmation.sessionHash !== Hashing.sha256Hex(caller.sessionId ?? '') ||
      confirmation.expiresAtMs <= this.clock.now()
    ) {
      return new ServiceResult(400);
    }
    if (
      expected &&
      (confirmation.issuer !== expected.issuer || confirmation.subject !== expected.subject)
    ) {
      return new ServiceResult(400);
    }
    const removed = await this.remove(caller, confirmation.issuer, confirmation.subject);
    if (removed instanceof ServiceResult) return removed;
    await this.audit.append({
      action: 'identity_link.removed',
      actor: caller.userId,
      target: `${removed.issuer}#${Hashing.sha256Hex(removed.subject)}`,
      correlationId: Hashing.sha256Hex(caller.sessionId ?? ''),
      before: { providerName: removed.providerName, subject_hint: hint(removed.subject) },
    });
    return removed;
  }

  private remove(
    caller: AccountCaller,
    issuer: string,
    subject: string,
  ): Promise<IdentityLink | ServiceResult> {
    return this.directory.transaction(async () => {
      const user = await this.directory.lockUser(caller.userId);
      if (user?.status !== 'active') return new ServiceResult(409);

      const link = await this.links.lockForUser(user.id, issuer, subject);
      if (!link) return new ServiceResult(404);
      const remaining = await this.links.countOther(user.id, link.id);
      const hasPassword = Boolean(user.passwordHash?.trim());
      const hasVerifiedEmail = user.emailVerified && Boolean(user.email?.trim());
      if (!hasPassword && !hasVerifiedEmail && remaining === 0) return new ServiceResult(409);
      await this.links.delete(link.id);
      await this.authorizations.deleteByPrincipal(user.id);
      await this.notifications.enqueue('unlinked', user.id, link, caller.sessionId ?? null);
      return link;
    });
  }

  private issuer(raw: string): string | ServiceResult {
    try {
      return this.issuers.canonicalize(raw);
    } catch (error) {
      return new ServiceResult(error instanceof IdentityError ? error.status : 500);
    }
  }

  view(link: IdentityLink) {
    return {
      id: link.id,
      providerName: link.providerName,
      issuer: link.issuer,
      subjectHint: hint(link.subject),
      createdAt: link.createdAt,
      updatedAt: link.updatedAt,
    };
  }
}

function hint(subject: string): string {
  return Hashing.sha256Hex(subject).slice(0, 16);
}
