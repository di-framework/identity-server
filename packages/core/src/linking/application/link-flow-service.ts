import { Component, Container } from '@di-framework/core/decorators';
import type { AuditRepository } from '../../audit/domain/audit-entry.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import { SecurityNotificationService } from '../../notifications/application/security-notifications.ts';
import type { Clock } from '../../shared/domain/clock.ts';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import {
  AUDIT,
  CLOCK,
  DIRECTORY,
  IDENTITY_PROVIDERS,
  IDENTITY_SETTINGS,
  LINKS,
} from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import type { IdentitySettings } from '../../shared/infrastructure/identity-settings.ts';
import type { IdentityLink, LinkRepository } from '../domain/identity-link.ts';
import type { IdentityProviderClient } from '../infrastructure/http-identity-provider-client.ts';
import { IdentityProviders } from './identity-providers.ts';

/** Link transactions and pending links live 600 seconds (`DEFAULT_TTL_SECONDS`). */
export const LINK_TTL_MS = 600_000;

export interface PendingLink {
  token: string;
  userId: string;
  issuer: string;
  subject: string;
  providerName: string;
  providerEmail: string | null;
  expiresAt: number;
}

export type CallbackResult =
  | { kind: 'pending'; token: string }
  | { kind: 'error'; message: string };

export const CALLBACK_INCOMPLETE =
  'External identity provider returned an error or incomplete authorization payload.';
export const CALLBACK_FAILED =
  'The external identity could not be verified. Start the link flow again.';

/**
 * Explicit, step-up OIDC linking (`IdentityLinkController` start/callback/confirm/cancel and
 * `IdentityLinkService`). `sessionId` is the browser session's stored id. The callback only stages
 * a pending link in memory, as the auth server does; the account owner confirms it.
 */
@Container()
export class LinkFlowService {
  private readonly pending = new Map<string, PendingLink>();

  constructor(
    @Component(LINKS) private readonly links: LinkRepository,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(IdentityProviders) private readonly providers: IdentityProviders,
    @Component(IDENTITY_PROVIDERS) private readonly client: IdentityProviderClient,
    @Component(SecurityNotificationService)
    private readonly notifications: SecurityNotificationService,
    @Component(AUDIT) private readonly audit: AuditRepository,
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  /** Callback URI registered with providers. */
  get redirectUri(): string {
    return `${this.settings.publicOrigin}/account/identity-links/callback`;
  }

  /** Persists the transaction and returns the provider authorization URL. */
  async start(input: {
    userId: string;
    sessionId: string;
    provider: string;
    issuer?: string | null;
    returnUrl?: string | null;
  }): Promise<string> {
    if (!(await this.directory.findUser(input.userId))) {
      throw new IdentityError(404, 'User not found');
    }
    const provider = this.providers.resolve(input.provider, input.issuer);
    const token = Hashing.token();
    const nonce = Hashing.token(16);
    const codeVerifier = Hashing.token();
    const codeChallenge = Hashing.pkceChallenge(codeVerifier);
    const returnUrl = input.returnUrl?.trim() ?? '';
    const now = this.clock.now();
    const providerName = input.provider.trim() || 'External Provider';
    await this.links.insertFlow({
      tokenHash: Hashing.sha256Hex(token),
      userId: input.userId,
      sessionHash: Hashing.sha256Hex(input.sessionId),
      providerName,
      issuer: provider.issuer,
      nonce,
      codeVerifier,
      codeChallenge,
      returnUrl:
        returnUrl.startsWith('/') && !returnUrl.startsWith('//')
          ? returnUrl
          : '/account/identity-links',
      createdAt: now,
      expiresAt: now + LINK_TTL_MS,
    });
    await this.audit.append({
      action: 'identity_link.initiated',
      actor: input.userId,
      target: provider.issuer,
      correlationId: Hashing.sha256Hex(input.sessionId),
      after: { providerName, issuer: provider.issuer },
    });
    const query = [
      ['client_id', provider.clientId],
      ['redirect_uri', this.redirectUri],
      ['response_type', 'code'],
      ['scope', provider.scopes.join(' ')],
      ['state', token],
      ['nonce', nonce],
      ['code_challenge', codeChallenge],
      ['code_challenge_method', 'S256'],
    ]
      .map(([key, value]) => `${key}=${encode(value as string)}`)
      .join('&');
    return `${provider.authorizationEndpoint}?${query}&${provider.freshAuthenticationParameter}`;
  }

  async callback(input: {
    userId: string;
    sessionId: string;
    state?: string | null;
    code?: string | null;
    error?: string | null;
  }): Promise<CallbackResult> {
    if (input.error || !input.state || !input.code) {
      return { kind: 'error', message: CALLBACK_INCOMPLETE };
    }
    try {
      const pending = await this.verify(input.userId, input.sessionId, input.state, input.code);
      await this.audit.append({
        action: 'identity_link.callback_validated',
        actor: input.userId,
        target: target(pending.issuer, pending.subject),
        correlationId: Hashing.sha256Hex(input.sessionId),
        after: { issuer: pending.issuer, providerName: pending.providerName },
      });
      return { kind: 'pending', token: pending.token };
    } catch {
      return { kind: 'error', message: CALLBACK_FAILED };
    }
  }

  /** A live pending link for this user, or undefined. Expired entries are dropped. */
  pendingFor(token: string | null | undefined, userId: string): PendingLink | undefined {
    if (!token) return undefined;
    const pending = this.pending.get(token);
    if (!pending) return undefined;
    if (pending.expiresAt < this.clock.now()) {
      this.pending.delete(token);
      return undefined;
    }
    return pending.userId === userId ? pending : undefined;
  }

  /** Writes `(issuer, subject)` under a row lock. Undefined when the pending link is not valid. */
  async confirm(
    token: string | null | undefined,
    userId: string,
  ): Promise<IdentityLink | undefined> {
    if (!token) return undefined;
    const pending = this.pending.get(token);
    this.pending.delete(token);
    if (!pending || pending.userId !== userId || pending.expiresAt < this.clock.now())
      return undefined;
    const link = await this.directory.transaction(async () => {
      const existing = await this.links.lockByIdentity(pending.issuer, pending.subject);
      if (existing) return existing.userId === userId ? existing : undefined;
      const created = await this.links.insert({
        id: crypto.randomUUID(),
        userId,
        issuer: pending.issuer,
        subject: pending.subject,
        providerName: pending.providerName || 'OAuth Provider',
        providerEmail: pending.providerEmail,
      });
      await this.notifications.enqueue('linked', userId, created, null);
      return created;
    });
    if (!link) return undefined;
    await this.audit.append({
      action: 'identity_link.created',
      actor: userId,
      target: target(link.issuer, link.subject),
      correlationId: Hashing.sha256Hex(token),
      after: {
        id: link.id,
        issuer: link.issuer,
        subject_hint: Hashing.sha256Hex(link.subject).slice(0, 16),
        providerName: link.providerName,
      },
    });
    return link;
  }

  cancel(token: string | null | undefined, userId: string): void {
    if (token && this.pending.get(token)?.userId === userId) this.pending.delete(token);
  }

  private async verify(
    userId: string,
    sessionId: string,
    state: string,
    code: string,
  ): Promise<PendingLink> {
    const flow = await this.links.takeFlow(Hashing.sha256Hex(state));
    if (!flow) throw new Error('Invalid, expired, or replayed link state token');
    if (
      flow.expiresAt < this.clock.now() ||
      flow.userId !== userId ||
      flow.sessionHash !== Hashing.sha256Hex(sessionId)
    ) {
      throw new Error('Link flow state has expired or is bound to a different session or user');
    }
    const provider = this.providers.resolve(flow.providerName, flow.issuer);
    const identity = await this.client.exchange(provider, flow, code, this.redirectUri);
    if (this.providers.canonical(identity.issuer) !== flow.issuer) {
      throw new Error('External identity issuer did not match the link transaction');
    }
    const existing = await this.links.lockByIdentity(flow.issuer, identity.subject);
    if (existing && existing.userId !== userId) {
      throw new Error('This external identity is already linked to another account.');
    }
    const pending: PendingLink = {
      token: `${crypto.randomUUID()}${crypto.randomUUID()}`.replaceAll('-', ''),
      userId,
      issuer: flow.issuer,
      subject: identity.subject,
      providerName: flow.providerName,
      providerEmail: identity.email,
      expiresAt: this.clock.now() + LINK_TTL_MS,
    };
    this.pending.set(pending.token, pending);
    return pending;
  }
}

/** Audit target `issuer#sha256(subject)`: the subject itself is never written to audit. */
function target(issuer: string, subject: string): string {
  return `${issuer}#${Hashing.sha256Hex(subject)}`;
}

/** `URLEncoder.encode`: form encoding with `+` for spaces. */
function encode(value: string): string {
  return encodeURIComponent(value).replaceAll('%20', '+');
}
