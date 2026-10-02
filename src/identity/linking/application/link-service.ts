import { randomBytes } from 'node:crypto';
import { Component, Container } from '@di-framework/core/decorators';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import { ClientSecrets } from '../../shared/domain/client-secrets.ts';
import { IdentityError } from '../../shared/domain/identity-error.ts';
import { IssuerCanonicalizer } from '../../shared/domain/issuer.ts';
import { ServiceResult } from '../../shared/domain/service-result.ts';
import { DIRECTORY, LINKS } from '../../shared/domain/tokens.ts';
import type { IdentityLink, LinkRepository } from '../domain/identity-link.ts';

const TOKEN = /^[A-Za-z0-9_-]{43}$/;

@Container()
export class LinkService {
  constructor(
    @Component(LINKS) private readonly links: LinkRepository,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(IssuerCanonicalizer) private readonly issuers: IssuerCanonicalizer,
    @Component(ClientSecrets) private readonly secrets: ClientSecrets,
  ) {}

  async list(userId: string | undefined): Promise<ServiceResult> {
    if (!userId) return new ServiceResult(400);
    const user = await this.directory.findUser(userId);
    if (!user) return new ServiceResult(404);
    const links = await this.links.list(user.id);
    return new ServiceResult(
      200,
      links.map((link) => this.view(link)),
    );
  }

  async prepare(input: {
    userId?: string;
    sessionId?: string;
    issuer?: string;
    subject?: string;
  }): Promise<ServiceResult> {
    if (!input.userId || !input.sessionId) return new ServiceResult(400);
    const issuer = this.issuer(input.issuer ?? '');
    if (issuer instanceof ServiceResult) return issuer;
    const subject = input.subject?.trim() ?? '';
    if (!subject) return new ServiceResult(400);
    const user = await this.directory.findUser(input.userId);
    if (!user) return new ServiceResult(404);
    if (user.status !== 'active') return new ServiceResult(409);
    const link = await this.links.find(user.id, issuer, subject);
    if (!link) return new ServiceResult(404);
    const token = randomBytes(32).toString('base64url');
    await this.links.insertConfirmation({
      tokenHash: this.secrets.hash(token),
      userId: user.id,
      sessionHash: this.secrets.hash(input.sessionId),
      issuer,
      subject,
      expiresAt: new Date(Date.now() + 300_000),
    });
    return new ServiceResult(200, {
      confirmation_token: token,
      expires_in: 300,
      identity: this.view(link),
    });
  }

  async unlink(input: {
    userId?: string;
    sessionId?: string;
    issuer?: string;
    subject?: string;
    confirmationToken?: string;
  }): Promise<ServiceResult> {
    if (!input.userId || !input.sessionId || !input.confirmationToken)
      return new ServiceResult(400);
    if (!TOKEN.test(input.confirmationToken)) return new ServiceResult(400);
    const issuer = this.issuer(input.issuer ?? '');
    if (issuer instanceof ServiceResult) return issuer;
    const subject = input.subject?.trim() ?? '';
    if (!subject) return new ServiceResult(400);
    const confirmation = await this.links.findConfirmation(
      this.secrets.hash(input.confirmationToken),
    );
    if (!confirmation) return new ServiceResult(400);
    await this.links.deleteConfirmation(confirmation.tokenHash);
    if (
      confirmation.userId !== input.userId ||
      confirmation.sessionHash !== this.secrets.hash(input.sessionId)
    ) {
      return new ServiceResult(400);
    }
    if (confirmation.expiresAtMs <= Date.now()) return new ServiceResult(400);
    if (confirmation.issuer !== issuer || confirmation.subject !== subject)
      return new ServiceResult(400);
    return this.remove(input.userId, issuer, subject);
  }

  private async remove(userId: string, issuer: string, subject: string): Promise<ServiceResult> {
    const user = await this.directory.findUser(userId);
    if (!user || user.status !== 'active') return new ServiceResult(409);
    const link = await this.links.find(user.id, issuer, subject);
    if (!link) return new ServiceResult(404);
    const remaining = await this.links.countOther(user.id, link.id);
    const usable = Boolean(user.passwordHash) || user.emailVerified === true;
    if (!usable && remaining === 0) return new ServiceResult(409);
    await this.links.delete(link.id);
    return new ServiceResult(200, {
      unlinked: true,
      issuer: link.issuer,
      subject_hint: this.secrets.hint(link.subject),
    });
  }

  private issuer(raw: string): string | ServiceResult {
    try {
      return this.issuers.canonicalize(raw);
    } catch (error) {
      return new ServiceResult(error instanceof IdentityError ? error.status : 500);
    }
  }

  private view(link: IdentityLink) {
    return {
      id: link.id,
      providerName: link.providerName,
      issuer: link.issuer,
      subjectHint: this.secrets.hint(link.subject),
      createdAt: link.createdAt,
      updatedAt: link.updatedAt,
    };
  }
}
