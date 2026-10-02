export class IdentityLink {
  constructor(
    readonly id: string,
    readonly providerName: string,
    readonly issuer: string,
    readonly subject: string,
    readonly createdAt: string,
    readonly updatedAt: string,
  ) {}
}

export class UnlinkConfirmation {
  constructor(
    readonly tokenHash: string,
    readonly userId: string,
    readonly sessionHash: string,
    readonly issuer: string,
    readonly subject: string,
    readonly expiresAtMs: number,
  ) {}
}

export interface NewConfirmation {
  tokenHash: string;
  userId: string;
  sessionHash: string;
  issuer: string;
  subject: string;
  expiresAt: Date;
}

export interface LinkRepository {
  list(userId: string): Promise<IdentityLink[]>;
  find(userId: string, issuer: string, subject: string): Promise<IdentityLink | undefined>;
  countOther(userId: string, linkId: string): Promise<number>;
  delete(id: string): Promise<void>;
  insertConfirmation(confirmation: NewConfirmation): Promise<void>;
  findConfirmation(tokenHash: string): Promise<UnlinkConfirmation | undefined>;
  deleteConfirmation(tokenHash: string): Promise<void>;
}
