export class IdentityLink {
  constructor(
    readonly id: string,
    readonly providerName: string,
    readonly issuer: string,
    readonly subject: string,
    readonly createdAt: string,
    readonly updatedAt: string,
    readonly userId: string = '',
    readonly providerEmail: string | null = null,
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

export interface NewIdentityLink {
  id: string;
  userId: string;
  issuer: string;
  subject: string;
  providerName: string;
  providerEmail: string | null;
}

/** An `identity_link_flows` row: the persisted start of a link transaction. */
export interface LinkFlow {
  tokenHash: string;
  userId: string;
  sessionHash: string;
  providerName: string;
  issuer: string;
  nonce: string;
  codeVerifier: string;
  codeChallenge: string;
  returnUrl: string;
  createdAt: number;
  expiresAt: number;
}

export interface LinkRepository {
  list(userId: string): Promise<IdentityLink[]>;
  find(userId: string, issuer: string, subject: string): Promise<IdentityLink | undefined>;
  findById(id: string): Promise<IdentityLink | undefined>;
  delete(id: string): Promise<void>;
  /**
   * Deletes a link in one statement unless it is the account's last way to sign in: no
   * password, no verified email, and no other link. The other links are locked, so two
   * concurrent unlinks cannot both pass. False when nothing was deleted.
   */
  deleteUnlessLastMethod(id: string): Promise<boolean>;
  insert(link: NewIdentityLink): Promise<IdentityLink>;
  /** `(issuer, subject)` row with `FOR UPDATE`, in any account. */
  lockByIdentity(issuer: string, subject: string): Promise<IdentityLink | undefined>;
  /** A user's link with `FOR UPDATE`. */
  lockForUser(userId: string, issuer: string, subject: string): Promise<IdentityLink | undefined>;
  insertConfirmation(confirmation: NewConfirmation): Promise<void>;
  /** Deletes and returns a confirmation, so a confirmation token is single-use. */
  takeConfirmation(tokenHash: string): Promise<UnlinkConfirmation | undefined>;
  /** Newest confirmation for a user and session. */
  latestConfirmation(userId: string, sessionHash: string): Promise<UnlinkConfirmation | undefined>;
  insertFlow(flow: LinkFlow): Promise<void>;
  /** Deletes and returns a flow, so a state token is single-use. */
  takeFlow(tokenHash: string): Promise<LinkFlow | undefined>;
}
