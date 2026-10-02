export class AuditEntry {
  constructor(
    readonly id: string,
    readonly action: string,
    readonly actorClientId: string | null,
    readonly target: string | null,
    readonly correlationId: string | null,
    readonly beforeMetadata: string,
    readonly afterMetadata: string,
    readonly createdAt: string,
  ) {}
}

export interface AuditWrite {
  action: string;
  /** Principal name, or null for system actions such as passwordless delivery. */
  actor: string | null;
  target: string | null;
  correlationId: string | null;
  before?: unknown;
  after?: unknown;
}

export interface AuditRepository {
  append(entry: AuditWrite): Promise<void>;
  idempotentTarget(action: string, key: string): Promise<string | undefined>;
  list(): Promise<AuditEntry[]>;
  find(id: string): Promise<AuditEntry | undefined>;
}
