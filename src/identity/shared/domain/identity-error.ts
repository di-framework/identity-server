/** Domain failure with the HTTP status the control plane should return. */
export class IdentityError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'IdentityError';
    this.status = status;
  }
}
