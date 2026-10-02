/** Outcome of an application use case. The HTTP adapter turns it into a response. */
export class ServiceResult<T = unknown> {
  constructor(
    readonly status: number,
    readonly body?: T,
  ) {}
}
