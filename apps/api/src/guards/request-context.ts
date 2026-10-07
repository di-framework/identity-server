import { AsyncLocalStorage } from 'node:async_hooks';

/** Caller resolved from an opaque bearer token. */
export interface TokenCaller {
  kind: 'token';
  /** User id for authorization-code tokens, client id for client-credentials tokens. */
  principalName: string;
  clientId: string;
  scopes: string[];
}

/** Caller resolved from a browser session cookie. */
export interface SessionCaller {
  kind: 'session';
  principalName: string;
  sessionId: string;
  lastAuthenticatedAt: number | null;
}

export type Caller = TokenCaller | SessionCaller;

const storage = new AsyncLocalStorage<Caller>();

/** Request-scoped caller. Replaces the unauthenticated `x-actor-id` header. */
export class RequestContext {
  constructor() {}

  static run<T>(caller: Caller, fn: () => T): T {
    return storage.run(caller, fn);
  }

  static current(): Caller | undefined {
    return storage.getStore();
  }
}
