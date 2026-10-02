import createClient from 'openapi-fetch';
import type { paths } from './schema.d.ts';

/** Typed client for the identity OpenAPI document. `openapi-fetch` sends the calls. */
export function createIdentityClient(options: {
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
}) {
  return createClient<paths>({
    baseUrl: options.baseUrl,
    ...(options.fetch ? { fetch: options.fetch } : {}),
  });
}

export type IdentityClient = ReturnType<typeof createIdentityClient>;
