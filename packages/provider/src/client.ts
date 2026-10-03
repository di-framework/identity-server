import createClient, { type Client } from 'openapi-fetch';
import type { paths } from '../../../apps/client/src/api/schema.d.ts';
import type { Connection } from './types.ts';

export type HttpFetch = (request: Request) => Promise<Response>;
export type AdminApi = Client<paths>;

const RETRYABLE = new Set([408, 429, 500, 502, 503, 504]);

/** Errors carry only the operation and HTTP status, never request or response bodies. */
export class ProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProviderError';
  }
}

/** `unexpectedStatus` from the Go provider. */
export function unexpectedStatus(action: string, response: Response): ProviderError {
  switch (response.status) {
    case 400:
      return new ProviderError(`${action}: server rejected the requested state (Bad Request)`);
    case 404:
      return new ProviderError(`${action}: remote resource does not exist (Not Found)`);
    case 409:
      return new ProviderError(`${action}: invalid state transition (Conflict)`);
    default:
      return new ProviderError(
        `${action}: auth API returned ${response.status} ${response.statusText}`.trim(),
      );
  }
}

/** Delete succeeds on 204, and on 404 or 410 because the resource is already gone. */
export function deleted(response: Response): boolean {
  return response.status === 204 || response.status === 404 || response.status === 410;
}

/**
 * `retryTransport`: three attempts with `100ms << attempt` between them, on transport errors and
 * 408/429/5xx, but only for GET/HEAD or requests carrying an `Idempotency-Key`. Each attempt has
 * a 15-second timeout.
 */
export interface RetryOptions {
  attempts?: number;
  delayMs?: number;
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export function retrying(base: HttpFetch, options: RetryOptions = {}): HttpFetch {
  const attempts = options.attempts ?? 3;
  const delayMs = options.delayMs ?? 100;
  const timeoutMs = options.timeoutMs ?? 15_000;
  // Pulumi runs dynamic providers in its Node language host, where `Bun` does not exist.
  const sleep =
    options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  return async (request) => {
    const retryable =
      request.method === 'GET' ||
      request.method === 'HEAD' ||
      request.headers.has('idempotency-key');
    let lastError: unknown;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (attempt > 0) await sleep(delayMs << attempt);
      const signal = AbortSignal.timeout(timeoutMs);
      try {
        const response = await base(new Request(request.clone() as Request, { signal }));
        if (!retryable || !RETRYABLE.has(response.status) || attempt === attempts - 1)
          return response;
      } catch (error) {
        lastError = error;
        if (!retryable) break;
      }
    }
    throw new ProviderError(
      `auth API request failed: ${lastError instanceof Error ? lastError.message : 'transport error'}`,
    );
  };
}

/**
 * Provisioner client for the protected admin API. Every request runs OIDC discovery against the
 * configured issuer (the advertised issuer must match), obtains a client-credentials token with
 * `admin:read admin:write directory:read`, and sends it as a bearer token, as the Go provider does.
 */
export function adminClient(
  connection: Connection,
  transport: HttpFetch = (request) => fetch(request),
  retry: RetryOptions = {},
): AdminApi {
  const issuer = connection.issuer.replace(/\/+$/, '');
  const baseUrl = (connection.apiUrl || connection.issuer).replace(/\/+$/, '');
  const http = retrying(transport, retry);
  const token = async (): Promise<string> => {
    const discovery = await http(new Request(`${issuer}/.well-known/openid-configuration`));
    if (discovery.status !== 200) {
      throw new ProviderError(`OIDC discovery returned ${discovery.status}`);
    }
    const metadata = (await discovery.json().catch(() => ({}))) as {
      issuer?: string;
      token_endpoint?: string;
    };
    if (metadata.issuer !== issuer || !metadata.token_endpoint) {
      throw new ProviderError('OIDC discovery issuer/token endpoint validation failed');
    }
    const basic = Buffer.from(
      `${encodeURIComponent(connection.provisionerClientId)}:${encodeURIComponent(connection.provisionerClientSecret)}`,
    ).toString('base64');
    const response = await http(
      new Request(metadata.token_endpoint, {
        method: 'POST',
        headers: {
          authorization: `Basic ${basic}`,
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          scope: 'admin:read admin:write directory:read',
        }),
      }),
    );
    if (response.status !== 200) {
      throw new ProviderError(`provisioner token request returned ${response.status}`);
    }
    const body = (await response.json().catch(() => ({}))) as { access_token?: string };
    if (!body.access_token) throw new ProviderError('invalid provisioner token response');
    return body.access_token;
  };
  return createClient<paths>({
    baseUrl,
    fetch: async (request: Request) => {
      const headers = new Headers(request.headers);
      headers.set('authorization', `Bearer ${await token()}`);
      return http(new Request(request, { headers }));
    },
  });
}
