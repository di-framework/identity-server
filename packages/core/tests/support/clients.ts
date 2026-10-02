import { useContainer } from '@di-framework/core/container';
import type { RegisteredClientRepository } from '../../src/authorization/domain/models.ts';
import { REGISTERED_CLIENTS } from '../../src/shared/domain/tokens.ts';
import { Hashing } from '../../src/shared/infrastructure/crypto/hashing.ts';
import { PasswordHasher } from '../../src/shared/infrastructure/crypto/passwords.ts';

export interface TestClient {
  clientId: string;
  secret: string;
  basic: string;
}

/** Registers a confidential client directly in Postgres. */
export async function registerClient(
  options: {
    clientId?: string;
    grantTypes?: string[];
    scopes?: string[];
    methods?: string[];
    redirectUris?: string[];
    requireProofKey?: boolean;
    requireAuthorizationConsent?: boolean;
    organizationSlug?: string | null;
  } = {},
): Promise<TestClient> {
  const clientId = options.clientId ?? `test-${Hashing.token(6)}`;
  const secret = Hashing.token();
  const repository = useContainer().resolve<RegisteredClientRepository>(REGISTERED_CLIENTS);
  await repository.insert({
    clientId,
    clientName: clientId,
    secretHash: await new PasswordHasher().hash(secret),
    authenticationMethods: options.methods ?? ['client_secret_basic', 'client_secret_post'],
    grantTypes: options.grantTypes ?? ['client_credentials'],
    redirectUris: options.redirectUris ?? [],
    scopes: options.scopes ?? ['admin:read', 'admin:write', 'directory:read'],
    settings: {
      requireProofKey: options.requireProofKey ?? false,
      requireAuthorizationConsent: options.requireAuthorizationConsent ?? false,
    },
    organizationSlug: options.organizationSlug ?? null,
  });
  return { clientId, secret, basic: basic(clientId, secret) };
}

export function basic(clientId: string, secret: string): string {
  const encode = (value: string) => encodeURIComponent(value);
  return `Basic ${Buffer.from(`${encode(clientId)}:${encode(secret)}`).toString('base64')}`;
}

/** Form POST against any `fetch`-shaped handler. */
export function formRequest(
  path: string,
  form: Record<string, string>,
  headers: Record<string, string> = {},
): Request {
  return new Request(`https://identity.test${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(form),
  });
}

/** Client-credentials bearer token for a fresh client with the given scopes. */
export async function bearerFor(
  fetch: (request: Request) => Promise<Response>,
  scopes: string[],
): Promise<string> {
  const client = await registerClient({ scopes });
  const response = await fetch(
    formRequest(
      '/oauth2/token',
      { grant_type: 'client_credentials', scope: scopes.join(' ') },
      { authorization: client.basic },
    ),
  );
  const body = (await response.json()) as { access_token: string };
  return body.access_token;
}
