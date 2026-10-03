import type { Server } from 'bun';
import { SigningKeys } from '../../src/shared/infrastructure/crypto/signing-keys.ts';
import type { ProviderSettings } from '../../src/shared/infrastructure/identity-settings.ts';
import { rsaPrivateJwk } from './keys.ts';

export interface FakeIdpBehaviour {
  /** Claims merged over the defaults for the next ID token. */
  claims?: Record<string, unknown>;
  /** Status for the token endpoint. */
  status?: number;
  /** Raw token-endpoint body instead of JSON with an id_token. */
  body?: string;
  /** Omit `id_token` from the token response. */
  noIdToken?: boolean;
  /** Sign with a key that is not on the JWKS. */
  foreignKey?: boolean;
}

/** In-process OpenID provider for link tests. Loopback HTTP is allowed by the provider allowlist. */
export class FakeIdp {
  readonly requests: URLSearchParams[] = [];
  behaviour: FakeIdpBehaviour = {};
  subject = `subject-${crypto.randomUUID()}`;
  email: string | undefined = 'linked@provider.example';
  private readonly keys = SigningKeys.load({
    activePrivate: JSON.stringify(rsaPrivateJwk('idp-key')),
    previousPublicSet: '',
    signingAlgorithm: 'RS256',
  });
  private readonly foreign = SigningKeys.load({
    activePrivate: JSON.stringify(rsaPrivateJwk('idp-key')),
    previousPublicSet: '',
    signingAlgorithm: 'RS256',
  });
  private readonly server: Server<undefined>;

  constructor(
    readonly clientId = 'identity-test-client',
    private readonly now = () => Date.now(),
  ) {
    this.server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch: (request) => this.handle(request),
    });
  }

  get issuer(): string {
    return `http://127.0.0.1:${this.server.port}`;
  }

  settings(extra: Partial<ProviderSettings> = {}): ProviderSettings {
    return {
      issuer: this.issuer,
      authorizationEndpoint: `${this.issuer}/authorize`,
      tokenEndpoint: `${this.issuer}/token`,
      jwksUri: `${this.issuer}/jwks`,
      clientId: this.clientId,
      ...extra,
    };
  }

  stop(): void {
    this.server.stop(true);
  }

  private async handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/jwks') return Response.json(this.keys.jwks());
    const form = new URLSearchParams(await request.text());
    this.requests.push(form);
    const behaviour = this.behaviour;
    if (behaviour.body !== undefined) {
      return new Response(behaviour.body, { status: behaviour.status ?? 200 });
    }
    if (behaviour.status && behaviour.status !== 200) {
      return Response.json({ error: 'invalid_grant' }, { status: behaviour.status });
    }
    if (behaviour.noIdToken) return Response.json({ access_token: 'x', token_type: 'Bearer' });
    const seconds = Math.floor(this.now() / 1000);
    const claims = {
      iss: this.issuer,
      sub: this.subject,
      aud: this.clientId,
      iat: seconds,
      exp: seconds + 300,
      auth_time: seconds,
      nonce: this.lastNonce,
      ...(this.email === undefined ? {} : { email: ` ${this.email} ` }),
      ...behaviour.claims,
    };
    const signer = behaviour.foreignKey ? this.foreign : this.keys;
    return Response.json({
      access_token: 'x',
      token_type: 'Bearer',
      id_token: signer.sign(claims),
    });
  }

  /** Nonce from the most recent authorization URL handed to `rememberAuthorization`. */
  lastNonce = '';

  rememberAuthorization(location: string): string {
    const url = new URL(location);
    this.lastNonce = url.searchParams.get('nonce') ?? '';
    return url.searchParams.get('state') ?? '';
  }
}
