import { createPrivateKey, createPublicKey, type KeyObject, sign, verify } from 'node:crypto';

export type SigningAlgorithm = 'RS256' | 'ML-DSA-65';

export const SIGNING_ALGORITHMS: readonly SigningAlgorithm[] = ['RS256', 'ML-DSA-65'];

/** Public JWK as published on JWKS. */
export type PublicJwk = Record<string, unknown> & { kty: string; kid?: string };

/** Startup failure. Messages never contain key material. */
export class SigningKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SigningKeyError';
  }
}

const RSA_PRIVATE = ['d', 'p', 'q', 'dp', 'dq', 'qi'];
const AKP_PUBLIC_BYTES = 1952;
const AKP_SEED_BYTES = 32;

/**
 * Active signing key plus the previous public set, validated the way the auth server's
 * `SecurityConfiguration` validates `AUTH_ACTIVE_PRIVATE_JWK` and `AUTH_PREVIOUS_PUBLIC_JWK_SET`.
 */
export class SigningKeys {
  private constructor(
    readonly algorithm: SigningAlgorithm,
    readonly kid: string,
    private readonly privateKey: KeyObject,
    private readonly activePublic: PublicJwk,
    private readonly previous: PublicJwk[],
  ) {}

  static load(input: {
    activePrivate: string;
    previousPublicSet: string;
    signingAlgorithm: string;
  }): SigningKeys {
    const algorithm = input.signingAlgorithm.trim() as SigningAlgorithm;
    if (!SIGNING_ALGORITHMS.includes(algorithm)) {
      throw new SigningKeyError('Unsupported signing algorithm');
    }
    if (!input.activePrivate.trim()) {
      throw new SigningKeyError('AUTH_ACTIVE_PRIVATE_JWK is required');
    }
    const jwk = SigningKeys.parseObject(input.activePrivate, 'Active private JWK');
    const kid = typeof jwk.kid === 'string' ? jwk.kid.trim() : '';
    if (!kid) throw new SigningKeyError('Active private JWK must include a kid');
    if (algorithm === 'RS256') {
      if (jwk.kty !== 'RSA') throw new SigningKeyError('RS256 requires an RSA JWK');
      if (typeof jwk.d !== 'string') {
        throw new SigningKeyError('Active JWK must contain private material');
      }
    } else {
      SigningKeys.checkAkp(jwk, true);
    }
    const privateKey = SigningKeys.importPrivate(jwk);
    const activePublic = SigningKeys.publicOf(createPublicKey(privateKey), kid, algorithm);
    return new SigningKeys(
      algorithm,
      kid,
      privateKey,
      activePublic,
      SigningKeys.parsePrevious(input.previousPublicSet),
    );
  }

  /** JWKS document: the active public key, then every previous public key. */
  jwks(): { keys: PublicJwk[] } {
    return { keys: [this.activePublic, ...this.previous] };
  }

  /** Compact JWS with `kid` forced to the active key. */
  sign(claims: Record<string, unknown>): string {
    const header = { alg: this.algorithm, kid: this.kid, typ: 'JWT' };
    const input = `${encode(header)}.${encode(claims)}`;
    const signature = sign(
      this.algorithm === 'RS256' ? 'sha256' : null,
      Buffer.from(input),
      this.privateKey,
    );
    return `${input}.${signature.toString('base64url')}`;
  }

  private static importPrivate(jwk: Record<string, unknown>): KeyObject {
    try {
      return createPrivateKey({ key: jwk as never, format: 'jwk' });
    } catch {
      throw new SigningKeyError('Active private JWK is malformed or its public key does not match');
    }
  }

  private static checkAkp(jwk: Record<string, unknown>, requirePrivate: boolean): void {
    if (jwk.kty !== 'AKP') throw new SigningKeyError('ML-DSA-65 requires an AKP JWK');
    if (jwk.alg !== 'ML-DSA-65') throw new SigningKeyError('AKP JWK must use alg ML-DSA-65');
    if (decodedLength(jwk.pub) !== AKP_PUBLIC_BYTES) {
      throw new SigningKeyError('AKP public key must be 1952 bytes');
    }
    if (requirePrivate && decodedLength(jwk.priv) !== AKP_SEED_BYTES) {
      throw new SigningKeyError('Active JWK must contain a 32-byte private seed');
    }
  }

  private static parsePrevious(raw: string): PublicJwk[] {
    if (!raw.trim()) return [];
    const set = SigningKeys.parseObject(raw, 'Previous public JWK set');
    if (!Array.isArray(set.keys)) {
      throw new SigningKeyError('Previous public JWK set must contain a keys array');
    }
    return set.keys.map((entry) => SigningKeys.previousKey(entry));
  }

  private static previousKey(entry: unknown): PublicJwk {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new SigningKeyError('Previous public JWK must be an object');
    }
    const jwk = entry as Record<string, unknown>;
    if (jwk.kty === 'RSA') {
      if (RSA_PRIVATE.some((field) => field in jwk)) {
        throw new SigningKeyError('Previous public JWK must not contain private material');
      }
      const { kty, n, e, kid, alg, use } = jwk;
      return strip({ kty: kty as string, n, e, kid, alg, use: use ?? 'sig' });
    }
    if (jwk.kty === 'AKP') {
      if ('priv' in jwk) {
        throw new SigningKeyError('Previous public JWK must not contain private material');
      }
      SigningKeys.checkAkp(jwk, false);
      const { kty, pub, kid, alg } = jwk;
      return strip({ kty: kty as string, alg, kid, pub, use: 'sig', key_ops: ['verify'] });
    }
    throw new SigningKeyError('Previous public JWK must be RSA or AKP');
  }

  private static publicOf(key: KeyObject, kid: string, algorithm: SigningAlgorithm): PublicJwk {
    const exported = key.export({ format: 'jwk' }) as Record<string, unknown>;
    if (algorithm === 'RS256') {
      return { kty: 'RSA', e: exported.e, n: exported.n, kid, alg: 'RS256', use: 'sig' };
    }
    return {
      kty: 'AKP',
      alg: 'ML-DSA-65',
      kid,
      pub: exported.pub,
      use: 'sig',
      key_ops: ['verify'],
    };
  }

  private static parseObject(raw: string, label: string): Record<string, unknown> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new SigningKeyError(`${label} is not valid JSON`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new SigningKeyError(`${label} must be a JSON object`);
    }
    return parsed as Record<string, unknown>;
  }
}

/** Verifies a compact JWS against a JWK set. Returns the claims or throws. */
export function verifyJws(
  compact: string,
  keys: readonly Record<string, unknown>[],
  algorithms: readonly SigningAlgorithm[],
): Record<string, unknown> {
  const parts = compact.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const [encodedHeader, encodedClaims, encodedSignature] = parts as [string, string, string];
  const header = decodeJson(encodedHeader);
  const alg = header.alg as SigningAlgorithm;
  if (!algorithms.includes(alg)) throw new Error('Unexpected signing algorithm');
  const candidates = keys.filter(
    (key) => (header.kid === undefined || key.kid === header.kid) && kty(alg) === key.kty,
  );
  const data = Buffer.from(`${encodedHeader}.${encodedClaims}`);
  const signature = Buffer.from(encodedSignature, 'base64url');
  for (const key of candidates) {
    const publicKey = importPublic(key);
    if (publicKey && verify(alg === 'RS256' ? 'sha256' : null, data, publicKey, signature)) {
      return decodeJson(encodedClaims);
    }
  }
  throw new Error('Invalid token signature');
}

function importPublic(key: Record<string, unknown>): KeyObject | undefined {
  try {
    const material =
      key.kty === 'RSA'
        ? { kty: 'RSA', n: key.n, e: key.e }
        : { kty: 'AKP', alg: key.alg, pub: key.pub };
    return createPublicKey({ key: material as never, format: 'jwk' });
  } catch {
    return undefined;
  }
}

function kty(alg: SigningAlgorithm): string {
  return alg === 'RS256' ? 'RSA' : 'AKP';
}

function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function decodeJson(segment: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  if (typeof parsed !== 'object' || parsed === null) throw new Error('Malformed token');
  return parsed as Record<string, unknown>;
}

function decodedLength(value: unknown): number {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return -1;
  return Buffer.from(value, 'base64url').length;
}

function strip(value: Record<string, unknown> & { kty: string }): PublicJwk {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== undefined),
  ) as PublicJwk;
}
