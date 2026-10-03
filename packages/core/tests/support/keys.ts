import { generateKeyPairSync } from 'node:crypto';

/** Fresh RSA private JWK with a kid. Test material only. */
export function rsaPrivateJwk(kid = 'test-rsa'): Record<string, unknown> {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { ...(privateKey.export({ format: 'jwk' }) as Record<string, unknown>), kid };
}

/** Fresh ML-DSA-65 AKP private JWK (RFC 9964 seed form) with a kid. */
export function akpPrivateJwk(kid = 'test-akp'): Record<string, unknown> {
  const { privateKey } = generateKeyPairSync('ml-dsa-65' as never);
  return { ...(privateKey.export({ format: 'jwk' }) as Record<string, unknown>), kid };
}

/** Public half of a private JWK as JWKS publishes it. */
export function publicOf(jwk: Record<string, unknown>): Record<string, unknown> {
  if (jwk.kty === 'RSA') return { kty: 'RSA', n: jwk.n, e: jwk.e, kid: jwk.kid };
  return { kty: 'AKP', alg: jwk.alg, pub: jwk.pub, kid: jwk.kid };
}
