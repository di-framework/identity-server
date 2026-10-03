/**
 * Prints a new private signing JWK for `AUTH_ACTIVE_PRIVATE_JWK`.
 *
 *   bun scripts/generate-jwk.ts            # RS256 (RSA 2048)
 *   bun scripts/generate-jwk.ts ML-DSA-65  # RFC 9964 AKP seed form
 *
 * The output is secret material: store it in the secret manager, never in a file in Git.
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';

const algorithm = process.argv[2] ?? 'RS256';
const kid = randomBytes(12).toString('hex');
if (algorithm === 'RS256') {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  console.log(
    JSON.stringify({
      ...(privateKey.export({ format: 'jwk' }) as object),
      kid,
      alg: 'RS256',
      use: 'sig',
    }),
  );
} else if (algorithm === 'ML-DSA-65') {
  const { privateKey } = generateKeyPairSync('ml-dsa-65' as never);
  console.log(JSON.stringify({ ...(privateKey.export({ format: 'jwk' }) as object), kid }));
} else {
  console.error('Usage: bun scripts/generate-jwk.ts [RS256|ML-DSA-65]');
  process.exit(1);
}
