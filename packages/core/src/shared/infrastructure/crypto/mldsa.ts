import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

/** ML-DSA-65 from an RFC 9964 32-byte seed. The public key is the FIPS 204 encoding. */
export function mlDsaKeygen(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const keys = ml_dsa65.keygen(seed);
  return { secretKey: keys.secretKey, publicKey: keys.publicKey };
}

export function mlDsaSign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ml_dsa65.sign(message, secretKey);
}

export function mlDsaVerify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
