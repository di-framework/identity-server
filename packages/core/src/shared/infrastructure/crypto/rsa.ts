import { createHash, timingSafeEqual } from 'node:crypto';
import { decodeBase64Url } from './base64url.ts';

const DIGEST_INFO = Uint8Array.from([
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
  0x00, 0x04, 0x20,
]);

export interface RsaPrivateJwk {
  n: string;
  e: string;
  d: string;
}

export interface RsaPublicJwk {
  n: string;
  e: string;
}

/** RSASSA-PKCS1-v1_5 with SHA-256. Works where `node:crypto` `sign` is unavailable. */
export function rs256Sign(message: Uint8Array, jwk: RsaPrivateJwk): Uint8Array {
  const modulus = decode(jwk.n);
  const encoded = pkcs1(sha256(message), modulus.length);
  const signature = modPow(os2ip(encoded), os2ip(decode(jwk.d)), os2ip(modulus));
  return i2osp(signature, modulus.length);
}

export function rs256Verify(
  message: Uint8Array,
  signature: Uint8Array,
  jwk: RsaPublicJwk,
): boolean {
  try {
    const modulus = decode(jwk.n);
    if (signature.length !== modulus.length) return false;
    const encoded = i2osp(
      modPow(os2ip(signature), os2ip(decode(jwk.e)), os2ip(modulus)),
      modulus.length,
    );
    const expected = pkcs1(sha256(message), modulus.length);
    return encoded.length === expected.length && timingSafeEqual(encoded, expected);
  } catch {
    return false;
  }
}

function sha256(message: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(message).digest());
}

function pkcs1(hash: Uint8Array, modulusLength: number): Uint8Array {
  const padding = modulusLength - DIGEST_INFO.length - hash.length - 3;
  if (padding < 8) throw new Error('RSA modulus is too short');
  const encoded = new Uint8Array(modulusLength);
  encoded[0] = 0x00;
  encoded[1] = 0x01;
  encoded.fill(0xff, 2, 2 + padding);
  encoded[2 + padding] = 0x00;
  encoded.set(DIGEST_INFO, 3 + padding);
  encoded.set(hash, 3 + padding + DIGEST_INFO.length);
  return encoded;
}

function decode(value: string): Uint8Array {
  const bytes = decodeBase64Url(value);
  if (bytes.length === 0) throw new Error('empty RSA component');
  return bytes;
}

function os2ip(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function i2osp(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new Error('negative RSA integer');
  const out = new Uint8Array(length);
  let current = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    out[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  if (current !== 0n) throw new Error('RSA integer does not fit');
  return out;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new Error('invalid RSA modulus');
  let result = 1n;
  let factor = base % modulus;
  let bits = exponent;
  while (bits > 0n) {
    if (bits & 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    bits >>= 1n;
  }
  return result;
}
