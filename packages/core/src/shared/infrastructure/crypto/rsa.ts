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
  /** CRT parameters; signing uses them when all five are present. */
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;
}

export interface RsaPublicJwk {
  n: string;
  e: string;
}

type NativeCrypto = Pick<typeof import('node:crypto'), 'createPrivateKey' | 'sign'>;

/**
 * An RS256 signer for one key. Bun and Node sign with their native RSA (OpenSSL), which is
 * constant-time. The wasmCloud guest has no native RSA, so it falls back to `rs256Sign`.
 * `node:crypto` is looked up at runtime because the guest's shim does not export it.
 */
export function rs256Signer(
  jwk: RsaPrivateJwk,
  native: NativeCrypto | null = nativeCrypto(),
): (message: Uint8Array) => Uint8Array {
  if (native) {
    try {
      const key = native.createPrivateKey({ key: { kty: 'RSA', ...jwk } as never, format: 'jwk' });
      return (message) => new Uint8Array(native.sign('sha256', message, key));
    } catch {
      // A JWK the native importer refuses (no CRT parameters, for one) signs portably.
    }
  }
  return (message) => rs256Sign(message, jwk);
}

function nativeCrypto(): NativeCrypto | null {
  const runtime = globalThis as { process?: { getBuiltinModule?: (id: string) => unknown } };
  const crypto = runtime.process?.getBuiltinModule?.('node:crypto') as Partial<NativeCrypto>;
  const usable =
    typeof crypto?.createPrivateKey === 'function' && typeof crypto.sign === 'function';
  return usable ? (crypto as NativeCrypto) : null;
}

/**
 * RSASSA-PKCS1-v1_5 with SHA-256 on BigInt, for runtimes without native RSA.
 *
 * BigInt arithmetic is not constant-time, so the private operation runs on a blinded input
 * (m·rᵉ, then ·r⁻¹), which decorrelates its timing from the message. It uses CRT when the
 * JWK carries p, q, dp, dq and qi, and checks the result against the public exponent so a
 * faulty CRT step never releases a signature.
 */
export function rs256Sign(message: Uint8Array, jwk: RsaPrivateJwk): Uint8Array {
  const length = decode(jwk.n).length;
  const n = os2ip(decode(jwk.n));
  const e = os2ip(decode(jwk.e));
  const m = os2ip(pkcs1(sha256(message), length));
  const r = blindingFactor(n, length);
  const blinded = (m * modPow(r, e, n)) % n;
  const signature = (privateOperation(blinded, jwk, n) * modInverse(r, n)) % n;
  if (modPow(signature, e, n) !== m) throw new Error('RSA signature failed its check');
  return i2osp(signature, length);
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

function privateOperation(c: bigint, jwk: RsaPrivateJwk, n: bigint): bigint {
  const { p, q, dp, dq, qi } = jwk;
  if (!(p && q && dp && dq && qi)) return modPow(c, os2ip(decode(jwk.d)), n);
  const [P, Q] = [os2ip(decode(p)), os2ip(decode(q))];
  const m1 = modPow(c % P, os2ip(decode(dp)), P);
  const m2 = modPow(c % Q, os2ip(decode(dq)), Q);
  const h = (((os2ip(decode(qi)) * (m1 - m2)) % P) + P) % P;
  return m2 + h * Q;
}

/** A random r in [2, n) coprime to n. */
function blindingFactor(n: bigint, length: number): bigint {
  const bytes = new Uint8Array(length);
  let r: bigint;
  do {
    crypto.getRandomValues(bytes);
    r = os2ip(bytes) % n;
  } while (r < 2n || gcd(r, n) !== 1n);
  return r;
}

function gcd(a: bigint, b: bigint): bigint {
  let [x, y] = [a, b];
  while (y !== 0n) [x, y] = [y, x % y];
  return x;
}

function modInverse(a: bigint, n: bigint): bigint {
  let [oldR, r] = [a % n, n];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  return ((oldS % n) + n) % n;
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
