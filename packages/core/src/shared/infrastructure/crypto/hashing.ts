import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

/** One-way digests and random values. Tokens are stored as SHA-256 hex, never in plain form. */
export class Hashing {
  static sha256Hex(value: string): string {
    return createHash('sha256').update(value, 'utf8').digest('hex');
  }

  static sha256(value: string | Uint8Array): Buffer {
    return createHash('sha256').update(value).digest();
  }

  static hmacSha256Base64Url(key: Uint8Array, value: string): string {
    return createHmac('sha256', key).update(value, 'utf8').digest('base64url');
  }

  /** 32 random bytes as unpadded base64url: 43 characters. */
  static token(bytes = 32): string {
    return randomBytes(bytes).toString('base64url');
  }

  /** `cli_` plus the first 16 hex characters of a dashless random UUID. */
  static clientId(): string {
    return `cli_${randomUUID().replaceAll('-', '').slice(0, 16)}`;
  }

  /** S256 PKCE challenge for a verifier. */
  static pkceChallenge(verifier: string): string {
    return createHash('sha256').update(verifier, 'ascii').digest('base64url');
  }

  static equal(left: string, right: string): boolean {
    const a = Buffer.from(left);
    const b = Buffer.from(right);
    return a.length === b.length && timingSafeEqual(a, b);
  }
}

/** 43-character base64url token shape used by passwordless, unlink, and link flows. */
export const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
