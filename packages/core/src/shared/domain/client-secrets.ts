import { Component, Container } from '@di-framework/core/decorators';
import { Hashing } from '../infrastructure/crypto/hashing.ts';
import type { IdentitySettings } from '../infrastructure/identity-settings.ts';
import { IDENTITY_SETTINGS } from './tokens.ts';

/**
 * Client secrets and one-way digests. Idempotent secrets are derived exactly as the auth
 * server's `ApiController.idempotentClientSecret`: the HMAC key is
 * `SHA-256("gsio-oauth-idempotency-v1\0" + active private JWK)`, so only a holder of the
 * signing key can recompute a secret from an `Idempotency-Key`.
 */
@Container()
export class ClientSecrets {
  constructor(@Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings) {}

  sign(idempotencyKey: string | undefined, operation: string): string {
    if (!idempotencyKey) return Hashing.token();
    if (!this.settings.jwk.activePrivate.trim()) {
      throw new Error('AUTH_ACTIVE_PRIVATE_JWK is required to derive idempotent client secrets');
    }
    const key = Hashing.sha256(`gsio-oauth-idempotency-v1\0${this.settings.jwk.activePrivate}`);
    return Hashing.hmacSha256Base64Url(key, `${idempotencyKey}\0${operation}`);
  }

  /** SHA-256 hex digest for tokens, sessions, and subjects. Not for secrets at rest. */
  hash(value: string): string {
    return Hashing.sha256Hex(value);
  }

  hint(value: string): string {
    return this.hash(value).slice(0, 16);
  }
}
