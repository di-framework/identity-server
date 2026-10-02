import { createHash, createHmac, randomBytes } from 'node:crypto';
import { Container } from '@di-framework/core/decorators';

/** Client secrets and identity-link digests. Plaintext secrets are not stored. */
@Container()
export class ClientSecrets {
  sign(idempotencyKey: string | undefined, operation: string): string {
    if (!idempotencyKey) return randomBytes(32).toString('base64url');
    const key = createHash('sha256').update('difi-oauth-idempotency-v1').digest();
    return createHmac('sha256', key).update(`${idempotencyKey}\0${operation}`).digest('base64url');
  }

  hash(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  hint(value: string): string {
    return this.hash(value).slice(0, 16);
  }
}
