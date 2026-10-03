import { Container } from '@di-framework/core/decorators';

/**
 * Argon2id with Spring Security's `defaultsForSpringSecurity_v5_8` parameters
 * (memory 16384 KiB, 2 iterations, parallelism 1). The PHC string is the same shape
 * the auth server stores, so hashes move between the two systems unchanged.
 */
@Container()
export class PasswordHasher {
  hash(plain: string): Promise<string> {
    return Bun.password.hash(plain, { algorithm: 'argon2id', memoryCost: 16384, timeCost: 2 });
  }

  async verify(plain: string, hash: string | null | undefined): Promise<boolean> {
    if (!hash?.startsWith('$argon2')) return false;
    try {
      return await Bun.password.verify(plain, hash);
    } catch {
      return false;
    }
  }
}
