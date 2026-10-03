import { Container } from '@di-framework/core/decorators';
import { argon2idPhc, argon2idVerify } from './argon2id.ts';

interface PasswordApi {
  hash(
    plain: string,
    options: { algorithm: 'argon2id'; memoryCost: number; timeCost: number },
  ): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;
}

/**
 * Argon2id with Spring Security's `defaultsForSpringSecurity_v5_8` parameters
 * (memory 16384 KiB, 2 iterations, parallelism 1). The PHC string is the same shape
 * the auth server stores, so hashes move between the two systems unchanged.
 * Bun uses its native hasher. The guest uses the pure JavaScript implementation.
 */
@Container()
export class PasswordHasher {
  hash(plain: string): Promise<string> {
    return hashPassword(plain, bunPassword());
  }

  async verify(plain: string, hash: string | null | undefined): Promise<boolean> {
    if (!hash?.startsWith('$argon2')) return false;
    return verifyPassword(plain, hash, bunPassword());
  }
}

export function hashPassword(plain: string, api: PasswordApi | undefined): Promise<string> {
  if (api) return api.hash(plain, { algorithm: 'argon2id', memoryCost: 16384, timeCost: 2 });
  return Promise.resolve(argon2idPhc(plain));
}

export async function verifyPassword(
  plain: string,
  hash: string,
  api: PasswordApi | undefined,
): Promise<boolean> {
  try {
    if (api) return await api.verify(plain, hash);
    return argon2idVerify(plain, hash);
  } catch {
    return false;
  }
}

function bunPassword(): PasswordApi | undefined {
  const runtime = globalThis as { Bun?: { password?: PasswordApi } };
  return runtime.Bun?.password;
}
