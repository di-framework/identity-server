import { Container } from '@di-framework/core/decorators';
import { argon2idPhc, argon2idVerify } from './argon2id.ts';

export interface PasswordApi {
  hash(
    plain: string,
    options: { algorithm: 'argon2id'; memoryCost: number; timeCost: number },
  ): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;
}

/** The `argon2` interface of `pqc-subtle:crypto@0.1.0`, as a composed component presents it. */
export interface ComponentArgon2 {
  hash(
    password: Uint8Array,
    params: {
      memoryKib: number;
      iterations: number;
      parallelism: number;
      outputLength: number | null;
    } | null,
  ): string;
  verify(password: Uint8Array, phc: string): boolean;
}

/**
 * Argon2id with Spring Security's `defaultsForSpringSecurity_v5_8` parameters
 * (memory 16384 KiB, 2 iterations, parallelism 1). The PHC string is the same shape
 * the auth server stores, so hashes move between the two systems unchanged.
 * Bun uses its native hasher. The guest registers the composed component's hasher at
 * startup ({@link registerPasswordApi}); without either, the pure JavaScript
 * implementation runs, at about 30 seconds per hash on QuickJS.
 */
@Container()
export class PasswordHasher {
  hash(plain: string): Promise<string> {
    return hashPassword(plain, resolvePasswordApi());
  }

  async verify(plain: string, hash: string | null | undefined): Promise<boolean> {
    if (!hash?.startsWith('$argon2')) return false;
    return verifyPassword(plain, hash, resolvePasswordApi());
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

/**
 * A {@link PasswordApi} over the composed Argon2id component. Parameters are passed
 * explicitly so the PHC string matches the Bun and Spring hashers; verify reads them from
 * the string. The component throws on a malformed PHC string, which `verifyPassword` maps
 * to `false`.
 */
export function componentPasswordApi(argon2: ComponentArgon2): PasswordApi {
  const encoder = new TextEncoder();
  return {
    async hash(plain, options) {
      return argon2.hash(encoder.encode(plain), {
        memoryKib: options.memoryCost,
        iterations: options.timeCost,
        parallelism: 1,
        outputLength: null,
      });
    },
    async verify(plain, hash) {
      return argon2.verify(encoder.encode(plain), hash);
    },
  };
}

let registered: PasswordApi | undefined;

/** Installs the hasher a runtime without `Bun.password` should use; `undefined` clears it. */
export function registerPasswordApi(api: PasswordApi | undefined): void {
  registered = api;
}

type Runtime = { Bun?: { password?: PasswordApi } };

/** `Bun.password` when it exists, else the registered hasher, else nothing (pure JavaScript). */
export function resolvePasswordApi(
  runtime: Runtime = globalThis as Runtime,
): PasswordApi | undefined {
  return runtime.Bun?.password ?? registered;
}
