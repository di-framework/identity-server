import { createWasmPgliteDatabase, type WasmPgliteModule } from '@di-framework/pglite-component';
import type { SqlDatabase } from '@di-framework/repo';

/** Environment variable cli-plugin-platform sets from `pglite.dataDir` in di-framework.config.json. */
export const DATABASE_ROOT_ENV = 'DI_PGLITE_DATA_DIR';
/** The provider's default root, inside the workload's persistent `/data` mount. */
export const DEFAULT_DATABASE_ROOT = '/data/pglite';

export type GuestEnv = Readonly<Record<string, string | undefined>>;

export function databaseRoot(env: GuestEnv): string {
  return env[DATABASE_ROOT_ENV]?.trim() || DEFAULT_DATABASE_ROOT;
}

/**
 * The identity database: embedded PostgreSQL 17 from the pglite provider component, which
 * `di-framework platform build` composes into this guest. The provider allows one connection per
 * component instance, so the instance opens it once, on its first request (not at
 * pre-initialization, where the WASI filesystem is not available), and shares that handle.
 * A failed open is retried by the next request.
 */
export function pgliteDatabase(
  module: WasmPgliteModule,
  env: () => GuestEnv,
): () => Promise<SqlDatabase> {
  let opening: Promise<SqlDatabase> | undefined;
  return () => {
    opening ??= createWasmPgliteDatabase(databaseRoot(env()), { module }).catch(
      (error: unknown) => {
        opening = undefined;
        throw error;
      },
    );
    return opening;
  };
}
