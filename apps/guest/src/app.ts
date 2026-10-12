import * as pglite from 'di-framework:pglite/database@0.2.0';
import { useContainer } from '@di-framework/core/container';
import type { WasmPgliteModule } from '@di-framework/pglite-component';
import { argon2 } from '@di-framework/wasm-pqc-subtle/component';
import {
  componentPasswordApi,
  registerPasswordApi,
} from '../../../packages/core/src/shared/infrastructure/crypto/passwords.ts';
import { IdentityConfig } from './bindings.ts';
import { type GuestEnv, pgliteDatabase } from './database.ts';
import { assetFiles, pageShell } from './embedded-assets.ts';
import { handle } from './runtime.ts';

// Argon2id from the composed `pqc-subtle:crypto` component: native Wasm instead of the
// pure JavaScript hasher, which takes about 30 seconds per hash on QuickJS.
registerPasswordApi(componentPasswordApi(argon2));

/** Read at request time; at pre-initialization the WASI environment is empty. */
const env = (): GuestEnv => (typeof process === 'undefined' ? {} : process.env);
// The pglite provider is composed into this component by `di-framework platform build`
// (`pglite` in di-framework.config.json); the static import keeps its WIT import in the world.
const database = pgliteDatabase(pglite as WasmPgliteModule, env);
const config = useContainer().resolve(IdentityConfig);
const assets = new Map(
  Object.entries(assetFiles).map(([name, encoded]) => [name, Buffer.from(encoded, 'base64')]),
);

export default function fetch(request: Request): Promise<Response> {
  return handle(request, { database, config, env, assets, shell: pageShell });
}
