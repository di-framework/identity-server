import { useContainer } from '@di-framework/core/container';
import { argon2 } from '@di-framework/wasm-pqc-subtle/component';
import {
  componentPasswordApi,
  registerPasswordApi,
} from '../../../packages/core/src/shared/infrastructure/crypto/passwords.ts';
import { IdentityConfig, IdentityDatabase } from './bindings.ts';
import { assetFiles, pageShell } from './embedded-assets.ts';
import { handle } from './runtime.ts';

// Argon2id from the composed `pqc-subtle:crypto` component: native Wasm instead of the
// pure JavaScript hasher, which takes about 30 seconds per hash on QuickJS.
registerPasswordApi(componentPasswordApi(argon2));

const database = useContainer().resolve(IdentityDatabase);
const config = useContainer().resolve(IdentityConfig);
const assets = new Map(
  Object.entries(assetFiles).map(([name, encoded]) => [name, Buffer.from(encoded, 'base64')]),
);

export default function fetch(request: Request): Promise<Response> {
  return handle(request, { database, config, assets, shell: pageShell });
}
