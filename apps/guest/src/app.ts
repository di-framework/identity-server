import { useContainer } from '@di-framework/core/container';
import { IdentityConfig, IdentityDatabase } from './bindings.ts';
import { assetFiles, pageShell } from './embedded-assets.ts';
import { handle } from './runtime.ts';

const database = useContainer().resolve(IdentityDatabase);
const config = useContainer().resolve(IdentityConfig);
const assets = new Map(
  Object.entries(assetFiles).map(([name, encoded]) => [name, Buffer.from(encoded, 'base64')]),
);

export default function fetch(request: Request): Promise<Response> {
  return handle(request, { database, config, assets, shell: pageShell });
}
