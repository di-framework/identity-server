import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { useContainer } from '@di-framework/core/container';
import { IdentityModule } from '@di-framework/identity/src/composition.ts';
import { SIGNING_KEYS } from '@di-framework/identity/src/shared/domain/tokens.ts';
import { applyMigrations } from '@di-framework/identity-migrations';
import { systemClock } from '../../client/src/domain/clock.ts';
import { createStore } from '../../client/src/domain/model.ts';
import { routeRequest } from './serve.ts';

const settings = IdentityModule.settings();
// Fail closed: a missing or invalid AUTH_ACTIVE_PRIVATE_JWK stops startup.
useContainer().resolve(SIGNING_KEYS);
const database = await IdentityModule.connectFromConfig();
const embeddedRoot = join(import.meta.dir, 'embedded');
await applyMigrations(
  database,
  Bun.isStandaloneExecutable ? join(embeddedRoot, 'migrations') : undefined,
);

const assets = Bun.isStandaloneExecutable
  ? new URL('embedded/assets/', pathToFileURL(`${import.meta.dir}/`))
  : await buildClientAssets();

const store = createStore(systemClock());
const server = Bun.serve({
  hostname: settings.server.host,
  port: settings.server.port,
  fetch: (request) => routeRequest(request, store, assets),
});

console.log(
  `identity listening on ${settings.server.host}:${server.port}, public origin ${settings.publicOrigin}`,
);

async function buildClientAssets(): Promise<URL> {
  const dist = new URL('../../client/dist/', import.meta.url);
  const built = await Bun.build({
    entrypoints: [new URL('../../client/src/main.tsx', import.meta.url).pathname],
    outdir: dist.pathname,
    target: 'browser',
  });
  if (!built.success) {
    console.error(built.logs);
    process.exit(1);
  }
  return dist;
}
