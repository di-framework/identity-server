import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { IdentityModule } from '@di-framework/identity/src/composition.ts';
import { applyMigrations } from '@di-framework/identity-migrations';
import { systemClock } from '../../client/src/domain/clock.ts';
import { createStore } from '../../client/src/domain/model.ts';
import { routeRequest } from './serve.ts';

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
const port = Number(process.env.PORT ?? 4180);
const server = Bun.serve({
  // TODO: This should be configurable via @di-framework/config
  hostname: '0.0.0.0',
  port,
  fetch: (request) => routeRequest(request, store, assets),
});

// TODO: This should be configurable via @di-framework/config
console.log(`identity http://0.0.0.0:${server.port}`);

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
