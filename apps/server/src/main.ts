import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { IdentityModule } from '@di-framework/identity/src/composition.ts';
import { applyMigrations } from '@di-framework/identity-migrations';
import { routeRequest } from './serve.ts';

const settings = IdentityModule.settings();
const database = await IdentityModule.connectFromConfig();
const embeddedRoot = join(import.meta.dir, 'embedded');
await applyMigrations(
  database,
  Bun.isStandaloneExecutable ? join(embeddedRoot, 'migrations') : undefined,
);

// Fail closed, as the auth server does: invalid signing keys or bootstrap settings stop startup.
try {
  await IdentityModule.prepare();
} catch (error) {
  console.error(
    `identity startup failed: ${error instanceof Error ? error.message : 'unknown error'}`,
  );
  process.exit(1);
}

IdentityModule.startNotificationWorker((error) =>
  console.error(
    `notification delivery failed: ${error instanceof Error ? error.message : 'unknown'}`,
  ),
);

const assets = Bun.isStandaloneExecutable
  ? new URL('embedded/assets/', pathToFileURL(`${import.meta.dir}/`))
  : await buildClientAssets();

const server = Bun.serve({
  hostname: settings.server.host,
  port: settings.server.port,
  fetch: (request) => routeRequest(request, assets),
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
