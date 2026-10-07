import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { useContainer } from '@di-framework/core/container';
import { IdentityModule } from '@di-framework/identity/src/composition.ts';
import { SessionService } from '@di-framework/identity/src/sessions/application/session-service.ts';
import { applyMigrations } from '@di-framework/identity-migrations';
import { routeRequest } from './serve.ts';

const settings = IdentityModule.settings();

try {
  const database = await IdentityModule.connectFromConfig();
  const embeddedRoot = join(import.meta.dir, 'embedded');
  await applyMigrations(
    database,
    Bun.isStandaloneExecutable ? join(embeddedRoot, 'migrations') : undefined,
  );
  // Fail closed, as the auth server does: invalid signing keys or bootstrap settings stop startup.
  await IdentityModule.prepare();
} catch (error) {
  console.error(
    `identity startup failed: ${error instanceof Error ? error.message : 'unknown error'}`,
  );
  process.exit(1);
}

const worker = IdentityModule.startNotificationWorker((error) =>
  console.error(
    `notification delivery failed: ${error instanceof Error ? error.message : 'unknown'}`,
  ),
);

const sessionService = useContainer().resolve(SessionService);
const purgeTimer = setInterval(
  async () => {
    try {
      await sessionService.purgeExpired();
    } catch (error) {
      console.error(`session purge failed: ${error instanceof Error ? error.message : 'unknown'}`);
    }
  },
  15 * 60 * 1000,
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

const shutdown = (signal: string) => {
  console.log(`received ${signal}, shutting down gracefully...`);
  worker?.stop();
  clearInterval(purgeTimer);
  server.stop(true);
  process.exit(0);
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

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
