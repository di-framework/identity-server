import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { BootstrapReconciler } from '../../../packages/core/src/bootstrap/application/bootstrap-reconciler.ts';
import { Readiness } from '../../../packages/core/src/bootstrap/application/readiness.ts';
import { IdentityModule } from '../../../packages/core/src/composition.ts';
import { NotificationWorker } from '../../../packages/core/src/notifications/application/security-notifications.ts';
import { SIGNING_KEYS } from '../../../packages/core/src/shared/domain/tokens.ts';
import { Hashing } from '../../../packages/core/src/shared/infrastructure/crypto/hashing.ts';
import type { IdentitySettings } from '../../../packages/core/src/shared/infrastructure/identity-settings.ts';
import { ControlPlaneRouter } from '../../api/src/control-plane.ts';
import { OperationsEndpoints } from '../../api/src/operations/health.ts';
import type { AssetSource } from '../../server/src/serve.ts';
import { routeRequest } from '../../server/src/serve.ts';
import type { IdentityDatabase } from './bindings.ts';
import { openGuestDatabase, sharesTransaction } from './database.ts';
import { ensureSchema, resetSchema } from './migrations.ts';
import type { ConfigStore } from './settings.ts';
import { loadGuestSettings } from './settings.ts';

const BOOTSTRAP_FINGERPRINT = 'bootstrap_fingerprint';

export interface GuestRuntime {
  database: IdentityDatabase;
  config: ConfigStore;
  assets: AssetSource;
  shell: string;
}

let ready: Promise<void> | undefined;

export function resetGuest(): void {
  ready = undefined;
  resetSchema();
}

/** Schema, signing keys, bootstrap, then the same routes as the Bun server. */
export async function handle(request: Request, runtime: GuestRuntime): Promise<Response> {
  try {
    ready ??= boot(runtime).catch((error: unknown) => {
      ready = undefined;
      throw error;
    });
    await ready;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'failed';
    return Response.json({ ok: false, error: message }, { status: 503 });
  }
  const response = await routeRequest(request, runtime.assets, runtime.shell);
  await drain();
  return response;
}

async function boot(runtime: GuestRuntime): Promise<void> {
  await ensureSchema(runtime.database);
  const database = openGuestDatabase(runtime.database);
  const settings = await loadGuestSettings(runtime.config, database);
  IdentityModule.configure(settings);
  IdentityModule.connect(database);
  // Singletons built by other tests keep the settings they were constructed with.
  // Re-register the readiness chain so this boot's settings and reconciler are the ones served.
  const container = useContainer();
  container.register(BootstrapReconciler);
  container.resolve(SIGNING_KEYS);
  const reconciler = container.resolve(BootstrapReconciler);
  const fingerprint = bootstrapFingerprint(settings);
  if ((await storedFingerprint(database)) === fingerprint) reconciler.markComplete();
  else {
    await reconciler.reconcile();
    await storeFingerprint(database, fingerprint);
  }
  container.register(Readiness);
  container.register(OperationsEndpoints);
  container.register(ControlPlaneRouter);
  if (!(await sharesTransaction(database))) {
    throw new Error('postgres queries do not share a transaction');
  }
}

/**
 * Every input `BootstrapReconciler.reconcile` applies: people, organization, client IDs,
 * secrets, and redirect URIs. A change to any of them must run reconcile again.
 */
function bootstrapFingerprint(settings: IdentitySettings): string {
  return Hashing.sha256Hex(
    JSON.stringify({ bootstrap: settings.bootstrap, clients: settings.clients }),
  );
}

async function storedFingerprint(database: SqlDatabase): Promise<string> {
  const row = await database.first<{ value: unknown }>(
    'SELECT value FROM identity_runtime_secret WHERE name = ?',
    [BOOTSTRAP_FINGERPRINT],
  );
  return row?.value == null ? '' : String(row.value);
}

async function storeFingerprint(database: SqlDatabase, fingerprint: string): Promise<void> {
  await database.run(
    `INSERT INTO identity_runtime_secret (name, value) VALUES (?, ?)
     ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value`,
    [BOOTSTRAP_FINGERPRINT, fingerprint],
  );
}

async function drain(): Promise<void> {
  const settings = IdentityModule.settings();
  if (!settings.notifications.schedulerEnabled) return;
  try {
    await useContainer().resolve(NotificationWorker).runOnce();
  } catch {
    // The next request retries anything still due.
  }
}
