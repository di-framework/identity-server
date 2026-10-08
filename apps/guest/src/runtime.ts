import { openPostgresDatabase } from '@di-framework/bindings/postgres';
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
import { ensureSchema, resetSchema } from './migrations.ts';
import type { ConfigStore } from './settings.ts';
import { loadGuestSettings } from './settings.ts';

const BOOTSTRAP_FINGERPRINT = 'bootstrap_fingerprint';
const CLIENT_FINGERPRINTS = 'bootstrap_client_fingerprints';
const BOOTSTRAP_LEASE = 'bootstrap_lease';
/**
 * How long one realm may hold the reconcile lease. A cold reconcile hashes up to three client
 * secrets at about 30 seconds each on QuickJS; the lease outlasts that with room for a busy host.
 * A realm the host aborts mid-reconcile (its client disconnected) leaves the lease to expire, and
 * every realm answers 503 until then.
 */
const LEASE_MS = 3 * 60_000;

/** A request that arrived while another realm holds the reconcile lease. */
export class BootstrapBusyError extends Error {
  constructor(until: string) {
    super(`bootstrap in progress until ${until}`);
    this.name = 'BootstrapBusyError';
  }
}

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
    const headers = error instanceof BootstrapBusyError ? { 'retry-after': '5' } : {};
    return Response.json({ ok: false, error: message }, { status: 503, headers });
  }
  const response = await routeRequest(request, runtime.assets, runtime.shell);
  await drain();
  return response;
}

async function boot(runtime: GuestRuntime): Promise<void> {
  await ensureSchema(runtime.database);
  const database = openPostgresDatabase(runtime.database);
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
  if ((await storedValue(database, BOOTSTRAP_FINGERPRINT)) === fingerprint) {
    reconciler.markComplete();
  } else {
    const current = clientFingerprints(settings);
    const stored = parseFingerprints(await storedValue(database, CLIENT_FINGERPRINTS));
    const settledClients = new Set(
      Object.keys(current).filter((id) => stored[id] !== undefined && stored[id] === current[id]),
    );
    await withBootstrapLease(database, async () => {
      await reconciler.reconcile({ settledClients });
      // Client fingerprints first: a realm that dies between the two stores reconciles again
      // with every client settled, which is cheap.
      await storeValue(database, CLIENT_FINGERPRINTS, JSON.stringify(current));
      await storeValue(database, BOOTSTRAP_FINGERPRINT, fingerprint);
    });
  }
  container.register(Readiness);
  container.register(OperationsEndpoints);
  container.register(ControlPlaneRouter);
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

/**
 * One fingerprint per confidential client over everything `ensureClient` writes for it. A client
 * whose fingerprint is unchanged is passed to reconcile as settled, so adding the CLI client or
 * rotating one secret hashes only what changed instead of all three secrets.
 */
function clientFingerprints(settings: IdentitySettings): Record<string, string> {
  const { access, directory, provisioner } = settings.clients;
  const entries = [
    [access.id, { secret: access.secret, redirectUris: access.redirectUris }],
    [directory.id, { secret: directory.secret }],
    [provisioner.id, { secret: provisioner.secret }],
  ] as const;
  return Object.fromEntries(
    entries.map(([id, inputs]) => [id, Hashing.sha256Hex(JSON.stringify({ id, ...inputs }))]),
  );
}

function parseFingerprints(stored: string): Record<string, string> {
  if (!stored) return {};
  try {
    const parsed: unknown = JSON.parse(stored);
    if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return Object.fromEntries(
      Object.entries(parsed).filter(
        (entry): entry is [string, string] => typeof entry[1] === 'string',
      ),
    );
  } catch {
    return {};
  }
}

/**
 * Lets one realm reconcile at a time. Every request that arrives before the fingerprint is
 * stored runs in its own realm, and without this each of them would start the same minutes of
 * Argon2id hashing on the host's CPU. The claim is one statement, as every write on this
 * database must be: insert the lease, or take over one whose expiry has passed. Losers throw
 * `BootstrapBusyError` and the request answers 503 at once.
 */
async function withBootstrapLease(database: SqlDatabase, fn: () => Promise<void>): Promise<void> {
  const now = new Date();
  const until = new Date(now.getTime() + LEASE_MS).toISOString();
  const claimed = await database.query<{ name: string }>(
    `INSERT INTO identity_runtime_secret (name, value) VALUES (?, ?)
     ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value
     WHERE identity_runtime_secret.value < ?
     RETURNING name`,
    [BOOTSTRAP_LEASE, until, now.toISOString()],
  );
  if (claimed.length === 0) {
    throw new BootstrapBusyError(await storedValue(database, BOOTSTRAP_LEASE));
  }
  try {
    await fn();
  } finally {
    await database.run('DELETE FROM identity_runtime_secret WHERE name = ? AND value = ?', [
      BOOTSTRAP_LEASE,
      until,
    ]);
  }
}

async function storedValue(database: SqlDatabase, name: string): Promise<string> {
  const row = await database.first<{ value: unknown }>(
    'SELECT value FROM identity_runtime_secret WHERE name = ?',
    [name],
  );
  return row?.value == null ? '' : String(row.value);
}

async function storeValue(database: SqlDatabase, name: string, value: string): Promise<void> {
  await database.run(
    `INSERT INTO identity_runtime_secret (name, value) VALUES (?, ?)
     ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value`,
    [name, value],
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
