import { afterAll, afterEach, beforeAll, expect, spyOn, test } from 'bun:test';
import { randomBytes } from 'node:crypto';
import { useContainer } from '@di-framework/core/container';
import type { AuditRepository } from '../src/audit/domain/audit-entry.ts';
import { IdentityModule } from '../src/composition.ts';
import { AUDIT, IDENTITY_SETTINGS } from '../src/shared/domain/tokens.ts';
import {
  ColumnEncryption,
  DISABLED_REFRESH_MS,
} from '../src/shared/infrastructure/column-encryption.ts';
import type { IdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import { PostgresGateway } from '../src/shared/infrastructure/postgres-gateway.ts';
import { useIsolatedDatabase } from './support/database.ts';

/**
 * Two service instances on one database: this process's container (instance A) and a second
 * `ColumnEncryption` on its own gateway (instance B), standing in for another replica.
 */
const KEYS = {
  columns: true,
  columnKey: randomBytes(32).toString('base64'),
  bidxKey: randomBytes(32).toString('base64'),
};
let original: IdentitySettings;
let isolated: Awaited<ReturnType<typeof useIsolatedDatabase>> | undefined;

const withEncryption = (encryption: IdentitySettings['encryption']): IdentitySettings => ({
  ...original,
  encryption,
});
const instanceA = () => useContainer().resolve(ColumnEncryption);
const audits = () => useContainer().resolve<AuditRepository>(AUDIT);

/** A fresh database where instance A has cached the disabled state. */
async function disabledInstanceA(name: string): Promise<void> {
  await isolated?.release();
  isolated = await useIsolatedDatabase(name);
  IdentityModule.configure(withEncryption({ columns: false, columnKey: '', bidxKey: '' }));
  expect((await instanceA().cipher()).enabled).toBe(false);
  // A's environment now has the keys too, but A keeps its cached state (no configure/reset).
  useContainer().registerValue(IDENTITY_SETTINGS, withEncryption({ ...KEYS, columns: false }));
}

/** Instance B opts in with the keys. */
async function instanceBOptsIn(): Promise<void> {
  const settings = useContainer().resolve<IdentitySettings>(IDENTITY_SETTINGS);
  useContainer().registerValue(IDENTITY_SETTINGS, withEncryption(KEYS));
  expect((await new ColumnEncryption(new PostgresGateway()).cipher()).enabled).toBe(true);
  useContainer().registerValue(IDENTITY_SETTINGS, settings);
}

beforeAll(() => {
  original = IdentityModule.settings();
});
afterEach(() => instanceA().reset());
afterAll(async () => {
  IdentityModule.configure(original);
  await isolated?.release();
});

test("a refused plaintext write makes an instance re-read the other instance's opt-in", async () => {
  await disabledInstanceA('identity_colenc_instances_a');
  await instanceBOptsIn();
  // A still has the disabled state cached...
  expect((await instanceA().cipher()).enabled).toBe(false);
  // ...so its plaintext write is refused by the trigger (503), which drops A's cached state.
  const append = () =>
    audits().append({
      action: 'test.instances',
      actor: null,
      target: null,
      correlationId: 'a',
      after: { email: 'pat@example.com' },
    });
  await expect(append()).rejects.toMatchObject({ status: 503 });
  expect((await instanceA().cipher()).enabled).toBe(true);
  await append();
  const rows = await isolated?.database.query<Record<string, unknown>>(
    `SELECT after_metadata, after_metadata_enc IS NOT NULL AS enc
     FROM auth_audit_records WHERE action = 'test.instances'`,
  );
  expect(rows).toEqual([{ after_metadata: null, enc: true }]);
});

test('a cached disabled state is re-read after the refresh interval', async () => {
  await disabledInstanceA('identity_colenc_instances_b');
  await instanceBOptsIn();
  const start = Date.now();
  const now = spyOn(Date, 'now');
  try {
    now.mockReturnValue(start + DISABLED_REFRESH_MS - 1_000);
    expect((await instanceA().cipher()).enabled).toBe(false);
    now.mockReturnValue(start + DISABLED_REFRESH_MS + 1_000);
    expect((await instanceA().cipher()).enabled).toBe(true);
  } finally {
    now.mockRestore();
  }
});
