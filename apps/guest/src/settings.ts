import type { SqlDatabase } from '@di-framework/repo';
import {
  type IdentitySettings,
  loadIdentitySettings,
} from '../../../packages/core/src/shared/infrastructure/identity-settings.ts';

/**
 * Operator values in `identity_runtime_secret`. wasi:config rejects URLs and secrets.
 * SMTP_HOST is per environment and is not compiled into the guest.
 */
export const SECRET_SETTINGS = [
  'ISSUER_URL',
  'AUTH_PUBLIC_ORIGIN',
  'AUTH_ACTIVE_PRIVATE_JWK',
  'AUTH_PREVIOUS_PUBLIC_JWK_SET',
  'SMTP_HOST',
  'SMTP_PASSWORD',
  'AUTH_ACCESS_REDIRECT_URIS',
  'AUTH_BOOTSTRAP_OWNER_PASSWORD',
  'AUTH_BOOTSTRAP_VIEWER_PASSWORD',
  'AUTH_ACCESS_CLIENT_SECRET',
  'AUTH_DIRECTORY_CLIENT_SECRET',
  'AUTH_PROVISIONER_CLIENT_SECRET',
] as const;

export interface ConfigStore {
  getAll(): Promise<Array<[string, string]>> | Array<[string, string]>;
}

/** Merge wasi:config with the secret table. Table values win. */
export async function loadGuestSettings(
  config: ConfigStore,
  database: SqlDatabase,
): Promise<IdentitySettings> {
  const env: Record<string, string> = {};
  for (const [key, value] of await config.getAll()) env[key] = value;
  const rows = await database.query<{ name: string; value: string }>(
    'SELECT name, value FROM identity_runtime_secret',
  );
  for (const row of rows) env[String(row.name)] = String(row.value);
  return loadIdentitySettings(env);
}
