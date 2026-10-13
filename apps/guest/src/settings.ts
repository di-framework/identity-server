import {
  type IdentitySettings,
  loadIdentitySettings,
} from '../../../packages/core/src/shared/infrastructure/identity-settings.ts';
import type { GuestEnv } from './database.ts';

/**
 * Settings the guest reads from its WASI environment, which the platform fills from the
 * workload's `identity-control` Kubernetes Secret (`localResources.environment.secretFrom`).
 * wasi:config cannot carry them: the platform rejects secrets and URLs there. They never touch
 * the database. SMTP_HOST is per environment and is not compiled into the guest either.
 */
export const RUNTIME_SECRET_SETTINGS = [
  'ISSUER_URL',
  'AUTH_PUBLIC_ORIGIN',
  'AUTH_ACTIVE_PRIVATE_JWK',
  'AUTH_PREVIOUS_PUBLIC_JWK_SET',
  'SMTP_HOST',
  'SMTP_USERNAME',
  'SMTP_PASSWORD',
  'AUTH_ACCESS_REDIRECT_URIS',
  'AUTH_BOOTSTRAP_OWNER_PASSWORD',
  'AUTH_BOOTSTRAP_VIEWER_PASSWORD',
  'AUTH_ACCESS_CLIENT_SECRET',
  'AUTH_DIRECTORY_CLIENT_SECRET',
  'AUTH_PROVISIONER_CLIENT_SECRET',
  'AUTH_CLI_CLIENT_ID',
  'AUTH_CLI_REDIRECT_URIS',
  // Opt-in column encryption (docs/configuration.md#column-encryption). The two keys are separate
  // from each other and from the pglite filesystem key DI_PGLITE_KEY.
  'IDENTITY_COLUMN_ENCRYPTION',
  'IDENTITY_COLUMN_KEY',
  'IDENTITY_BIDX_KEY',
] as const;

/**
 * The bootstrap identity: who the owner and viewer are and which organization they bootstrap.
 * The compiled-in wasi:config (`IdentityConfig` in bindings.ts) holds the defaults; an
 * environment value overrides them, as the Postgres-era guest's `identity_runtime_secret` rows
 * did when it merged that table over wasi:config. authproto set all eight there, so the cutover
 * carries them through the values file and the `identity-control` Secret; without them the new
 * guest's bootstrap fingerprint would differ and it would reconcile a second owner, viewer and
 * organization from the defaults.
 *
 * They are personal data (logins, emails, names), not secrets: kept apart from
 * `RUNTIME_SECRET_SETTINGS` so nothing treats them as credentials, but travelling in the same
 * Secret, because that is the only channel into the guest's environment, and never logged.
 */
export const RUNTIME_BOOTSTRAP_IDENTITY_SETTINGS = [
  'AUTH_BOOTSTRAP_ORGANIZATION_SLUG',
  'AUTH_BOOTSTRAP_ORGANIZATION_NAME',
  'AUTH_BOOTSTRAP_OWNER_LOGIN',
  'AUTH_BOOTSTRAP_OWNER_EMAIL',
  'AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME',
  'AUTH_BOOTSTRAP_VIEWER_LOGIN',
  'AUTH_BOOTSTRAP_VIEWER_EMAIL',
  'AUTH_BOOTSTRAP_VIEWER_DISPLAY_NAME',
] as const;

/** Every name the guest reads from its environment. */
export const RUNTIME_ENV_SETTINGS = [
  ...RUNTIME_SECRET_SETTINGS,
  ...RUNTIME_BOOTSTRAP_IDENTITY_SETTINGS,
] as const;

/**
 * Without these the guest would sign tokens for the default `http://localhost:4180` issuer, or
 * with no key at all. A deploy that wrote the control Secret without them (a plain
 * `di-framework platform deploy` rewrites it with only its control token) must fail closed.
 */
export const REQUIRED_RUNTIME_SECRETS = [
  'ISSUER_URL',
  'AUTH_PUBLIC_ORIGIN',
  'AUTH_ACTIVE_PRIVATE_JWK',
] as const;

export interface ConfigStore {
  getAll(): Promise<Array<[string, string]>> | Array<[string, string]>;
}

/** The boot error for a control Secret without the runtime settings. Names only, never values. */
export class MissingRuntimeSecretsError extends Error {
  constructor(readonly missing: readonly string[]) {
    super(`runtime settings missing from the identity-control Secret: ${missing.join(', ')}`);
    this.name = 'MissingRuntimeSecretsError';
  }
}

/**
 * Merge wasi:config with the runtime settings from the environment (`RUNTIME_ENV_SETTINGS`).
 * Environment values win, also over the bootstrap identity defaults.
 */
export async function loadGuestSettings(
  config: ConfigStore,
  env: GuestEnv,
): Promise<IdentitySettings> {
  const merged: Record<string, string> = {};
  for (const [key, value] of await config.getAll()) merged[key] = value;
  for (const key of RUNTIME_ENV_SETTINGS) {
    const value = env[key];
    if (value !== undefined) merged[key] = value;
  }
  const missing = REQUIRED_RUNTIME_SECRETS.filter((key) => !merged[key]?.trim());
  if (missing.length > 0) throw new MissingRuntimeSecretsError(missing);
  return loadIdentitySettings(merged);
}
