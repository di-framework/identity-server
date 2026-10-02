import {
  type ConfigSource,
  Configuration,
  envSource,
  loadConfigSync,
  Value,
} from '@di-framework/config';
import { useContainer } from '@di-framework/core/container';
import { Container } from '@di-framework/core/decorators';

/** Local `podman compose` database. Matches `compose.yml`. */
export const localPostgresUrl = 'postgres://identity:identity@127.0.0.1:5432/identity';

/**
 * Env source for the identity process.
 * `IDENTITY_DATABASE__URL` sets `database.url`. `DATABASE_URL` wins when both are set.
 */
export function identityEnvSource(env: NodeJS.ProcessEnv = process.env): ConfigSource {
  return {
    name: 'identity-env',
    load() {
      const prefixed = envSource({ prefix: 'IDENTITY_', env, coerce: false }).load() as Record<
        string,
        unknown
      >;
      if (!env.DATABASE_URL) return prefixed;
      const database = prefixed.database;
      const current = database !== null && typeof database === 'object' ? database : {};
      return { ...prefixed, database: { ...current, url: env.DATABASE_URL } };
    },
  };
}

export function loadDatabaseConfig(env: NodeJS.ProcessEnv = process.env): { url: string } {
  const loaded = loadConfigSync<{ database: { url: string } }>({
    defaults: { database: { url: localPostgresUrl } },
    sources: [identityEnvSource(env)],
  });
  return { url: loaded.database.url };
}

@Configuration({
  token: 'identity.config',
  sources: [identityEnvSource()],
})
export class IdentityConfig {
  database = { url: localPostgresUrl };
}

/** Database URL injected from the registered identity config. */
@Container()
export class DatabaseSettings {
  constructor(@Value('database.url', { token: 'identity.config' }) readonly url: string) {}
}

export function configuredDatabaseUrl(env?: NodeJS.ProcessEnv): string {
  if (env) return loadDatabaseConfig(env).url;
  return useContainer().resolve(DatabaseSettings).url;
}
