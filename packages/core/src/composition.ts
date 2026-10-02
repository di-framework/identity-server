import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { PostgresAuditRepository } from './audit/infrastructure/postgres-audit-repository.ts';
import { PostgresDirectoryRepository } from './directory/infrastructure/postgres-directory-repository.ts';
import { PostgresLinkRepository } from './linking/infrastructure/postgres-link-repository.ts';
import { PostgresOAuthRepository } from './oauth/infrastructure/postgres-oauth-repository.ts';
import { systemClock } from './shared/domain/clock.ts';
import {
  AUDIT,
  CLOCK,
  DIRECTORY,
  IDENTITY_DATABASE,
  IDENTITY_SETTINGS,
  LINKS,
  OAUTH,
  SIGNING_KEYS,
} from './shared/domain/tokens.ts';
import { SigningKeys } from './shared/infrastructure/crypto/signing-keys.ts';
import { configuredDatabaseUrl } from './shared/infrastructure/database-config.ts';
import {
  type IdentitySettings,
  loadIdentitySettings,
} from './shared/infrastructure/identity-settings.ts';
import { openPostgresDatabase } from './shared/infrastructure/postgres.ts';

/** Binds domain ports to Postgres adapters and accepts the process database and settings. */
export class IdentityModule {
  static bind(): void {
    const container = useContainer();
    container.registerFactory(IDENTITY_SETTINGS, () => loadIdentitySettings());
    container.registerFactory(SIGNING_KEYS, () =>
      SigningKeys.load(container.resolve<IdentitySettings>(IDENTITY_SETTINGS).jwk),
    );
    container.registerFactory(CLOCK, () => systemClock());
    IdentityModule.port(DIRECTORY, PostgresDirectoryRepository);
    IdentityModule.port(OAUTH, PostgresOAuthRepository);
    IdentityModule.port(AUDIT, PostgresAuditRepository);
    IdentityModule.port(LINKS, PostgresLinkRepository);
  }

  /** Registers explicit settings, for a process that loaded them itself. */
  static configure(settings: IdentitySettings): void {
    useContainer().registerValue(IDENTITY_SETTINGS, settings);
  }

  static settings(): IdentitySettings {
    return useContainer().resolve<IdentitySettings>(IDENTITY_SETTINGS);
  }

  static connect(database: SqlDatabase): void {
    useContainer().registerValue(IDENTITY_DATABASE, database);
  }

  /** Opens Postgres from the identity config and registers that connection pool. */
  static async connectFromConfig(env?: NodeJS.ProcessEnv): Promise<SqlDatabase> {
    const max = env
      ? loadIdentitySettings(env).database.poolMax
      : IdentityModule.settings().database.poolMax;
    const database = await openPostgresDatabase(configuredDatabaseUrl(env), { max });
    IdentityModule.connect(database);
    return database;
  }

  /** Binds a port token to an adapter class. Exposed so other modules can add ports. */
  static port<T>(token: string, adapter: new (...args: never[]) => T): void {
    const container = useContainer();
    container.registerFactory(token, () => container.resolve(adapter as never));
  }
}

IdentityModule.bind();
