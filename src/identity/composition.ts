import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { PostgresAuditRepository } from './audit/infrastructure/postgres-audit-repository.ts';
import { PostgresDirectoryRepository } from './directory/infrastructure/postgres-directory-repository.ts';
import { PostgresLinkRepository } from './linking/infrastructure/postgres-link-repository.ts';
import { PostgresOAuthRepository } from './oauth/infrastructure/postgres-oauth-repository.ts';
import { AUDIT, DIRECTORY, IDENTITY_DATABASE, LINKS, OAUTH } from './shared/domain/tokens.ts';
import { configuredDatabaseUrl } from './shared/infrastructure/database-config.ts';
import { openPostgresDatabase } from './shared/infrastructure/postgres.ts';

/** Binds domain ports to Postgres adapters and accepts the process database. */
export class IdentityModule {
  static bind(): void {
    IdentityModule.port(DIRECTORY, PostgresDirectoryRepository);
    IdentityModule.port(OAUTH, PostgresOAuthRepository);
    IdentityModule.port(AUDIT, PostgresAuditRepository);
    IdentityModule.port(LINKS, PostgresLinkRepository);
  }

  static connect(database: SqlDatabase): void {
    useContainer().registerValue(IDENTITY_DATABASE, database);
  }

  /** Opens Postgres from the identity config and registers that connection. */
  static async connectFromConfig(env?: NodeJS.ProcessEnv): Promise<SqlDatabase> {
    const database = await openPostgresDatabase(configuredDatabaseUrl(env));
    IdentityModule.connect(database);
    return database;
  }

  private static port<T>(token: string, adapter: new (...args: never[]) => T): void {
    const container = useContainer();
    container.registerFactory(token, () => container.resolve(adapter as never));
  }
}

IdentityModule.bind();
