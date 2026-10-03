import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { PostgresChallengeRepository } from './account/infrastructure/postgres-challenge-repository.ts';
import { PostgresAuditRepository } from './audit/infrastructure/postgres-audit-repository.ts';
import { PostgresAuthorizationRepository } from './authorization/infrastructure/postgres-authorization-repository.ts';
import { PostgresRegisteredClientRepository } from './authorization/infrastructure/postgres-registered-client-repository.ts';
import { BootstrapReconciler } from './bootstrap/application/bootstrap-reconciler.ts';
import { PostgresDirectoryRepository } from './directory/infrastructure/postgres-directory-repository.ts';
import { HttpIdentityProviderClient } from './linking/infrastructure/http-identity-provider-client.ts';
import { PostgresLinkRepository } from './linking/infrastructure/postgres-link-repository.ts';
import type { MailSender } from './mail/domain/mail.ts';
import { SmtpMailSender, UnconfiguredMailSender } from './mail/infrastructure/smtp-mail-sender.ts';
import { NotificationWorker } from './notifications/application/security-notifications.ts';
import { PostgresNotificationRepository } from './notifications/infrastructure/postgres-notification-repository.ts';
import { PostgresOAuthRepository } from './oauth/infrastructure/postgres-oauth-repository.ts';
import { PostgresSessionRepository } from './sessions/infrastructure/postgres-session-repository.ts';
import { systemClock } from './shared/domain/clock.ts';
import {
  AUDIT,
  AUTHORIZATIONS,
  CHALLENGES,
  CLOCK,
  DIRECTORY,
  IDENTITY_DATABASE,
  IDENTITY_PROVIDERS,
  IDENTITY_SETTINGS,
  LINKS,
  MAIL,
  NOTIFICATIONS,
  OAUTH,
  REGISTERED_CLIENTS,
  SESSIONS,
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
    container.registerFactory(MAIL, () => IdentityModule.mailSender(IdentityModule.settings()));
    IdentityModule.port(DIRECTORY, PostgresDirectoryRepository);
    IdentityModule.port(OAUTH, PostgresOAuthRepository);
    IdentityModule.port(AUDIT, PostgresAuditRepository);
    IdentityModule.port(LINKS, PostgresLinkRepository);
    IdentityModule.port(REGISTERED_CLIENTS, PostgresRegisteredClientRepository);
    IdentityModule.port(AUTHORIZATIONS, PostgresAuthorizationRepository);
    IdentityModule.port(SESSIONS, PostgresSessionRepository);
    IdentityModule.port(CHALLENGES, PostgresChallengeRepository);
    IdentityModule.port(NOTIFICATIONS, PostgresNotificationRepository);
    IdentityModule.port(IDENTITY_PROVIDERS, HttpIdentityProviderClient);
  }

  /** SMTP from settings, or a sender that always fails when no host is configured. */
  static mailSender(settings: IdentitySettings): MailSender {
    if (!settings.smtp.host) return new UnconfiguredMailSender();
    return new SmtpMailSender(settings.smtp);
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

  /**
   * Startup checks that fail closed, as the auth server does: load and validate the signing
   * keys, then reconcile bootstrap state.
   */
  static async prepare(): Promise<void> {
    const container = useContainer();
    container.resolve(SIGNING_KEYS);
    await container.resolve(BootstrapReconciler).reconcile();
  }

  /** Starts the security-notification worker unless the settings disable it. */
  static startNotificationWorker(
    onError?: (error: unknown) => void,
  ): NotificationWorker | undefined {
    const { notifications } = IdentityModule.settings();
    if (!notifications.schedulerEnabled) return undefined;
    const worker = useContainer().resolve(NotificationWorker);
    worker.start(notifications.fixedDelayMs, onError);
    return worker;
  }

  /** Binds a port token to an adapter class. Exposed so other modules can add ports. */
  static port<T>(token: string, adapter: new (...args: never[]) => T): void {
    const container = useContainer();
    container.registerFactory(token, () => container.resolve(adapter as never));
  }
}

IdentityModule.bind();
