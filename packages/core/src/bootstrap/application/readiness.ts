import { Component, Container } from '@di-framework/core/decorators';
import { IDENTITY_SETTINGS } from '../../shared/domain/tokens.ts';
import type { IdentitySettings } from '../../shared/infrastructure/identity-settings.ts';
import { PostgresGateway } from '../../shared/infrastructure/postgres-gateway.ts';
import { BootstrapReconciler } from './bootstrap-reconciler.ts';

export interface ReadinessReport {
  database: boolean;
  signing_key: boolean;
  smtp: boolean;
  bootstrap: boolean;
  ok: boolean;
}

/**
 * `GET /ready` checks, in the auth server's key order (`WebController.ready`). The signing key is
 * validated at startup, so its check is always true. SMTP is ready when a host and a sender are
 * configured; no connection is made. The body never contains configuration values.
 */
@Container()
export class Readiness {
  constructor(
    @Component(PostgresGateway) private readonly db: PostgresGateway,
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(BootstrapReconciler) private readonly bootstrap: BootstrapReconciler,
  ) {}

  async check(timeoutMs = 2000): Promise<ReadinessReport> {
    const database = await this.database(timeoutMs);
    const smtp = Boolean(this.settings.smtp.host && this.settings.smtp.from);
    const bootstrap = this.bootstrap.complete;
    return {
      database,
      signing_key: true,
      smtp,
      bootstrap,
      ok: database && smtp && bootstrap,
    };
  }

  private async database(timeoutMs: number): Promise<boolean> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), timeoutMs);
    });
    const probe = this.db.one('SELECT 1 AS ok').then(
      () => true,
      () => false,
    );
    try {
      return await Promise.race([probe, timeout]);
    } finally {
      clearTimeout(timer);
    }
  }
}
