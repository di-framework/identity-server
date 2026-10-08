import { Component, Container } from '@di-framework/core/decorators';
import type { RegisteredClientRepository } from '../../authorization/domain/models.ts';
import type { DirectoryRepository } from '../../directory/domain/directory-repository.ts';
import { DIRECTORY, IDENTITY_SETTINGS, REGISTERED_CLIENTS } from '../../shared/domain/tokens.ts';
import { PasswordHasher } from '../../shared/infrastructure/crypto/passwords.ts';
import type {
  IdentitySettings,
  PersonSettings,
} from '../../shared/infrastructure/identity-settings.ts';

/** Startup failure for incomplete bootstrap configuration. */
export class BootstrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BootstrapError';
  }
}

interface BootstrapClient {
  id: string;
  secret: string;
  scopes: string[];
  redirects: string[];
  browser: boolean;
}

/**
 * First-deployment state from encrypted configuration (`BootstrapReconciler.kt`): the owner as an
 * active platform admin, the organization with the owner as owner, an optional viewer member,
 * and the access, directory, and provisioner clients. Safe to run on every start. Writes no
 * audit rows.
 */
@Container()
export class BootstrapReconciler {
  private reconciled = false;

  constructor(
    @Component(IDENTITY_SETTINGS) private readonly settings: IdentitySettings,
    @Component(DIRECTORY) private readonly directory: DirectoryRepository,
    @Component(REGISTERED_CLIENTS) private readonly clients: RegisteredClientRepository,
    @Component(PasswordHasher) private readonly passwords: PasswordHasher,
  ) {}

  /** True once `reconcile` has succeeded in this process. The `/ready` `bootstrap` check. */
  get complete(): boolean {
    return this.reconciled;
  }

  /**
   * Records bootstrap as done without hashing. The guest calls this when a fresh component
   * realm finds the same secret fingerprint it stored after the last successful reconcile.
   */
  markComplete(): void {
    this.reconciled = true;
  }

  async reconcile(): Promise<void> {
    const { bootstrap, clients } = this.settings;
    const { owner, organization } = bootstrap;
    require(Boolean(
      owner.email && owner.login && owner.password,
    ), 'Bootstrap owner configuration is required');
    require(Boolean(
      organization.slug && organization.name,
    ), 'Bootstrap organization configuration is required');
    require(Boolean(
      clients.access.id && clients.access.secret,
    ), 'Access Control client configuration is required');
    require(Boolean(
      clients.directory.id && clients.directory.secret,
    ), 'Directory client configuration is required');
    require(Boolean(
      clients.provisioner.id && clients.provisioner.secret,
    ), 'Provisioner client configuration is required');
    const redirects = [...new Set(clients.access.redirectUris)];
    require(redirects.length > 0, 'Access Control redirect URIs are required');
    for (const uri of redirects) require(absolute(uri), 'Invalid Access Control redirect URI');
    if (clients.cli.id) {
      const reserved = [clients.access.id, clients.directory.id, clients.provisioner.id];
      const duplicate = reserved.includes(clients.cli.id);
      require(!duplicate, 'CLI client id must differ from the other bootstrap clients');
      require(clients.cli.redirectUris.length > 0, 'CLI client redirect URIs are required');
      for (const uri of clients.cli.redirectUris)
        require(loopbackOnly(uri), 'CLI client redirect URIs must be loopback http URIs');
    }

    await this.directory.transaction(async () => {
      const ownerId = await this.ensurePerson(owner, 'platform_admin', true);
      const org = await this.ensureOrganization();
      await this.directory.upsertMembership(org, ownerId, 'owner');
      await this.ensureViewer(org);
      await this.ensureClient({
        id: clients.access.id,
        secret: clients.access.secret,
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        redirects,
        browser: true,
      });
      await this.ensureClient({
        id: clients.directory.id,
        secret: clients.directory.secret,
        scopes: ['directory:read'],
        redirects: [],
        browser: false,
      });
      await this.ensureClient({
        id: clients.provisioner.id,
        secret: clients.provisioner.secret,
        scopes: ['admin:read', 'admin:write', 'directory:read'],
        redirects: [],
        browser: false,
      });
      if (clients.cli.id) await this.ensurePublicClient(clients.cli.id, clients.cli.redirectUris);
    });
    this.reconciled = true;
  }

  /** Creates the person, or keeps the existing row and activates it (the owner is re-promoted). */
  private async ensurePerson(
    person: PersonSettings,
    systemRole: string,
    promote: boolean,
  ): Promise<string> {
    const existing = await this.directory.findUserByEmailOrLogin(person.email, person.login);
    if (!existing) {
      const id = crypto.randomUUID();
      await this.directory.insertAccount({
        id,
        login: person.login,
        email: person.email,
        displayName: person.displayName || person.login,
        passwordHash: await this.passwords.hash(person.password),
        emailVerified: true,
        systemRole,
        status: 'active',
      });
      return id;
    }
    await this.directory.updateAccount(existing.id, {
      passwordHash: existing.passwordHash ? undefined : await this.passwords.hash(person.password),
      systemRole: promote ? systemRole : undefined,
      status: 'active',
    });
    return existing.id;
  }

  private async ensureOrganization(): Promise<string> {
    const { slug, name } = this.settings.bootstrap.organization;
    const existing = await this.directory.findOrganization(slug);
    if (existing) return existing.id;
    const id = crypto.randomUUID();
    await this.directory.insertOrganization({ id, slug, name });
    return id;
  }

  /** Optional journey member, skipped when the viewer login or password is blank. */
  private async ensureViewer(organizationId: string): Promise<void> {
    const viewer = this.settings.bootstrap.viewer;
    if (!viewer.login || !viewer.password) return;
    require(Boolean(viewer.email), 'Bootstrap viewer email is required when viewer login is set');
    const viewerId = await this.ensurePerson(viewer, 'user', false);
    await this.directory.upsertMembership(organizationId, viewerId, 'member');
  }

  /**
   * A public native client (RFC 8252): `none` authentication, PKCE required, loopback redirects
   * matched on any port, consent on first use. An existing row is rewritten to that shape,
   * including its grants and a cleared secret, so it cannot keep `client_credentials`.
   */
  private async ensurePublicClient(id: string, redirects: string[]): Promise<void> {
    const scopes = ['openid', 'profile', 'email', 'offline_access'];
    const grantTypes = ['authorization_code', 'refresh_token'];
    const unique = [...new Set(redirects)];
    const settings = { requireProofKey: true, requireAuthorizationConsent: true };
    if (await this.clients.find(id)) {
      await this.clients.update(id, {
        secretHash: null,
        grantTypes,
        scopes,
        authenticationMethods: ['none'],
        redirectUris: unique,
        settings,
        organizationSlug: null,
      });
      await this.clients.ensureLifecycle(id, null);
      return;
    }
    await this.clients.insert({
      clientId: id,
      clientName: id,
      secretHash: null,
      authenticationMethods: ['none'],
      grantTypes,
      redirectUris: unique,
      scopes,
      settings,
      organizationSlug: null,
    });
  }

  /**
   * New clients get the full registration. Existing clients get a re-hashed secret and replaced
   * scopes; the browser client also gets its auth methods and redirect URIs replaced. Grant
   * types and settings of an existing client are left alone.
   */
  private async ensureClient(input: BootstrapClient): Promise<void> {
    const secretHash = await this.passwords.hash(input.secret);
    const existing = await this.clients.find(input.id);
    const methods = input.browser
      ? ['client_secret_basic', 'client_secret_post']
      : ['client_secret_basic'];
    if (existing) {
      await this.clients.update(input.id, {
        secretHash,
        scopes: input.scopes,
        ...(input.browser ? { authenticationMethods: methods, redirectUris: input.redirects } : {}),
      });
      await this.clients.ensureLifecycle(input.id, null);
      return;
    }
    await this.clients.insert({
      clientId: input.id,
      clientName: input.id,
      secretHash,
      authenticationMethods: methods,
      grantTypes: input.browser ? ['authorization_code', 'refresh_token'] : ['client_credentials'],
      redirectUris: input.redirects,
      scopes: input.scopes,
      settings: { requireProofKey: input.browser, requireAuthorizationConsent: input.browser },
      organizationSlug: null,
    });
  }
}

function require(condition: boolean, message: string): void {
  if (!condition) throw new BootstrapError(message);
}

/** The loopback redirect a native client registers; the port is matched at authorize time. */
function loopbackOnly(uri: string): boolean {
  try {
    const url = new URL(uri);
    return url.protocol === 'http:' && (url.hostname === '127.0.0.1' || url.hostname === '[::1]');
  } catch {
    return false;
  }
}

/** `java.net.URI.isAbsolute` with no fragment: a scheme is present and there is no `#`. */
function absolute(uri: string): boolean {
  if (uri.includes('#')) return false;
  try {
    return new URL(uri).protocol.length > 1;
  } catch {
    return false;
  }
}
