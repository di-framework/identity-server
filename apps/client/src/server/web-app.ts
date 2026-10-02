import { container as diContainer } from '@di-framework/core/container';
import { AccountService } from '@di-framework/identity/src/account/application/account-service.ts';
import { PasswordlessService } from '@di-framework/identity/src/account/application/passwordless-service.ts';
import {
  AdminAccessDenied,
  AdminPolicy,
  type AdminResult,
} from '@di-framework/identity/src/admin/application/admin-policy.ts';
import { AuditAdminService } from '@di-framework/identity/src/admin/application/audit-admin.ts';
import { ClientAdminService } from '@di-framework/identity/src/admin/application/client-admin.ts';
import { MembershipAdminService } from '@di-framework/identity/src/admin/application/membership-admin.ts';
import { OrganizationAdminService } from '@di-framework/identity/src/admin/application/organization-admin.ts';
import { UserAdminService } from '@di-framework/identity/src/admin/application/user-admin.ts';
import { PLATFORM_ONLY } from '@di-framework/identity/src/admin/domain/admin-access-policy.ts';
import type { RegisteredClient } from '@di-framework/identity/src/authorization/domain/models.ts';
import type { DirectoryRepository } from '@di-framework/identity/src/directory/domain/directory-repository.ts';
import type {
  Organization,
  UserAccount,
} from '@di-framework/identity/src/directory/domain/models.ts';
import { LinkFlowService } from '@di-framework/identity/src/linking/application/link-flow-service.ts';
import {
  type AccountCaller,
  LinkService,
} from '@di-framework/identity/src/linking/application/link-service.ts';
import {
  type ActiveSession,
  SessionService,
} from '@di-framework/identity/src/sessions/application/session-service.ts';
import {
  SESSION_ATTRIBUTES,
  SESSION_COOKIE,
} from '@di-framework/identity/src/sessions/domain/session.ts';
import { IdentityError } from '@di-framework/identity/src/shared/domain/identity-error.ts';
import { ServiceResult } from '@di-framework/identity/src/shared/domain/service-result.ts';
import { DIRECTORY, IDENTITY_SETTINGS } from '@di-framework/identity/src/shared/domain/tokens.ts';
import {
  Hashing,
  TOKEN_PATTERN,
} from '@di-framework/identity/src/shared/infrastructure/crypto/hashing.ts';
import type { IdentitySettings } from '@di-framework/identity/src/shared/infrastructure/identity-settings.ts';
import type {
  ActorFields,
  BannerName,
  DeniedReason,
  MembershipRole,
  OrgChoice,
  PageModel,
} from '../domain/page-model.ts';

/** Passwordless challenge cookie (`WebController.challengeCookie`). */
export const CHALLENGE_COOKIE = 'gsio_passwordless_challenge';
const SECRET_ATTRIBUTE = 'IDENTITY_CLIENT_SECRET_REVEAL';

type Body<P> = P extends PageModel ? Omit<P, keyof ActorFields> : never;
type PageBody = Body<PageModel>;

/** What a route produces: a page model (with the auth server's status) or a redirect. */
export type Result =
  | { kind: 'page'; page: PageBody; status?: number }
  | { kind: 'redirect'; location: string; status?: number };

interface Context {
  url: URL;
  method: string;
  form: URLSearchParams;
  active: ActiveSession;
  user: UserAccount | undefined;
  cookies: string[];
  cookieHeader: string | null;
}

const page = (body: PageBody, status = 200): Result => ({ kind: 'page', page: body, status });
const redirect = (location: string, status = 303): Result => ({
  kind: 'redirect',
  location,
  status,
});

/**
 * Server side of the PatternFly pages, on Postgres. Each route mirrors an auth-server
 * kotlinx.html page or form action (`WebController`, `Admin*Controller`, `IdentityLinkController`)
 * and returns a page model; `handler.ts` renders it as JSON or as the HTML shell.
 */
export class WebApp {
  private get container() {
    return diContainer;
  }
  private get sessions() {
    return this.container.resolve(SessionService);
  }
  private get accounts() {
    return this.container.resolve(AccountService);
  }
  private get passwordless() {
    return this.container.resolve(PasswordlessService);
  }
  private get policy() {
    return this.container.resolve(AdminPolicy);
  }
  private get settings() {
    return this.container.resolve<IdentitySettings>(IDENTITY_SETTINGS);
  }

  /** Runs the route for a request. Returns the page or redirect plus cookies to set. */
  async run(request: Request): Promise<{ result: Result; cookies: string[]; actor: ActorFields }> {
    const url = new URL(request.url);
    const cookieHeader = request.headers.get('cookie');
    let active = await this.sessions.resolve(cookie(cookieHeader, SESSION_COOKIE));
    const cookies: string[] = [];
    if (!active) {
      active = await this.sessions.start();
      cookies.push(this.sessionCookie(active.token));
    }
    const form =
      request.method === 'POST' ? new URLSearchParams(await request.text()) : new URLSearchParams();
    const user = active.session.userId
      ? await this.directoryUser(active.session.userId)
      : undefined;
    const context: Context = {
      url,
      method: request.method,
      form,
      active,
      user,
      cookies,
      cookieHeader,
    };
    let result: Result;
    try {
      result = await this.route(context);
    } catch (error) {
      if (!(error instanceof AdminAccessDenied)) throw error;
      result = page({ page: 'denied', reason: this.deniedReason(context, error) }, 403);
    }
    return {
      result,
      cookies: context.cookies,
      actor: {
        csrf: context.active.session.csrf,
        signedIn: Boolean(context.user),
        displayName: context.user?.displayName ?? null,
      },
    };
  }

  private async route(c: Context): Promise<Result> {
    const path = c.url.pathname;
    if (
      c.method === 'POST' &&
      !path.startsWith('/passwordless') &&
      !this.sessions.csrfMatches(c.active, c.form.get('_csrf'))
    ) {
      return page(
        { page: 'error', title: 'Forbidden', message: 'Invalid or missing CSRF token.' },
        403,
      );
    }
    const publicRoute = this.publicRoute(c, path);
    if (publicRoute) return publicRoute;
    if (!c.user) return this.loginRequired(c);
    const get = c.method === 'GET';
    if (path === '/') return redirect('/account/identity-links', 302);
    if (path === '/account/password') return get ? this.passwordPage(c) : this.savePassword(c);
    if (path === '/oauth2/consent' && get) return this.consentPage(c);
    if (path.startsWith('/admin/')) return this.adminRoute(c, path, get);
    if (path.startsWith('/account/identity-links')) return this.linkRoute(c, path, get);
    return page({ page: 'not-found' }, 404);
  }

  /** Routes that need no signed-in user. Returns undefined when the path is not one of them. */
  private publicRoute(c: Context, path: string): Promise<Result> | undefined {
    const get = c.method === 'GET';
    if (path === '/login') return get ? Promise.resolve(page({ page: 'login' })) : this.signIn(c);
    if (path === '/admin/logout' && !get) return this.logOut(c);
    if (path === '/passwordless') {
      return get
        ? Promise.resolve(page({ page: 'passwordless', notice: false }))
        : this.requestLink(c);
    }
    if (path === '/passwordless/confirm') return get ? this.stageLink(c) : this.consumeLink(c);
    return undefined;
  }

  // ---- sign-in, passwords, passwordless -------------------------------------------------

  private async signIn(c: Context): Promise<Result> {
    const user = await this.accounts.signIn(
      c.form.get('username') ?? '',
      c.form.get('password') ?? '',
    );
    if (!user) return redirect('/login?error');
    const saved = c.active.session.attributes[SESSION_ATTRIBUTES.savedRequest];
    c.active = await this.sessions.signIn(c.active, user.id, true);
    c.active = await this.sessions.setAttribute(c.active, SESSION_ATTRIBUTES.savedRequest, null);
    c.cookies.push(this.sessionCookie(c.active.token));
    c.user = user;
    return redirect(saved && saved.startsWith('/') && !saved.startsWith('//') ? saved : '/');
  }

  private async logOut(c: Context): Promise<Result> {
    await this.sessions.destroy(c.active);
    c.cookies.length = 0;
    c.cookies.push(`${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${this.secure()}`);
    c.user = undefined;
    return redirect('/login?logout=1');
  }

  private async requestLink(c: Context): Promise<Result> {
    await this.passwordless.requestSignIn(c.form.get('email') ?? '');
    return page({ page: 'passwordless', notice: true });
  }

  /** `GET /passwordless/confirm?token=`: stores the token in a cookie and does not sign in. */
  private async stageLink(c: Context): Promise<Result> {
    const token = c.url.searchParams.get('token');
    if (token === null) return page({ page: 'passwordless-confirm', unavailable: false });
    if (!TOKEN_PATTERN.test(token))
      return page({ page: 'passwordless-confirm', unavailable: true }, 400);
    c.cookies.push(
      `${CHALLENGE_COOKIE}=${token}; Max-Age=900; Path=/passwordless/confirm; HttpOnly${this.secure()}; SameSite=Strict`,
    );
    return redirect('/passwordless/confirm');
  }

  private async consumeLink(c: Context): Promise<Result> {
    const token = cookie(c.cookieHeader, CHALLENGE_COOKIE) ?? '';
    c.cookies.push(
      `${CHALLENGE_COOKIE}=; Max-Age=0; Path=/passwordless/confirm; HttpOnly${this.secure()}; SameSite=Strict`,
    );
    const consumed = await this.passwordless.consume(token);
    if (!consumed) return redirect('/passwordless/confirm?error=invalid');
    c.active = await this.sessions.signIn(c.active, consumed.user.id, false);
    c.user = consumed.user;
    return redirect('/account/password');
  }

  private async passwordPage(_c: Context): Promise<Result> {
    return page({ page: 'password', error: null });
  }

  private async savePassword(c: Context): Promise<Result> {
    const result = await this.accounts.setPassword(
      (c.user as UserAccount).id,
      c.form.get('password') ?? '',
    );
    if (result === 'short') return page({ page: 'password', error: 'short' }, 400);
    return redirect('/account/password?updated=1');
  }

  /** `GET /oauth2/consent` (`WebController.consent`): the client is not named. */
  private async consentPage(c: Context): Promise<Result> {
    const clientId = c.url.searchParams.get('client_id');
    if (!clientId)
      return page({ page: 'error', title: 'Bad Request', message: 'client_id is required.' }, 400);
    const scopes = [
      ...new Set((c.url.searchParams.get('scope') ?? '').split(/[\s+,]+/).filter(Boolean)),
    ];
    return page({
      page: 'consent',
      clientId,
      state: c.url.searchParams.get('state'),
      openid: scopes.includes('openid'),
      scopes: scopes.filter((scope) => scope !== 'openid'),
    });
  }

  // ---- admin ------------------------------------------------------------------------------

  private async adminRoute(c: Context, path: string, get: boolean): Promise<Result> {
    const actor = (c.user as UserAccount).id;
    const q = c.url.searchParams;
    const f = c.form;
    const value = (name: string) => f.get(name) ?? '';
    if (path === '/admin/users' && get) return this.usersPage(actor, q);
    if (path === '/admin/users/invite') {
      if (get)
        return page({
          page: 'invite',
          organizations: choices(await this.users.inviteOrganizations(actor)),
          error: null,
        });
      const result = await this.users.invite(actor, {
        login: value('login'),
        email: value('email'),
        displayName: value('displayName'),
        orgSlug: f.get('orgSlug'),
        role: f.get('role'),
      });
      if (result.kind === 'error') {
        const organizations = choices(await this.users.inviteOrganizations(actor));
        return page(
          { page: 'invite', organizations, error: result.status === 409 ? 'conflict' : 'required' },
          result.status,
        );
      }
      return this.admin(result, () => page({ page: 'not-found' }));
    }
    const userAction = /^\/admin\/users\/([^/]+)\/(archive|restore|password-reset)$/.exec(path);
    if (userAction && !get) {
      const [, id = '', action] = userAction;
      const result =
        action === 'archive'
          ? await this.users.archive(actor, id)
          : action === 'restore'
            ? await this.users.restore(actor, id)
            : await this.users.passwordReset(actor, id);
      return this.admin(result, () => page({ page: 'not-found' }));
    }
    const userDetail = /^\/admin\/users\/([^/]+)$/.exec(path);
    if (userDetail && get) return this.userPage(actor, userDetail[1] ?? '', q);

    if (path === '/admin/organizations' && get) return this.organizationsPage(actor, q);
    if (path === '/admin/organizations/create') {
      if (get) {
        await this.organizations.checkCreate(actor);
        return page({ page: 'create-organization', error: null });
      }
      const result = await this.organizations.create(actor, {
        slug: value('slug'),
        name: value('name'),
      });
      if (result.kind === 'error') {
        return page(
          { page: 'create-organization', error: result.status === 409 ? 'duplicate-slug' : 'slug' },
          result.status,
        );
      }
      return this.admin(result, () => page({ page: 'not-found' }));
    }
    const orgAction = /^\/admin\/organizations\/([^/]+)\/(settings|archive)$/.exec(path);
    if (orgAction && !get) {
      const [, id = '', action] = orgAction;
      const result =
        action === 'settings'
          ? await this.organizations.updateSettings(actor, id, value('name'))
          : await this.organizations.archive(actor, id);
      return this.admin(result, () => page({ page: 'not-found' }));
    }
    const orgDetail = /^\/admin\/organizations\/([^/]+)$/.exec(path);
    if (orgDetail && get) return this.organizationPage(actor, orgDetail[1] ?? '', q);

    if (path === '/admin/memberships' && get) return this.membershipsPage(actor, q);
    if (path === '/admin/memberships/add' && !get) {
      return this.admin(
        await this.memberships.add(actor, {
          orgSlug: value('orgSlug'),
          userLoginOrEmail: value('userLoginOrEmail'),
          role: value('role'),
        }),
        () => page({ page: 'not-found' }),
      );
    }
    if (path === '/admin/memberships/role-change' && !get) {
      return this.admin(
        await this.memberships.changeRole(actor, {
          orgSlug: value('orgSlug'),
          userId: value('userId'),
          newRole: value('newRole'),
        }),
        () => page({ page: 'not-found' }),
      );
    }
    if (path === '/admin/memberships/remove' && !get) {
      return this.admin(
        await this.memberships.remove(actor, {
          orgSlug: value('orgSlug'),
          userId: value('userId'),
        }),
        () => page({ page: 'not-found' }),
      );
    }

    if (path === '/admin/oauth-clients' && get) return this.clientsPage(actor, q);
    if (path === '/admin/oauth-clients/register') {
      const organizations = choices(await this.clients.registerOrganizations(actor));
      if (get) return page({ page: 'register-client', organizations, error: null });
      const result = await this.clients.register(actor, {
        orgSlug: value('orgSlug'),
        clientName: value('clientName'),
        redirectUris: f.get('redirectUris'),
        grantTypes: f.get('grantTypes') || null,
        scopes: f.get('scopes') || null,
      });
      if (result.kind === 'error')
        return page(
          { page: 'register-client', organizations, error: 'invalid-org' },
          result.status,
        );
      return this.revealThenRedirect(c, result, 'newSecret');
    }
    const clientAction = /^\/admin\/oauth-clients\/([^/]+)\/(edit|rotate-secret|revoke)$/.exec(
      path,
    );
    if (clientAction && !get) {
      const [, id = '', action] = clientAction;
      if (action === 'edit') {
        const result = await this.clients.edit(actor, id, {
          clientName: value('clientName'),
          redirectUris: f.get('redirectUris'),
          grantTypes: f.get('grantTypes'),
          scopes: f.get('scopes'),
        });
        return this.admin(result, () => redirect(`/admin/oauth-clients/${id}?updated=1`));
      }
      if (action === 'rotate-secret')
        return this.revealThenRedirect(
          c,
          await this.clients.rotateSecret(actor, id),
          'rotatedSecret',
        );
      return this.admin(await this.clients.revoke(actor, id), () => page({ page: 'not-found' }));
    }
    const clientDetail = /^\/admin\/oauth-clients\/([^/]+)$/.exec(path);
    if (clientDetail && get) return this.clientPage(c, actor, clientDetail[1] ?? '', q);

    if (path === '/admin/audit' && get) return this.auditPage(actor, q);
    const auditDetail = /^\/admin\/audit\/([^/]+)$/.exec(path);
    if (auditDetail && get) {
      return this.admin(await this.audits.detail(actor, auditDetail[1] ?? ''), (record) =>
        page({
          page: 'audit-record',
          record: {
            id: record.id,
            timestamp: record.createdAt,
            action: record.action,
            actor: record.actorClientId ?? '',
            target: record.target ?? '',
            correlationId: record.correlationId ?? '',
            stateBefore: record.beforeMetadata,
            stateAfter: record.afterMetadata,
          },
        }),
      );
    }
    return page({ page: 'not-found' }, 404);
  }

  private async usersPage(actor: string, q: URLSearchParams): Promise<Result> {
    const status = q.get('status') ?? '';
    const users = await this.users.list(actor, {
      q: q.get('q') ?? undefined,
      status: status === 'all' ? undefined : status || undefined,
    });
    return page({
      page: 'users',
      query: q.get('q') ?? '',
      status: status || 'all',
      users: users.map((user) => ({
        id: user.id,
        login: user.login,
        displayName: user.displayName,
        email: user.email ?? '',
        status: user.status,
        systemRole: user.systemRole,
      })),
    });
  }

  private async userPage(actor: string, id: string, q: URLSearchParams): Promise<Result> {
    return this.admin(await this.users.detail(actor, id), ({ user, memberships }) =>
      page({
        page: 'user',
        user: {
          id: user.id,
          login: user.login,
          displayName: user.displayName,
          email: user.email ?? '',
          status: user.status,
          systemRole: user.systemRole,
          emailVerified: user.emailVerified,
          memberships: memberships.map((m) => ({
            organizationId: m.organizationSlug,
            slug: m.organizationSlug,
            name: m.organizationName,
            role: m.role,
          })),
        },
        banner: banner(q, {
          invited: 'invited',
          archived: 'archived',
          restored: 'restored',
          reset: 'password-reset',
          error: 'blocked',
        }),
        message: q.get('error'),
        showArchive: user.status !== 'archived',
        showRestore: user.status === 'archived',
        showPasswordReset: Boolean(user.email),
      }),
    );
  }

  private async organizationsPage(actor: string, q: URLSearchParams): Promise<Result> {
    const status = q.get('status') ?? '';
    const { rows, canCreate } = await this.organizations.list(
      actor,
      status === 'all' ? undefined : status,
    );
    return page({
      page: 'organizations',
      status: status || 'all',
      canCreate,
      organizations: rows.map((row) => ({
        id: row.organization.id,
        slug: row.organization.slug,
        name: row.organization.name,
        status: row.organization.archivedAt ? 'archived' : 'active',
        activeMemberCount: row.memberCount,
        activeClientCount: row.clientCount,
      })),
    });
  }

  private async organizationPage(actor: string, id: string, q: URLSearchParams): Promise<Result> {
    const detail = await this.organizations.detail(actor, id);
    if (detail.kind !== 'ok') return this.admin(detail, () => page({ page: 'not-found' }));
    const { organization, memberCount, clientCount, canArchive } = detail.value;
    const canEdit = await this.policy.authorized(actor, 'ORG_EDIT_SETTINGS', {
      orgSlug: organization.slug,
    });
    return page({
      page: 'organization',
      organization: {
        id: organization.id,
        slug: organization.slug,
        name: organization.name,
        status: organization.archivedAt ? 'archived' : 'active',
        activeMemberCount: memberCount,
        activeClientCount: clientCount,
        createdAt: organization.createdAt,
        memberCount,
      },
      banner: banner(q, { created: 'created', updated: 'saved', archived: 'archived' }),
      canEdit,
      canArchive,
    });
  }

  private async membershipsPage(actor: string, q: URLSearchParams): Promise<Result> {
    const orgSlug = q.get('orgSlug') ?? '';
    const { memberships, organizations } = await this.memberships.list(actor, orgSlug);
    return page({
      page: 'memberships',
      organizations: choices(organizations),
      organizationId: orgSlug,
      members: memberships.map((m) => ({
        organizationId: m.organizationSlug,
        userId: m.userId,
        login: m.userLogin,
        email: m.userEmail ?? '',
        role: m.role as MembershipRole,
      })),
      banner: banner(q, {
        added: 'added',
        changed: 'role-changed',
        removed: 'removed',
        error: 'blocked',
      }),
      error: null,
      message: q.get('error'),
    });
  }

  private async clientsPage(actor: string, q: URLSearchParams): Promise<Result> {
    const status = q.get('status') ?? '';
    const orgSlug = q.get('orgSlug') ?? '';
    const { clients, organizations } = await this.clients.list(actor, {
      orgSlug,
      status: status === 'all' ? null : status,
    });
    return page({
      page: 'clients',
      organizations: choices(organizations),
      organizationId: orgSlug,
      status: status || 'all',
      clients: clients.map((client) => ({
        id: client.clientId,
        organization: client.organizationSlug ?? '',
        name: client.clientName,
        status: client.revokedAt === null ? 'active' : 'revoked',
      })),
    });
  }

  private async clientPage(
    c: Context,
    actor: string,
    id: string,
    q: URLSearchParams,
  ): Promise<Result> {
    return this.admin(await this.clients.detail(actor, id), async (client: RegisteredClient) => {
      const reveal = c.active.session.attributes[SECRET_ATTRIBUTE];
      let secret: string | null = null;
      if (reveal) {
        const parsed = JSON.parse(reveal) as { clientId: string; secret: string };
        if (parsed.clientId === client.clientId) {
          secret = parsed.secret;
          c.active = await this.sessions.setAttribute(c.active, SECRET_ATTRIBUTE, null);
        }
      }
      return page({
        page: 'client',
        client: {
          id: client.clientId,
          organizationId: client.organizationSlug ?? '',
          organization: client.organizationSlug ?? '',
          name: client.clientName,
          status: client.revokedAt === null ? 'active' : 'revoked',
          redirectUris: client.redirectUris.join(', '),
          grantTypes: client.grantTypes.join(', '),
          scopes: client.scopes.join(', '),
        },
        banner: banner(q, {
          newSecret: 'registered',
          rotatedSecret: 'secret-rotated',
          updated: 'metadata-updated',
          revoked: 'revoked',
        }),
        secret,
        canModify: client.revokedAt === null,
      });
    });
  }

  private async auditPage(actor: string, q: URLSearchParams): Promise<Result> {
    const filters = {
      action: q.get('action') ?? '',
      actor: q.get('actor') ?? '',
      target: q.get('target') ?? '',
      from: q.get('from') ?? '',
      to: q.get('to') ?? '',
    };
    const records = await this.audits.list(actor, filters);
    return page({
      page: 'audit',
      count: records.length,
      filters,
      records: records.map((record) => ({
        id: record.id,
        timestamp: record.createdAt,
        action: record.action,
        actor: record.actorClientId ?? '',
        target: record.target ?? '',
      })),
    });
  }

  /** The new secret goes in the session for one page view, never in the URL. */
  private async revealThenRedirect(
    c: Context,
    result: AdminResult<{ clientId: string; secret: string }>,
    flag: string,
  ): Promise<Result> {
    return this.admin(result, async ({ clientId, secret }) => {
      c.active = await this.sessions.setAttribute(
        c.active,
        SECRET_ATTRIBUTE,
        JSON.stringify({ clientId, secret }),
      );
      return redirect(`/admin/oauth-clients/${clientId}?${flag}=1`);
    });
  }

  private async admin<T>(
    result: AdminResult<T>,
    ok: (value: T) => Result | Promise<Result>,
  ): Promise<Result> {
    if (result.kind === 'redirect') return redirect(result.location);
    if (result.kind === 'error') {
      return page({ page: 'error', title: result.title, message: result.message }, result.status);
    }
    return ok(result.value);
  }

  // ---- linked identities -------------------------------------------------------------------

  private async linkRoute(c: Context, path: string, get: boolean): Promise<Result> {
    const user = c.user as UserAccount;
    const caller: AccountCaller = {
      userId: user.id,
      sessionId: c.active.session.id,
      lastAuthenticatedAt: c.active.session.lastAuthenticatedAt,
    };
    const pendingToken = c.active.session.attributes[SESSION_ATTRIBUTES.pendingLink];
    const unavailable = (message: string | null) =>
      page({ page: 'link-unavailable', message }, 400);
    if (path === '/account/identity-links' && get) {
      const links = await this.links.views(user.id);
      return page({
        page: 'links',
        accountName: user.displayName || user.login,
        links: links.map((link) => ({
          id: link.id,
          issuer: link.issuer,
          subjectHint: link.subjectHint,
          provider: link.providerName,
          linkedAt: link.createdAt,
        })),
        banner: banner(c.url.searchParams, {
          linked: 'linked',
          unlinked: 'unlinked',
          canceled: 'canceled',
        }),
        error: null,
      });
    }
    if (path === '/account/identity-links/start' && get) {
      try {
        return redirect(
          await this.flows.start({
            userId: user.id,
            sessionId: c.active.session.id,
            provider: c.url.searchParams.get('provider') ?? '',
            issuer: c.url.searchParams.get('issuer'),
            returnUrl: c.url.searchParams.get('returnUrl'),
          }),
        );
      } catch (error) {
        return unavailable(error instanceof IdentityError ? error.message : null);
      }
    }
    if (path === '/account/identity-links/callback' && get) {
      const result = await this.flows.callback({
        userId: user.id,
        sessionId: c.active.session.id,
        state: c.url.searchParams.get('state'),
        code: c.url.searchParams.get('code'),
        error: c.url.searchParams.get('error'),
      });
      if (result.kind === 'error') return unavailable(result.message);
      c.active = await this.sessions.setAttribute(
        c.active,
        SESSION_ATTRIBUTES.pendingLink,
        result.token,
      );
      return redirect('/account/identity-links/confirm');
    }
    if (path === '/account/identity-links/confirm') {
      const token = (get ? c.url.searchParams.get('token') : c.form.get('token')) || pendingToken;
      if (get) {
        const pending = this.flows.pendingFor(token, user.id);
        if (!pending) {
          return unavailable(
            'This identity link confirmation request is invalid, expired, or bound to another account.',
          );
        }
        return page({
          page: 'link-confirm',
          token: pending.token,
          account: {
            displayName: user.displayName || user.login,
            login: user.login,
            email: user.email ?? '(no email)',
          },
          external: {
            provider: pending.providerName,
            issuer: pending.issuer,
            subjectHint: Hashing.sha256Hex(pending.subject).slice(0, 16),
            providerEmail: pending.providerEmail ?? '(none provided)',
          },
        });
      }
      const link = await this.flows.confirm(token, user.id);
      if (!link) return unavailable('The identity link confirmation is invalid or expired.');
      c.active = await this.sessions.setAttribute(c.active, SESSION_ATTRIBUTES.pendingLink, null);
      return redirect('/account/identity-links?linked=1');
    }
    if (path === '/account/identity-links/cancel' && !get) {
      this.flows.cancel(c.form.get('token') || pendingToken, user.id);
      c.active = await this.sessions.setAttribute(c.active, SESSION_ATTRIBUTES.pendingLink, null);
      return redirect('/account/identity-links?canceled=1');
    }
    if (path === '/account/identity-links/unlink/start' && !get) {
      const token = await this.links.startUnlink(caller, c.form.get('id') ?? '');
      if (token instanceof ServiceResult) {
        return token.status === 403
          ? page({ page: 'denied', reason: 'member' }, 403)
          : unavailable('This unlink confirmation is invalid or expired.');
      }
      c.active = await this.sessions.setAttribute(
        c.active,
        SESSION_ATTRIBUTES.unlinkConfirmation,
        token,
      );
      return redirect('/account/identity-links/unlink/confirm');
    }
    if (path === '/account/identity-links/unlink/confirm') {
      if (get) {
        const pending = await this.links.pendingUnlink(caller);
        if (!pending) return unavailable('This unlink confirmation is invalid or expired.');
        return page({
          page: 'unlink-confirm',
          provider: pending.providerName,
          issuer: pending.issuer,
          subjectHint: pending.subjectHint,
        });
      }
      const removed = await this.links.confirmUnlink(
        caller,
        c.active.session.attributes[SESSION_ATTRIBUTES.unlinkConfirmation],
      );
      if (!removed) return unavailable('The unlink confirmation is invalid or expired.');
      c.active = await this.sessions.setAttribute(
        c.active,
        SESSION_ATTRIBUTES.unlinkConfirmation,
        null,
      );
      return redirect('/account/identity-links?unlinked=1');
    }
    return page({ page: 'not-found' }, 404);
  }

  // ---- helpers ------------------------------------------------------------------------------

  /** Unauthenticated access: remember the page and send the browser to the login form. */
  private async loginRequired(c: Context): Promise<Result> {
    if (c.method === 'GET') {
      c.active = await this.sessions.setAttribute(
        c.active,
        SESSION_ATTRIBUTES.savedRequest,
        `${c.url.pathname}${c.url.search}`,
      );
      return { kind: 'page', page: { page: 'unauthenticated' }, status: 401 };
    }
    return redirect('/login');
  }

  private deniedReason(c: Context, error: AdminAccessDenied): DeniedReason {
    if (c.user?.status !== 'active') return 'inactive';
    return PLATFORM_ONLY.includes(error.capability) ? 'platform' : 'member';
  }

  /** The session's user in any status, as the auth server's session principal. */
  private directoryUser(id: string): Promise<UserAccount | undefined> {
    return this.container.resolve<DirectoryRepository>(DIRECTORY).findUser(id);
  }

  private sessionCookie(token: string): string {
    return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax${this.secure()}`;
  }

  private secure(): string {
    return this.settings.cookieSecure ? '; Secure' : '';
  }

  private get users() {
    return this.container.resolve(UserAdminService);
  }
  private get organizations() {
    return this.container.resolve(OrganizationAdminService);
  }
  private get memberships() {
    return this.container.resolve(MembershipAdminService);
  }
  private get clients() {
    return this.container.resolve(ClientAdminService);
  }
  private get audits() {
    return this.container.resolve(AuditAdminService);
  }
  private get links() {
    return this.container.resolve(LinkService);
  }
  private get flows() {
    return this.container.resolve(LinkFlowService);
  }
}

function choices(organizations: Organization[]): OrgChoice[] {
  return organizations.map((organization) => ({
    id: organization.slug,
    slug: organization.slug,
    name: organization.name,
  }));
}

function banner(q: URLSearchParams, flags: Record<string, BannerName>): BannerName | null {
  for (const [flag, name] of Object.entries(flags)) if (q.has(flag)) return name;
  return null;
}

export function cookie(header: string | null, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0 && part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return undefined;
}
