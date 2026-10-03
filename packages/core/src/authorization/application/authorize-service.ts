import { Component, Container } from '@di-framework/core/decorators';
import type { Clock } from '../../shared/domain/clock.ts';
import { AUTHORIZATIONS, CLOCK, REGISTERED_CLIENTS } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';
import {
  type Authorization,
  type AuthorizationRepository,
  type RegisteredClient,
  type RegisteredClientRepository,
  TOKEN_SETTINGS,
} from '../domain/models.ts';

/** Signed-in browser user, from the session. */
export interface AuthorizeUser {
  userId: string;
  /** Epoch ms of the session's last sign-in, written as `auth_time`. */
  authenticatedAt: number;
  /** Whether the account is active. Sessions of archived or pending users get no codes. */
  active: boolean;
}

export type AuthorizeResult =
  /**
   * Send the browser to the login page, then back to `/oauth2/authorize?{resume}`. `resume` is
   * the request without `prompt` and `max_age` when a fresh sign-in was required, so the request
   * succeeds once the user has signed in again. Absent for the consent `POST`.
   */
  | { kind: 'login'; resume?: string }
  /** Redirect to the client, or to the consent page. */
  | { kind: 'redirect'; location: string }
  /** The client or redirect URI cannot be trusted, so the error is shown, not redirected. */
  | { kind: 'error'; message: string };

/**
 * `GET /oauth2/authorize` and the consent `POST` (Spring Authorization Server's authorization
 * endpoint as configured by the auth server): code flow only, PKCE S256 when the client requires
 * it, consent stored in `oauth2_authorization_consent`, and 60-second codes.
 */
@Container()
export class AuthorizeService {
  constructor(
    @Component(REGISTERED_CLIENTS) private readonly clients: RegisteredClientRepository,
    @Component(AUTHORIZATIONS) private readonly authorizations: AuthorizationRepository,
    @Component(CLOCK) private readonly clock: Clock,
  ) {}

  async authorize(
    params: URLSearchParams,
    user: AuthorizeUser | undefined,
  ): Promise<AuthorizeResult> {
    const client = await this.clients.find(params.get('client_id') ?? '');
    if (!client || client.revokedAt !== null || !client.grantTypes.includes('authorization_code')) {
      return { kind: 'error', message: 'The client is not valid.' };
    }
    const redirectUri = this.redirectUri(client, params.get('redirect_uri'));
    if (!redirectUri) return { kind: 'error', message: 'The redirect URI is not valid.' };
    const state = params.get('state');
    const fail = (error: string) => ({
      kind: 'redirect' as const,
      location: withQuery(redirectUri, { error, state }),
    });
    if (params.get('response_type') !== 'code') return fail('unsupported_response_type');
    const scopes = [...new Set((params.get('scope') ?? '').split(' ').filter(Boolean))];
    if (scopes.some((scope) => !client.scopes.includes(scope))) return fail('invalid_scope');
    const challenge = params.get('code_challenge');
    const method = params.get('code_challenge_method');
    if (challenge ? method !== 'S256' : client.settings.requireProofKey)
      return fail('invalid_request');
    const prompt = (params.get('prompt') ?? '').split(' ').filter(Boolean);
    const maxAge = params.get('max_age');
    if (maxAge !== null && !/^\d+$/.test(maxAge)) return fail('invalid_request');
    // The sign-in a login redirect leads to is fresh by definition, so the resumed request drops
    // `prompt` and `max_age` (otherwise `max_age=0` would ask for a second sign-in).
    const fresh = new URLSearchParams(params);
    fresh.delete('prompt');
    fresh.delete('max_age');
    if (!user) return prompt.includes('none') ? fail('login_required') : login(fresh);
    if (!user.active) return fail('access_denied');
    // OpenID Connect `prompt=login` and `max_age` ask for a sign-in newer than the session's.
    const stale =
      prompt.includes('login') ||
      (maxAge !== null && this.clock.now() - user.authenticatedAt > Number(maxAge) * 1000);
    if (stale) return prompt.includes('none') ? fail('login_required') : login(fresh);

    const attributes = {
      redirect_uri: redirectUri,
      requested_redirect_uri: params.get('redirect_uri'),
      scopes,
      state,
      code_challenge: challenge,
      nonce: params.get('nonce'),
      auth_time: user.authenticatedAt,
    };
    const askFor = scopes.filter((scope) => scope !== 'openid');
    const consented = await this.authorizations.findConsent(client.id, user.userId);
    if (
      client.settings.requireAuthorizationConsent &&
      askFor.some((scope) => !consented.includes(scope))
    ) {
      const consentState = Hashing.token();
      await this.authorizations.save(
        this.pending(client, user.userId, attributes, Hashing.sha256Hex(consentState)),
      );
      return {
        kind: 'redirect',
        location: withQuery('/oauth2/consent', {
          client_id: client.clientId,
          scope: scopes.join(' '),
          state: consentState,
        }),
      };
    }
    return this.issue(this.pending(client, user.userId, attributes, null), scopes);
  }

  /** The consent form posts `client_id`, the consent `state`, and the approved `scope` values. */
  async consent(form: URLSearchParams, user: AuthorizeUser | undefined): Promise<AuthorizeResult> {
    if (!user) return { kind: 'login' };
    if (!user.active) return { kind: 'error', message: 'The consent request is not valid.' };
    const consentState = form.get('state') ?? '';
    const pending = consentState
      ? await this.authorizations.findByState(Hashing.sha256Hex(consentState))
      : undefined;
    const client = await this.clients.find(form.get('client_id') ?? '');
    if (
      !pending ||
      !client ||
      pending.registeredClientId !== client.id ||
      pending.principalName !== user.userId
    ) {
      return { kind: 'error', message: 'The consent request is not valid.' };
    }
    const attributes = pending.attributes as {
      redirect_uri: string;
      scopes: string[];
      state: string | null;
    };
    const approved = form
      .getAll('scope')
      .filter((scope) => attributes.scopes.includes(scope) && scope !== 'openid');
    if (approved.length === 0) {
      await this.authorizations.delete(pending.id);
      return {
        kind: 'redirect',
        location: withQuery(attributes.redirect_uri, {
          error: 'access_denied',
          state: attributes.state,
        }),
      };
    }
    const previous = await this.authorizations.findConsent(client.id, user.userId);
    await this.authorizations.saveConsent(client.id, user.userId, [
      ...new Set([...previous, ...approved]),
    ]);
    const granted = attributes.scopes.includes('openid') ? ['openid', ...approved] : approved;
    return this.issue({ ...pending, state: null }, granted);
  }

  private async issue(authorization: Authorization, scopes: string[]): Promise<AuthorizeResult> {
    const code = Hashing.token();
    const now = this.clock.now();
    await this.authorizations.save({
      ...authorization,
      authorizedScopes: scopes,
      code: {
        hash: Hashing.sha256Hex(code),
        issuedAt: now,
        expiresAt: now + TOKEN_SETTINGS.authorizationCodeTtlSeconds * 1000,
        invalidated: false,
      },
    });
    const attributes = authorization.attributes as { redirect_uri: string; state: string | null };
    return {
      kind: 'redirect',
      location: withQuery(attributes.redirect_uri, { code, state: attributes.state }),
    };
  }

  private pending(
    client: RegisteredClient,
    userId: string,
    attributes: Record<string, unknown>,
    state: string | null,
  ): Authorization {
    return {
      id: crypto.randomUUID(),
      registeredClientId: client.id,
      principalName: userId,
      grantType: 'authorization_code',
      authorizedScopes: [],
      attributes,
      state,
      code: null,
      access: null,
      refresh: null,
      idToken: null,
    };
  }

  /** Exact match, or the single registered URI when the request omits it. */
  private redirectUri(client: RegisteredClient, requested: string | null): string | undefined {
    if (requested === null)
      return client.redirectUris.length === 1 ? client.redirectUris[0] : undefined;
    return client.redirectUris.includes(requested) ? requested : undefined;
  }
}

function login(params: URLSearchParams): AuthorizeResult {
  return { kind: 'login', resume: params.toString() };
}

function withQuery(base: string, params: Record<string, string | null>): string {
  const url = new URL(base, 'http://relative.invalid');
  for (const [key, value] of Object.entries(params))
    if (value !== null) url.searchParams.set(key, value);
  return url.origin === 'http://relative.invalid' ? `${url.pathname}${url.search}` : url.toString();
}
