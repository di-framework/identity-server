import { Hashing } from '../../../../packages/core/src/shared/infrastructure/crypto/hashing.ts';
import { Browser } from '../../../server/tests/support/browser.ts';

/**
 * End-to-end identity flows that touch the database, written against a `fetch`-shaped handler so
 * the same steps run in-process (`boot.test.ts`, on the in-process PGlite) and against a deployed
 * guest (`apps/guest/scripts/live-check.ts`). Each step throws with what it saw; no step prints
 * or returns a secret.
 */
export interface FlowInputs {
  fetch: (request: Request) => Promise<Response>;
  ownerLogin: string;
  ownerPassword: string;
  accessClient: { id: string; secret: string; redirectUri: string };
  provisionerClient: { id: string; secret: string };
  /** Slug of the organization the admin flow creates; must not exist yet. */
  organizationSlug: string;
}

export interface FlowReport {
  ready: Record<string, unknown>;
  organization: { created: number; duplicate: number; read: number; name: unknown };
  login: { signIn: number; consent: number; token: number; userinfo: number; subject: string };
}

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export async function readiness(
  fetch: FlowInputs['fetch'],
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await fetch(new Request('https://identity.test/ready'));
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

/** Client credentials as the provisioner, then an organization write and read through the API. */
export async function organizationFlow(inputs: FlowInputs): Promise<FlowReport['organization']> {
  const token = await inputs.fetch(
    new Request('https://identity.test/oauth2/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: basic(inputs.provisionerClient.id, inputs.provisionerClient.secret),
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'admin:read admin:write',
      }),
    }),
  );
  check(token.status === 200, `client_credentials token: HTTP ${token.status}`);
  const { access_token: accessToken } = (await token.json()) as { access_token: string };
  const admin = (method: string, path: string, body?: unknown) =>
    inputs.fetch(
      new Request(`https://identity.test/api/admin${path}`, {
        method,
        headers: {
          authorization: `Bearer ${accessToken}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    );
  const slug = inputs.organizationSlug;
  const created = await admin('POST', '/organizations', { slug, name: `Org ${slug}` });
  check(created.status === 201, `create organization: HTTP ${created.status}`);
  const duplicate = await admin('POST', '/organizations', { slug, name: 'Again' });
  check(duplicate.status === 409, `duplicate organization: HTTP ${duplicate.status}`);
  const read = await admin('GET', `/organizations/${slug}`);
  check(read.status === 200, `read organization: HTTP ${read.status}`);
  const body = (await read.json()) as { name?: unknown; organization?: { name?: unknown } };
  return {
    created: created.status,
    duplicate: duplicate.status,
    read: read.status,
    name: body.organization?.name ?? body.name,
  };
}

/** The owner signs in, consents, and the access client exchanges the code (PKCE) for tokens. */
export async function loginFlow(inputs: FlowInputs): Promise<FlowReport['login']> {
  const browser = new Browser(inputs.fetch);
  const signIn = await browser.signIn(inputs.ownerLogin, inputs.ownerPassword);
  check(signIn.status === 303, `sign-in: HTTP ${signIn.status}`);
  const verifier = Hashing.token();
  const authorize = `/oauth2/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: inputs.accessClient.id,
    redirect_uri: inputs.accessClient.redirectUri,
    scope: 'openid profile',
    state: 'live-state',
    code_challenge: Hashing.pkceChallenge(verifier),
    code_challenge_method: 'S256',
  })}`;
  const first = await browser.send('GET', authorize);
  let location = first.headers.get('location') ?? '';
  let consentStatus = 0;
  if (new URL(location, 'https://identity.test').pathname === '/oauth2/consent') {
    const consentUrl = new URL(location, 'https://identity.test');
    const consent = await browser.page<{ state: string }>(
      `${consentUrl.pathname}${consentUrl.search}`,
    );
    const approved = await browser.send('POST', '/oauth2/authorize', {
      form: {
        client_id: inputs.accessClient.id,
        state: consent.state,
        scope: ['openid', 'profile'],
      },
    });
    consentStatus = approved.status;
    location = approved.headers.get('location') ?? '';
  }
  const callback = new URL(location, 'https://identity.test');
  const code = callback.searchParams.get('code');
  check(
    code && callback.searchParams.get('state') === 'live-state',
    `authorize did not redirect with a code (HTTP ${first.status})`,
  );
  const token = await inputs.fetch(
    new Request('https://identity.test/oauth2/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: basic(inputs.accessClient.id, inputs.accessClient.secret),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: inputs.accessClient.redirectUri,
        code_verifier: verifier,
      }),
    }),
  );
  check(token.status === 200, `code exchange: HTTP ${token.status}`);
  const tokens = (await token.json()) as { access_token: string; id_token?: string };
  check(tokens.id_token, 'code exchange returned no ID token');
  const userinfo = await inputs.fetch(
    new Request('https://identity.test/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    }),
  );
  check(userinfo.status === 200, `userinfo: HTTP ${userinfo.status}`);
  const claims = (await userinfo.json()) as { sub?: string; preferred_username?: string };
  check(
    claims.preferred_username === inputs.ownerLogin,
    `userinfo names ${claims.preferred_username}`,
  );
  return {
    signIn: signIn.status,
    consent: consentStatus,
    token: token.status,
    userinfo: userinfo.status,
    subject: String(claims.sub),
  };
}

export async function identityFlows(inputs: FlowInputs): Promise<FlowReport> {
  const ready = await readiness(inputs.fetch);
  check(ready.status === 200, `ready: HTTP ${ready.status} ${JSON.stringify(ready.body)}`);
  return {
    ready: ready.body,
    organization: await organizationFlow(inputs),
    login: await loginFlow(inputs),
  };
}
