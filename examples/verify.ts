const identityUrl = process.env.IDENTITY_URL ?? 'http://127.0.0.1:4180';
const appUrl = process.env.APP_URL ?? 'http://127.0.0.1:3000';
const password = 'correct horse battery staple';
const failures: string[] = [];

function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) {
    failures.push(detail ? `${name}: ${detail}` : name);
    console.error(`fail ${name}${detail ? ` (${detail})` : ''}`);
    return;
  }
  console.log(`ok ${name}`);
}

function cookies(response: Response): string[] {
  return typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
}

function named(response: Response, name: string): string | undefined {
  return cookies(response).find((header) => header.startsWith(`${name}=`));
}

function attributes(header: string): string[] {
  return header
    .split(';')
    .slice(1)
    .map((part) => part.trim().toLowerCase());
}

function pair(header: string): string {
  const first = header.split(';', 1)[0] ?? '';
  return first.trim();
}

async function waitFor(
  url: string,
  ready: (response: Response) => Promise<boolean>,
): Promise<void> {
  const deadline = Date.now() + 60_000;
  let last = 'not started';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (await ready(response)) return;
      last = `status ${response.status}`;
    } catch (error) {
      last = error instanceof Error ? error.message : 'request failed';
    }
    await Bun.sleep(500);
  }
  throw new Error(`${url} did not become ready (${last})`);
}

async function main(): Promise<void> {
  await waitFor(`${identityUrl}/api/admin/users`, async (response) => {
    if (!response.ok) return false;
    const body: unknown = await response.json();
    return Array.isArray(body);
  });
  await waitFor(`${appUrl}/health`, async (response) => response.ok);

  const loginPage = await fetch(`${identityUrl}/login`, {
    headers: { accept: 'application/json' },
  });
  const loginBody = (await loginPage.json()) as { csrf?: string; page?: string };
  const anonymous = named(loginPage, 'identity_session');
  check(
    'identity login page is the sign-in model',
    loginBody.page === 'login' && Boolean(loginBody.csrf),
  );
  check(
    'identity session cookie is HttpOnly, Path=/, and SameSite=Lax',
    anonymous !== undefined &&
      attributes(anonymous).includes('httponly') &&
      attributes(anonymous).includes('path=/') &&
      attributes(anonymous).includes('samesite=lax'),
  );

  const rejected = await fetch(`${identityUrl}/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: anonymous ? pair(anonymous) : '',
    },
    body: new URLSearchParams({
      identifier: 'ada@identity.example',
      password: 'platform-admin-pass',
      _csrf: 'not-the-token',
    }),
    redirect: 'manual',
  });
  check(
    'identity sign-in without the CSRF token stays on the login page',
    rejected.status === 303 && rejected.headers.get('location') === '/login',
  );

  const signedIn = await fetch(`${identityUrl}/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: anonymous ? pair(anonymous) : '',
    },
    body: new URLSearchParams({
      identifier: 'ada@identity.example',
      password: 'platform-admin-pass',
      _csrf: loginBody.csrf ?? '',
    }),
    redirect: 'manual',
  });
  const session = named(signedIn, 'identity_session');
  check(
    'identity sign-in with the CSRF token starts a session',
    signedIn.status === 303 &&
      signedIn.headers.get('location') === '/account/identity-links' &&
      session !== undefined &&
      pair(session) !== (anonymous ? pair(anonymous) : ''),
  );
  const users = await fetch(`${identityUrl}/admin/users`, {
    headers: { accept: 'application/json', cookie: session ? pair(session) : '' },
  });
  const usersBody = (await users.json()) as { page?: string };
  check('identity session can open the user list', users.ok && usersBody.page === 'users');

  const weak = await fetch(`${appUrl}/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier: 'weak@example.com', password: 'too-short' }),
  });
  const weakText = await weak.text();
  check(
    'example app rejects a short password',
    weak.status === 400 && !weakText.includes('too-short'),
  );

  const identifier = `person-${Date.now()}@example.com`;
  const registered = await fetch(`${appUrl}/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier, password }),
  });
  const registeredText = await registered.text();
  const sid = named(registered, '__Host-sid');
  const registeredBody = JSON.parse(registeredText) as { principal?: { sub?: string } };
  check(
    'example app session cookie is a __Host- cookie',
    registered.ok &&
      sid !== undefined &&
      attributes(sid).includes('httponly') &&
      attributes(sid).includes('secure') &&
      attributes(sid).includes('path=/') &&
      attributes(sid).includes('samesite=lax') &&
      !attributes(sid).some((item) => item.startsWith('domain')),
  );
  check(
    'example app registration response hides the password',
    Boolean(registeredBody.principal?.sub) && !registeredText.includes(password),
  );

  const anonymousMe = await fetch(`${appUrl}/me`);
  check('example app /me rejects a missing session', anonymousMe.status === 401);

  const me = await fetch(`${appUrl}/me`, { headers: { cookie: sid ? pair(sid) : '' } });
  const meBody = (await me.json()) as { sub?: string };
  check(
    'example app /me accepts the session and is not cached',
    me.ok &&
      meBody.sub === registeredBody.principal?.sub &&
      me.headers.get('cache-control') === 'no-store',
  );

  const forged = await fetch(`${appUrl}/me`, { headers: { cookie: '__Host-sid=forged' } });
  check('example app /me rejects a forged session cookie', forged.status === 401);

  const badPassword = await fetch(`${appUrl}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier, password: 'not-the-password' }),
  });
  const badText = await badPassword.text();
  check(
    'example app login rejects a wrong password without a session cookie',
    badPassword.status === 401 &&
      named(badPassword, '__Host-sid') === undefined &&
      badText.includes('Invalid credentials') &&
      !badText.includes('Password mismatch'),
  );

  const loggedOut = await fetch(`${appUrl}/auth/logout`, {
    method: 'POST',
    headers: { cookie: sid ? pair(sid) : '', 'content-type': 'application/json' },
    body: '{}',
  });
  const cleared = named(loggedOut, '__Host-sid');
  const afterLogout = await fetch(`${appUrl}/me`, { headers: { cookie: sid ? pair(sid) : '' } });
  check(
    'example app logout revokes the session',
    loggedOut.status === 204 &&
      cleared !== undefined &&
      attributes(cleared).includes('max-age=0') &&
      afterLogout.status === 401,
  );

  if (failures.length > 0) {
    console.error(`${failures.length} check${failures.length === 1 ? '' : 's'} failed`);
    process.exit(1);
  }
  console.log('auth stack checks passed');
}

await main();
