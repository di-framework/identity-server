import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { IdentityClient } from '../api/client.ts';
import { applyDirectory } from '../api/directory.ts';
import { createSession, findSession, type Outcome, type Store } from '../domain/model.ts';
import { submit, view } from '../domain/service.ts';
import { clearCookie, readCookie, writeCookie } from './cookies.ts';

const SESSION = 'identity_session';
const EMAIL = 'identity_email';

/** Source checkout first. A compiled binary serves `embedded/index.html`. */
export function indexDocument(moduleUrl: string = import.meta.url): URL {
  const source = new URL('../../index.html', moduleUrl);
  if (existsSync(fileURLToPath(source))) return source;
  return new URL('embedded/index.html', moduleUrl);
}

export async function handle(
  request: Request,
  store: Store,
  directory?: IdentityClient,
): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return new Response(null, { status: 405 });
  }
  const url = new URL(request.url);
  const incoming = readCookie(request.headers.get('cookie'), SESSION);
  const emailToken = readCookie(request.headers.get('cookie'), EMAIL);
  let session = findSession(store, incoming);
  const created = !session;
  if (!session) session = createSession(store, null, null);
  const form =
    request.method === 'POST' ? new URLSearchParams(await request.text()) : new URLSearchParams();
  const wantsJson = (request.headers.get('accept') ?? '').includes('application/json');
  const viewed =
    request.method === 'GET' ? view(store, session, emailToken, url, wantsJson) : undefined;
  const baseline: Outcome = viewed ?? { type: 'page', session };
  let outcome = baseline;
  if (directory) {
    const next = await applyDirectory(directory, {
      method: request.method,
      url,
      store,
      session,
      form,
      outcome: baseline,
      revealSecrets: wantsJson,
    });
    outcome =
      request.method === 'POST' && next === baseline
        ? submit(store, session, emailToken, url, form)
        : next;
  } else if (request.method === 'POST') {
    outcome = submit(store, session, emailToken, url, form);
  }
  const headers = new Headers();
  if (outcome.session === null) {
    headers.append('set-cookie', clearCookie(SESSION));
  } else if (created || outcome.session.id !== incoming) {
    headers.append('set-cookie', writeCookie(SESSION, outcome.session.id));
  }
  if (outcome.emailCookie !== undefined) {
    headers.append(
      'set-cookie',
      outcome.emailCookie === null
        ? clearCookie(EMAIL)
        : writeCookie(EMAIL, outcome.emailCookie, 15 * 60),
    );
  }
  if (outcome.type === 'redirect' && outcome.location) {
    headers.set('location', outcome.location);
    return new Response(null, { status: 303, headers });
  }
  if (outcome.type === 'login-required' && (request.method === 'POST' || !wantsJson)) {
    headers.set('location', '/login');
    return new Response(null, { status: request.method === 'POST' ? 303 : 302, headers });
  }
  if (request.method === 'GET' && !wantsJson) {
    headers.set('content-type', 'text/html; charset=utf-8');
    return new Response(await Bun.file(indexDocument()).text(), {
      status: outcome.status ?? 200,
      headers,
    });
  }
  headers.set('content-type', 'application/json; charset=utf-8');
  const status = outcome.type === 'login-required' ? 401 : (outcome.status ?? 200);
  return new Response(JSON.stringify(outcome.page), { status, headers });
}
