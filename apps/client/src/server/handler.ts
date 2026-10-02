import { createSession, findSession, type Store } from '../domain/model.ts';
import { submit, view } from '../domain/service.ts';
import { clearCookie, readCookie, writeCookie } from './cookies.ts';

const SESSION = 'identity_session';
const EMAIL = 'identity_email';
const INDEX = new URL('../../index.html', import.meta.url);

export async function handle(request: Request, store: Store): Promise<Response> {
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
  const outcome =
    request.method === 'POST'
      ? submit(store, session, emailToken, url, form)
      : view(store, session, emailToken, url, wantsJson);
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
    return new Response(await Bun.file(INDEX).text(), { status: outcome.status ?? 200, headers });
  }
  headers.set('content-type', 'application/json; charset=utf-8');
  const status = outcome.type === 'login-required' ? 401 : (outcome.status ?? 200);
  return new Response(JSON.stringify(outcome.page), { status, headers });
}
