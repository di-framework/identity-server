import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { PageModel } from '../domain/page-model.ts';
import { WebApp } from './web-app.ts';

/** Source checkout first. A compiled binary serves `embedded/index.html`. */
export function indexDocument(moduleUrl: string = import.meta.url): URL {
  const source = new URL('../../index.html', moduleUrl);
  if (existsSync(fileURLToPath(source))) return source;
  return new URL('embedded/index.html', moduleUrl);
}

/** JSON safe to place inside a `<script>` element. */
export function scriptJson(value: unknown): string {
  return JSON.stringify(value)
    .replaceAll('<', '\\u003c')
    .replaceAll('>', '\\u003e')
    .replaceAll('&', '\\u0026')
    .replaceAll(' ', '\\u2028')
    .replaceAll(' ', '\\u2029');
}

const app = new WebApp();

/**
 * Browser pages. A request that accepts JSON gets the page model; any other GET or a form POST
 * gets the HTML shell with the page model embedded, so a failed form post keeps the auth
 * server's status code without a redirect.
 */
export async function handle(request: Request, web: WebApp = app): Promise<Response> {
  if (request.method !== 'GET' && request.method !== 'POST') {
    return new Response(null, { status: 405, headers: { allow: 'GET, POST' } });
  }
  const { result, cookies, actor } = await web.run(request);
  const headers = new Headers();
  for (const value of cookies) headers.append('set-cookie', value);
  headers.set('cache-control', 'no-store');
  if (result.kind === 'redirect') {
    headers.set('location', result.location);
    return new Response(null, { status: result.status ?? 303, headers });
  }
  const wantsJson = (request.headers.get('accept') ?? '').includes('application/json');
  const model = { ...actor, ...result.page } as PageModel;
  if (model.page === 'unauthenticated' && !wantsJson) {
    headers.set('location', '/login');
    return new Response(null, { status: 302, headers });
  }
  if (wantsJson) {
    headers.set('content-type', 'application/json; charset=utf-8');
    return new Response(JSON.stringify(model), { status: result.status ?? 200, headers });
  }
  headers.set('content-type', 'text/html; charset=utf-8');
  const shell = await Bun.file(indexDocument()).text();
  const html = shell.replace(
    '<div id="root"></div>',
    `<div id="root"></div>\n    <script>window.__IDENTITY_PAGE__ = ${scriptJson(model)};</script>`,
  );
  return new Response(html, { status: result.status ?? 200, headers });
}
