import { registerAuth } from '@di-framework/auth';
import {
  createAuthRoutes,
  privateJson,
  withAuthErrors,
  withAuthRoutes,
} from '@di-framework/auth/http';
import { Container } from '@di-framework/core';
import { json, TypedRouter } from '@di-framework/http';

export function createExampleApp(options: { secret: string; issuer: string }): {
  fetch(request: Request): Promise<Response>;
} {
  const container = new Container();
  registerAuth({
    container,
    secret: options.secret,
    jwt: {
      issuer: options.issuer,
      audience: 'example',
      symmetric: true,
    },
    password: { minLength: 15 },
  });

  const router = TypedRouter({
    catch: withAuthErrors({ log: () => undefined, fallback: authFailure }),
  });
  const auth = createAuthRoutes({
    container,
    enable: { oauth: false, webauthn: false },
  });
  router.all('/auth/*', async (request: Request) => {
    const url = new URL(request.url);
    const pathname = url.pathname.slice('/auth'.length);
    url.pathname = pathname.startsWith('/') ? pathname : `/${pathname}`;
    const body =
      request.method === 'GET' || request.method === 'HEAD'
        ? undefined
        : await request.arrayBuffer();
    return auth.fetch(
      new Request(url.toString(), {
        method: request.method,
        headers: request.headers,
        body,
      }),
    );
  });

  router.get('/health', () => json({ ok: true }));

  const secure = withAuthRoutes(router, { container });
  secure.get('/me', (request) => privateJson({ sub: request.principal.sub }));

  return {
    fetch: (request) => router.fetch(request),
  };
}

/** Client-facing failure for a compiled binary, where `instanceof AuthError` can miss. */
export function authFailure(error: unknown): Response {
  const record = typeof error === 'object' && error !== null ? error : undefined;
  const status =
    record && 'status' in record && typeof record.status === 'number' ? record.status : 500;
  const publicMessage =
    record && 'publicMessage' in record && typeof record.publicMessage === 'string'
      ? record.publicMessage
      : undefined;
  if (publicMessage && status < 500) {
    return new Response(JSON.stringify({ error: publicMessage, status }), {
      status,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
      },
    });
  }
  console.error(error);
  return new Response(JSON.stringify({ error: 'Internal Server Error', status: 500 }), {
    status: 500,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}
