import { registerAuth } from '@di-framework/auth';
import {
  createAuthRoutes,
  privateJson,
  withAuthErrors,
  withAuthRoutes,
} from '@di-framework/auth/http';
import { json, TypedRouter } from '@di-framework/http';

const secret = process.env.AUTH_SECRET ?? '';
if (secret.length < 32) {
  console.error('AUTH_SECRET must be at least 32 characters');
  process.exit(1);
}

registerAuth({
  secret,
  jwt: {
    issuer: process.env.AUTH_ISSUER ?? 'http://127.0.0.1:3000',
    audience: 'example',
    symmetric: true,
  },
  password: { minLength: 15 },
});

const router = TypedRouter({
  catch: withAuthErrors({ log: () => undefined, fallback: authFailure }),
});
const auth = createAuthRoutes({ enable: { oauth: false, webauthn: false } });
router.all('/auth/*', async (request: Request) => {
  const url = new URL(request.url);
  const pathname = url.pathname.slice('/auth'.length);
  url.pathname = pathname.startsWith('/') ? pathname : `/${pathname}`;
  const body =
    request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.arrayBuffer();
  return auth.fetch(
    new Request(url.toString(), {
      method: request.method,
      headers: request.headers,
      body,
    }),
  );
});

router.get('/health', () => json({ ok: true }));

const secure = withAuthRoutes(router);
secure.get('/me', (request) => privateJson({ sub: request.principal.sub }));

const port = Number(process.env.PORT ?? 3000);
const server = Bun.serve({
  hostname: '0.0.0.0',
  port,
  fetch: (request) => router.fetch(request),
});

console.log(`example http://0.0.0.0:${server.port}`);

function authFailure(error: unknown): Response {
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
