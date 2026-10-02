import { createExampleApp } from './app.ts';

const secret = process.env.AUTH_SECRET ?? '';
if (secret.length < 32) {
  console.error('AUTH_SECRET must be at least 32 characters');
  process.exit(1);
}

const app = createExampleApp({
  secret,
  issuer: process.env.AUTH_ISSUER ?? 'http://127.0.0.1:3000',
});

const port = Number(process.env.PORT ?? 3000);
const server = Bun.serve({
  hostname: '0.0.0.0',
  port,
  fetch: (request) => app.fetch(request),
});

console.log(`example http://0.0.0.0:${server.port}`);
