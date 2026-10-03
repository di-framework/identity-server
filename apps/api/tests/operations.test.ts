import { beforeAll, expect, test } from 'bun:test';
import { useTestDatabase } from '@di-framework/identity/tests/support/database.ts';
import { controlPlane } from '../src/control-plane.ts';

beforeAll(async () => {
  await useTestDatabase();
});

test('GET /health is always ok', async () => {
  const response = await controlPlane.fetch(new Request('https://identity.test/health'));
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ ok: true });
  expect(controlPlane.handles('/health')).toBe(true);
  expect(controlPlane.handles('/ready')).toBe(true);
});

test('GET /ready is 503 until SMTP is configured and bootstrap has run, without echoing values', async () => {
  const response = await controlPlane.fetch(new Request('https://identity.test/ready'));
  expect(response.status).toBe(503);
  const text = await response.text();
  expect(JSON.parse(text)).toEqual({
    database: true,
    signing_key: true,
    smtp: false,
    bootstrap: false,
    ok: false,
  });
  expect(text).not.toContain('identity.test');
});

test('operations endpoints are GET only', async () => {
  const response = await controlPlane.fetch(
    new Request('https://identity.test/health', { method: 'POST' }),
  );
  expect(response.status).toBe(405);
  expect(response.headers.get('allow')).toBe('GET');
});
