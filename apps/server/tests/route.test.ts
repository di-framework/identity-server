import { expect, spyOn, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { useContainer } from '@di-framework/core/container';
import {
  ColumnEncryption,
  ColumnEncryptionUnavailable,
} from '../../../packages/core/src/shared/infrastructure/column-encryption.ts';
import { useTestDatabase } from '../../../packages/core/tests/support/database.ts';
import { routeRequest } from '../src/serve.ts';

test('serves the JSON API, OAuth metadata, browser pages, and assets from one router', async () => {
  await useTestDatabase();
  const directory = await mkdtemp(join(tmpdir(), 'identity-assets-'));
  const assets = new URL(`${directory}/`, 'file:');
  await writeFile(new URL('main.js', assets), 'console.log(1)\n');

  const api = await routeRequest(new Request('https://identity.test/api/admin/users'), assets);
  expect(api.status).toBe(401);
  expect(api.headers.get('www-authenticate')).toBe('Bearer');
  const discovery = await routeRequest(
    new Request('https://identity.test/.well-known/openid-configuration'),
    assets,
  );
  expect(((await discovery.json()) as { issuer: string }).issuer).toBe('https://identity.test');

  const page = await routeRequest(new Request('https://identity.test/login'), assets);
  expect(page.headers.get('content-type')).toContain('text/html');
  expect(await page.text()).toContain('<title>Identity</title>');

  const file = await routeRequest(new Request('https://identity.test/assets/main.js'), assets);
  expect(await file.text()).toBe('console.log(1)\n');
  expect(
    (await routeRequest(new Request('https://identity.test/assets/missing.js'), assets)).status,
  ).toBe(404);
  expect(
    (await routeRequest(new Request('https://identity.test/assets/nested/file.js'), assets)).status,
  ).toBe(404);
});

test('column encryption that is enabled but unusable answers 503; other errors are a generic 500', async () => {
  await useTestDatabase();
  const encryption = useContainer().resolve(ColumnEncryption);
  const fail = (error: Error) => {
    (encryption as unknown as { cipher: () => Promise<never> }).cipher = () =>
      Promise.reject(error);
  };
  const lines: string[] = [];
  const log = spyOn(console, 'error').mockImplementation((line: unknown) => {
    lines.push(String(line));
  });
  try {
    fail(
      new ColumnEncryptionUnavailable(
        'column encryption is enabled but IDENTITY_COLUMN_KEY is not set',
      ),
    );
    const page = await routeRequest(new Request('https://identity.test/login'), new Map());
    expect(page.status).toBe(503);
    expect(page.headers.get('cache-control')).toBe('no-store');
    // Generic body: which setting is missing goes to the log only.
    expect(await page.json()).toEqual({ ok: false, error: 'service unavailable' });
    fail(new Error('boom'));
    const failed = await routeRequest(new Request('https://identity.test/login'), new Map());
    expect(failed.status).toBe(500);
    expect(await failed.json()).toEqual({ ok: false, error: 'internal error' });
    expect(lines.join('\n')).toContain('IDENTITY_COLUMN_KEY is not set');
    expect(lines.join('\n')).toContain('request /login failed: boom');
  } finally {
    log.mockRestore();
    delete (encryption as unknown as { cipher?: unknown }).cipher;
  }
});
