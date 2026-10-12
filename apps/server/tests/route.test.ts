import { expect, test } from 'bun:test';
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

test('column encryption that is enabled but unusable answers 503; other errors propagate', async () => {
  await useTestDatabase();
  const encryption = useContainer().resolve(ColumnEncryption);
  const fail = (error: Error) => {
    (encryption as unknown as { cipher: () => Promise<never> }).cipher = () =>
      Promise.reject(error);
  };
  try {
    fail(
      new ColumnEncryptionUnavailable(
        'column encryption is enabled but IDENTITY_COLUMN_KEY is not set',
      ),
    );
    const page = await routeRequest(new Request('https://identity.test/login'), new Map());
    expect(page.status).toBe(503);
    expect(await page.json()).toEqual({
      ok: false,
      error: 'column encryption is enabled but IDENTITY_COLUMN_KEY is not set',
    });
    const token = await routeRequest(
      new Request('https://identity.test/oauth2/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=authorization_code&code=x&client_id=nobody',
      }),
      new Map(),
    );
    expect([400, 401, 503]).toContain(token.status);
    fail(new Error('boom'));
    await expect(
      routeRequest(new Request('https://identity.test/login'), new Map()),
    ).rejects.toThrow('boom');
  } finally {
    delete (encryption as unknown as { cipher?: unknown }).cipher;
  }
});
