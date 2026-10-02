import { expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
