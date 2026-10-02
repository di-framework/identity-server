import { expect, test } from 'bun:test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { systemClock } from '../../client/src/domain/clock.ts';
import { createStore } from '../../client/src/domain/model.ts';
import { routeRequest } from '../src/serve.ts';

test('serves the JSON API, browser pages, and assets from one router', async () => {
  const store = createStore(systemClock());
  const directory = await mkdtemp(join(tmpdir(), 'identity-assets-'));
  const assets = new URL(`${directory}/`, 'file:');
  await writeFile(new URL('main.js', assets), 'console.log(1)\n');

  const api = await routeRequest(
    new Request('https://identity.test/api/admin/users'),
    store,
    assets,
  );
  expect(api.headers.get('content-type')).toContain('application/json');
  const payload: unknown = await api.json();
  const apiBody = payload as { error?: unknown } | unknown[];
  expect(Array.isArray(apiBody) || typeof apiBody.error === 'string').toBe(true);

  const page = await routeRequest(new Request('https://identity.test/login'), store, assets);
  expect(page.headers.get('content-type')).toContain('text/html');
  expect(await page.text()).toContain('<title>Identity</title>');

  const file = await routeRequest(
    new Request('https://identity.test/assets/main.js'),
    store,
    assets,
  );
  expect(await file.text()).toBe('console.log(1)\n');

  const missing = await routeRequest(
    new Request('https://identity.test/assets/missing.js'),
    store,
    assets,
  );
  expect(missing.status).toBe(404);

  const rejected = await routeRequest(
    new Request('https://identity.test/assets/nested/file.js'),
    store,
    assets,
  );
  expect(rejected.status).toBe(404);
});
