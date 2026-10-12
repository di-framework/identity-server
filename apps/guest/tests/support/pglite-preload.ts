import { afterAll } from 'bun:test';
import { OPEN_TEST_PGLITE } from './pglite.ts';

/** bunfig.pglite.toml preload: closes the shared PGlite from `openTestPglite` after the run. */
afterAll(async () => {
  const close = (globalThis as Record<symbol, unknown>)[OPEN_TEST_PGLITE];
  if (typeof close === 'function') await close();
});
