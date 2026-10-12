import { expect, test } from 'bun:test';
import { SECRET_FLASH_TTL_MS, SecretFlash } from '../src/sessions/application/secret-flash.ts';
import { manualClock } from '../src/shared/domain/clock.ts';

test('a flashed secret is taken once, per session and scope, before it expires', () => {
  const clock = manualClock(1_000);
  const flash = new SecretFlash(clock);
  flash.put('session-a', 'client:1', 'secret-1');
  expect(flash.take('session-b', 'client:1')).toBeUndefined();
  expect(flash.take('session-a', 'client:2')).toBeUndefined();
  expect(flash.take('session-a', 'client:1')).toBe('secret-1');
  expect(flash.take('session-a', 'client:1')).toBeUndefined();

  flash.put('session-a', 'client:1', 'late');
  clock.advance(SECRET_FLASH_TTL_MS);
  expect(flash.take('session-a', 'client:1')).toBeUndefined();

  // Expired entries are swept on the next put, so abandoned flashes do not accumulate.
  flash.put('session-c', 'client:3', 'abandoned');
  clock.advance(SECRET_FLASH_TTL_MS);
  flash.put('session-d', 'client:4', 'fresh');
  expect((flash as unknown as { entries: Map<string, unknown> }).entries.size).toBe(1);
  expect(flash.take('session-d', 'client:4')).toBe('fresh');
});
