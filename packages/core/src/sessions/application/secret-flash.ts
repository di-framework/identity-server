import { Component, Container } from '@di-framework/core/decorators';
import type { Clock } from '../../shared/domain/clock.ts';
import { CLOCK } from '../../shared/domain/tokens.ts';
import { Hashing } from '../../shared/infrastructure/crypto/hashing.ts';

/** How long a flashed value waits for the page it redirects to. */
export const SECRET_FLASH_TTL_MS = 5 * 60 * 1000;

/**
 * One-shot hand-off of a secret from a form POST to the page it redirects to, such as a newly
 * minted OAuth client secret. The value stays in process memory under the SHA-256 of the session
 * id and a scope; it is never written to `browser_sessions` or any other table, so a database
 * read or a backup cannot recover it. `take` removes it, and it expires after
 * `SECRET_FLASH_TTL_MS`.
 *
 * Like pending identity links, the value lives in the serving process: the Bun server and the
 * warm, exclusive wasmCloud instance keep it between the POST and the redirect. A restart in
 * between drops it, and the operator rotates the secret again.
 */
@Container()
export class SecretFlash {
  private readonly entries = new Map<string, { value: string; expiresAt: number }>();

  constructor(@Component(CLOCK) private readonly clock: Clock) {}

  put(sessionId: string, scope: string, value: string): void {
    const now = this.clock.now();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
    this.entries.set(flashKey(sessionId, scope), { value, expiresAt: now + SECRET_FLASH_TTL_MS });
  }

  /** The value flashed for this session and scope, once. Undefined when absent or expired. */
  take(sessionId: string, scope: string): string | undefined {
    const key = flashKey(sessionId, scope);
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    this.entries.delete(key);
    return entry.expiresAt > this.clock.now() ? entry.value : undefined;
  }
}

function flashKey(sessionId: string, scope: string): string {
  return Hashing.sha256Hex(`${sessionId}\u0000${scope}`);
}
