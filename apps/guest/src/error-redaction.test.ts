import { afterAll, beforeAll, expect, spyOn, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { IDENTITY_DATABASE } from '../../../packages/core/src/shared/domain/tokens.ts';
import { ColumnEncryption } from '../../../packages/core/src/shared/infrastructure/column-encryption.ts';
import {
  describeError,
  redactStatement,
} from '../../../packages/core/src/shared/infrastructure/error-redaction.ts';
import { PostgresGateway } from '../../../packages/core/src/shared/infrastructure/postgres-gateway.ts';
import { withContainer } from '../../../packages/core/tests/support/container-lock.ts';
import { useTestDatabase } from '../../../packages/core/tests/support/database.ts';
import { ControlPlaneController } from '../../api/src/control-plane.ts';
import { ControlPlaneHandlers } from '../../api/src/handlers.ts';
import { routeRequest } from '../../server/src/serve.ts';

const KEY = Buffer.alloc(32, 5).toString('base64');
const engine = new PGlite({ extensions: { pgcrypto } } as never);
let keyed: Error & { params?: unknown[]; query?: string };

/** A fresh copy of the real error, so each check starts from the unredacted object. */
async function pgcryptoError(): Promise<Error & { params?: unknown[]; query?: string }> {
  return engine
    .query('SELECT pgp_sym_decrypt(pgp_sym_encrypt($1::text, $2::text), $3::text)', [
      'pat@example.com',
      KEY,
      `${KEY}-wrong`,
    ])
    .then(
      () => {
        throw new Error('expected a decrypt failure');
      },
      (error: unknown) => error as Error & { params?: unknown[]; query?: string },
    );
}

beforeAll(async () => {
  await engine.exec('CREATE EXTENSION IF NOT EXISTS pgcrypto');
  keyed = await pgcryptoError();
});
afterAll(() => engine.close());

test('a real pgcrypto error carries the key in its bound values', () => {
  // The premise: PGlite's DatabaseError keeps `params` (and `query`).
  expect(JSON.stringify(keyed.params)).toContain(KEY);
  expect(keyed.message).not.toContain(KEY);
});

test('the gateway strips bound values before rethrowing', async () => {
  await withContainer(async () => {
    const failing = {
      query: async () => {
        throw await pgcryptoError();
      },
      first: async () => {
        throw await pgcryptoError();
      },
      run: async () => {
        throw await pgcryptoError();
      },
    } as unknown as SqlDatabase;
    useContainer().registerValue(IDENTITY_DATABASE, failing);
    try {
      const gateway = new PostgresGateway();
      for (const call of [
        () => gateway.query('SELECT 1'),
        () => gateway.one('SELECT 1'),
        () => gateway.run('SELECT 1'),
        () => gateway.write('SELECT 1'),
      ]) {
        const error = (await call().catch((caught: unknown) => caught)) as Record<string, unknown>;
        expect(error.params).toBeUndefined();
        expect(error.query).toBeUndefined();
        expect(`${JSON.stringify(error)} ${String(error)}`).not.toContain(KEY);
      }
    } finally {
      await useTestDatabase();
    }
  });
});

test('no log line or HTTP body carries the key', async () => {
  const lines: string[] = [];
  const log = spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  const encryption = useContainer().resolve(ColumnEncryption);
  try {
    // Browser routes, through routeRequest.
    (encryption as unknown as { cipher: () => Promise<never> }).cipher = async () => {
      throw await pgcryptoError();
    };
    const page = await routeRequest(new Request('https://identity.test/login'), new Map());
    expect(page.status).toBe(500);
    expect(await page.text()).not.toContain(KEY);

    // JSON API operations, through ControlPlaneHandlers.
    useContainer().registerValue(ControlPlaneController, {
      apiList: async () => {
        throw await pgcryptoError();
      },
    } as unknown as ControlPlaneController);
    const handlers = new ControlPlaneHandlers();
    const api = await handlers.apiList({}, { transport: 'http', request: {} });
    expect(api.status).toBe(500);
    expect(await api.text()).not.toContain(KEY);
    expect(lines.length).toBeGreaterThanOrEqual(2);
    expect(lines.join('\n')).not.toContain(KEY);
    expect(lines.join('\n')).toContain('Wrong key or corrupt data');
  } finally {
    log.mockRestore();
    delete (encryption as unknown as { cipher?: unknown }).cipher;
    useContainer().register(ControlPlaneController);
  }
});

test('redaction follows the cause chain and tolerates odd error shapes', () => {
  const inner = Object.assign(new Error('inner'), { parameters: [KEY] });
  const outer = Object.assign(new Error('outer', { cause: inner }), { values: [KEY] });
  redactStatement(outer);
  expect(JSON.stringify([outer, inner])).not.toContain(KEY);
  const frozen = Object.defineProperty(new Error('frozen'), 'params', {
    value: [KEY],
    configurable: false,
    enumerable: true,
  });
  Object.assign(frozen, { code: 'XX000', errno: 'IDC01' });
  const replaced = redactStatement(frozen) as Error & { code?: string; errno?: string };
  expect(replaced).not.toBe(frozen);
  expect([replaced.message, replaced.code, replaced.errno]).toEqual(['frozen', 'XX000', 'IDC01']);
  expect(JSON.stringify(replaced)).not.toContain(KEY);
  expect(redactStatement(null)).toBeNull();
  expect(describeError('text')).toBe('unknown error');
  expect(describeError(Object.assign(new Error('m'), { code: 'IDC01' }))).toBe('m (IDC01)');
  expect(describeError(new Error('m'))).toBe('m');
});
