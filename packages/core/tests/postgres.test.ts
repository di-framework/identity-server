import { beforeAll, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import { PostgresGateway, Timestamps } from '../src/shared/infrastructure/postgres-gateway.ts';
import { useTestDatabase } from './support/database.ts';

let database: SqlDatabase;

beforeAll(async () => {
  database = await useTestDatabase();
  await database.exec(
    `CREATE TABLE IF NOT EXISTS pool_probe (id int PRIMARY KEY, value int NOT NULL);
     TRUNCATE pool_probe; INSERT INTO pool_probe VALUES (1, 0);`,
  );
});

test('row locks serialize concurrent transactions on separate pooled connections', async () => {
  const order: string[] = [];
  let releaseFirst!: () => void;
  const firstHolds = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let firstLocked!: () => void;
  const locked = new Promise<void>((resolve) => {
    firstLocked = resolve;
  });
  const first = database.transaction(async (tx) => {
    await tx.query('SELECT value FROM pool_probe WHERE id = 1 FOR UPDATE');
    order.push('first-locked');
    firstLocked();
    await firstHolds;
    await tx.run('UPDATE pool_probe SET value = value + 1 WHERE id = 1');
    order.push('first-commit');
  });
  await locked;
  const second = database.transaction(async (tx) => {
    const row = await tx.first<{ value: number }>(
      'SELECT value FROM pool_probe WHERE id = 1 FOR UPDATE',
    );
    order.push(`second-saw-${row?.value}`);
  });
  const outside = await database.first<{ value: number }>(
    'SELECT value FROM pool_probe WHERE id = 1',
  );
  order.push(`outside-saw-${outside?.value}`);
  releaseFirst();
  await Promise.all([first, second]);
  expect(order).toEqual(['first-locked', 'outside-saw-0', 'first-commit', 'second-saw-1']);
});

test('nested transactions and statements in the same context join the outer one', async () => {
  const gateway = useContainer().resolve(PostgresGateway);
  const ids = await gateway.transaction(async () => {
    const outer = await gateway.one<{ id: string }>('SELECT txid_current()::text AS id');
    const inner = await gateway.transaction(async () =>
      gateway.one<{ id: string }>('SELECT txid_current()::text AS id'),
    );
    const viaView = await database.transaction(async (tx) =>
      tx.transaction(async (nested) =>
        nested.first<{ id: string }>('SELECT txid_current()::text AS id'),
      ),
    );
    return [outer?.id, inner?.id, viaView?.id];
  });
  expect(new Set(ids).size).toBe(1);
});

test('a throwing transaction rolls back its writes', async () => {
  await expect(
    database.transaction(async (tx) => {
      await tx.run('UPDATE pool_probe SET value = 99 WHERE id = 1');
      throw new Error('abort');
    }),
  ).rejects.toThrow('abort');
  const row = await database.first<{ value: number }>('SELECT value FROM pool_probe WHERE id = 1');
  expect(row?.value).not.toBe(99);
  await database.transaction(async (tx) => tx.exec('SELECT 1; SELECT 2'));
});

test('gateway helpers', async () => {
  const gateway = useContainer().resolve(PostgresGateway);
  expect(await gateway.count('SELECT count(*)::int AS count FROM pool_probe')).toBe(1);
  expect(await gateway.count('SELECT 1 AS other WHERE false')).toBe(0);
  expect(await gateway.one('SELECT 1 WHERE false')).toBeUndefined();
  expect((await gateway.run('UPDATE pool_probe SET value = value WHERE id = 1')).changes).toBe(1);
  await expect(gateway.write('INSERT INTO pool_probe VALUES (1, 1)')).rejects.toMatchObject({
    status: 409,
  });
  await expect(gateway.write('INSERT INTO missing_table VALUES (1)')).rejects.toThrow();
  expect(gateway.isUnique({ errno: '23505' })).toBe(true);
  expect(Timestamps.ms('2026-01-01T00:00:00.000Z')).toBe(Date.UTC(2026, 0, 1));
  expect(Timestamps.isoOrNull(null)).toBeNull();
  expect(Timestamps.isoOrNull(new Date(0))).toBe('1970-01-01T00:00:00.000Z');
});
