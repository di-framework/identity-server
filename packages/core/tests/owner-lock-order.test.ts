import { describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import { applyMigrations } from '@di-framework/identity-migrations';
import type { SqlDatabase } from '@di-framework/repo';
import { PostgresDirectoryRepository } from '../src/directory/infrastructure/postgres-directory-repository.ts';
import { openPostgresDatabase } from '../src/shared/infrastructure/postgres.ts';
import type { PostgresGateway } from '../src/shared/infrastructure/postgres-gateway.ts';
import { databaseUrl, withThrowawayDatabase } from './support/database.ts';

/** Previous `OTHER_OWNER` pattern from the guest autocommit refactor (cross-locks rows). */
const LEGACY_OTHER_OWNER = `SELECT 1 FROM organization_memberships AS x
  WHERE x.organization_id = m.organization_id AND x.user_id <> m.user_id AND x.role = 'owner'
  FOR UPDATE`;

const LEGACY_DEMOTE_OWNER = `UPDATE organization_memberships AS m SET role = 'member'
  FROM organizations AS o
  WHERE o.id = m.organization_id AND o.slug = ? AND m.user_id = ? AND m.role = 'owner'
    AND EXISTS (${LEGACY_OTHER_OWNER})
  RETURNING 1`;

function isDeadlock(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const record = error as { code?: string; errno?: string; message?: string };
  return (
    record.code === '40P01' ||
    record.errno === '40P01' ||
    (record.message?.toLowerCase().includes('deadlock') ?? false)
  );
}

function gatewayFor(database: SqlDatabase): PostgresGateway {
  const gateway: Pick<
    PostgresGateway,
    'query' | 'one' | 'run' | 'write' | 'transaction' | 'count' | 'isUnique'
  > = {
    query: <T>(sql: string, params?: unknown[]) => database.query<T>(sql, params),
    one: async <T>(sql: string, params?: unknown[]) =>
      (await database.first<T>(sql, params)) ?? undefined,
    run: (sql: string, params?: unknown[]) => database.run(sql, params),
    write: async (sql: string, params?: unknown[]) => {
      await database.run(sql, params);
    },
    transaction: <T>(fn: () => Promise<T>) => database.transaction(async () => fn()),
    count: async (sql: string, params?: unknown[]) => {
      const row = await database.first<{ count: unknown }>(sql, params);
      return Number(row?.count ?? 0);
    },
    isUnique: () => false,
  };
  return gateway as unknown as PostgresGateway;
}

function directoryFor(database: SqlDatabase): PostgresDirectoryRepository {
  return useContainer().construct(PostgresDirectoryRepository, {
    0: gatewayFor(database),
  });
}

async function seedTwoOwnerOrg(
  database: SqlDatabase,
): Promise<{ slug: string; first: string; second: string }> {
  const slug = `lock-order-${crypto.randomUUID().slice(0, 8)}`;
  const orgId = crypto.randomUUID();
  const first = crypto.randomUUID();
  const second = crypto.randomUUID();
  await database.run(`INSERT INTO organizations (id, slug, name) VALUES (?, ?, ?)`, [
    orgId,
    slug,
    slug,
  ]);
  for (const [id, label] of [
    [first, 'one'],
    [second, 'two'],
  ] as const) {
    await database.run(
      `INSERT INTO users (id, login, normalized_login, email, normalized_email, display_name,
         email_verified, system_role, status)
       VALUES (?, ?, ?, ?, ?, ?, true, 'user', 'active')`,
      [
        id,
        `${label}-${id.slice(0, 8)}`,
        `${label}-${id.slice(0, 8)}`,
        `${label}-${id.slice(0, 8)}@example.com`,
        `${label}-${id.slice(0, 8)}@example.com`,
        label,
      ],
    );
    await database.run(
      `INSERT INTO organization_memberships (organization_id, user_id, role) VALUES (?, ?, 'owner')`,
      [orgId, id],
    );
  }
  return { slug, first, second };
}

describe('owner row locking order', () => {
  test('legacy cross-lock demote SQL deadlocks under concurrent owners', async () => {
    await withThrowawayDatabase('identity_owner_lock_legacy', async (admin) => {
      await applyMigrations(admin);
      const url = databaseUrl('identity_owner_lock_legacy');
      const left = await openPostgresDatabase(url, { max: 1 });
      const right = await openPostgresDatabase(url, { max: 1 });
      try {
        await left.exec('SET deadlock_timeout TO 50');
        await right.exec('SET deadlock_timeout TO 50');
        let sawDeadlock = false;
        for (let attempt = 0; attempt < 40 && !sawDeadlock; attempt++) {
          const { slug, first, second } = await seedTwoOwnerOrg(left);
          const results = await Promise.allSettled([
            left.run(LEGACY_DEMOTE_OWNER, [slug, first]),
            right.run(LEGACY_DEMOTE_OWNER, [slug, second]),
          ]);
          sawDeadlock = results.some(
            (result) => result.status === 'rejected' && isDeadlock(result.reason),
          );
        }
        expect(sawDeadlock).toBe(true);
      } finally {
        await left.close?.();
        await right.close?.();
      }
    });
  });

  test('demoteOwner completes concurrent demotions without deadlock', async () => {
    await withThrowawayDatabase('identity_owner_lock_fixed', async (admin) => {
      await applyMigrations(admin);
      const url = databaseUrl('identity_owner_lock_fixed');
      const left = await openPostgresDatabase(url, { max: 1 });
      const right = await openPostgresDatabase(url, { max: 1 });
      try {
        await left.exec('SET deadlock_timeout TO 50');
        await right.exec('SET deadlock_timeout TO 50');
        const { slug, first, second } = await seedTwoOwnerOrg(left);
        const results = await Promise.allSettled([
          directoryFor(left).demoteOwner(slug, first),
          directoryFor(right).demoteOwner(slug, second),
        ]);
        expect(results.every((result) => result.status === 'fulfilled')).toBe(true);
        const demoted = results.filter(
          (result) => result.status === 'fulfilled' && result.value === true,
        );
        expect(demoted).toHaveLength(1);
      } finally {
        await left.close?.();
        await right.close?.();
      }
    });
  });
});
