import { beforeAll, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { MailMessage } from '@di-framework/identity/src/mail/domain/mail.ts';
import { MAIL } from '@di-framework/identity/src/shared/domain/tokens.ts';
import { bearerFor } from '@di-framework/identity/tests/support/clients.ts';
import {
  databaseUrl,
  testDatabaseName,
  useTestDatabase,
} from '@di-framework/identity/tests/support/database.ts';
import { useRecordingMail } from '@di-framework/identity/tests/support/mail.ts';
import type { SqlDatabase } from '@di-framework/repo';
import { controlPlane } from '../src/control-plane.ts';

let database: SqlDatabase;
let token = '';

beforeAll(async () => {
  database = await useTestDatabase();
  token = await bearerFor((request) => controlPlane.fetch(request), ['admin:write']);
});

test('POST /api/admin/users mails a passwordless invite, and a replay does not mail again', async () => {
  const mail = useRecordingMail();
  const email = `invitee-${crypto.randomUUID()}@example.com`;
  const create = () =>
    controlPlane.fetch(
      new Request('https://identity.test/api/admin/users', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          'idempotency-key': `urn:invite:${email}`,
        },
        body: JSON.stringify({ login: email.split('@')[0], email, displayName: 'Invitee' }),
      }),
    );
  const created = await create();
  expect(created.status).toBe(201);
  expect(mail.to(email)).toHaveLength(1);
  expect(mail.lastToken(email)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  const challenge = await database.first<{ purpose: string }>(
    `SELECT purpose FROM email_challenges WHERE email = ?`,
    [email],
  );
  expect(challenge?.purpose).toBe('invite');
  expect((await create()).status).toBe(201);
  expect(mail.to(email)).toHaveLength(1);

  const reader = await bearerFor((request) => controlPlane.fetch(request), ['admin:read']);
  const audit = (await (
    await controlPlane.fetch(
      new Request('https://identity.test/api/admin/audit', {
        headers: { authorization: `Bearer ${reader}` },
      }),
    )
  ).json()) as Array<{ action: string; target: string; after_metadata: string }>;
  const id = ((await created.json()) as { id: string }).id;
  const record = audit.find(
    (entry) => entry.action === 'admin.user_created' && entry.target === id,
  );
  expect(JSON.parse(record?.after_metadata ?? 'null')).toEqual({ status: 'pending' });
});

test('the invite is mailed only after the new account commits', async () => {
  const outside = new Bun.SQL(databaseUrl(testDatabaseName));
  const seen: string[] = [];
  useContainer().registerValue(MAIL, {
    async send(message: MailMessage) {
      const rows = await outside`SELECT status FROM users WHERE email = ${message.to}`;
      seen.push(rows[0]?.status ?? 'missing');
    },
  });
  try {
    const email = `committed-${crypto.randomUUID()}@example.com`;
    const created = await controlPlane.fetch(
      new Request('https://identity.test/api/admin/users', {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ login: email.split('@')[0], email, displayName: 'Committed' }),
      }),
    );
    expect(created.status).toBe(201);
    expect(seen).toEqual(['pending']);
  } finally {
    useRecordingMail();
    await outside.close();
  }
});
