import { beforeAll, expect, test } from 'bun:test';
import { bearerFor } from '@di-framework/identity/tests/support/clients.ts';
import { useTestDatabase } from '@di-framework/identity/tests/support/database.ts';
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
});
