#!/usr/bin/env bun
/**
 * Boots the identity guest's code on a COPY of an imported data directory, before it is
 * installed anywhere, and checks that the cutover keeps what it must.
 * docs/guest-http-api.md#authproto-cutover is the runbook.
 *
 *   bun deploy/cutover/rehearse.ts --data <data-dir> --values <values.json> [--export <dir>]
 *       [--provider ...] [--guest ...] [--runner ...]
 *
 * The copy is opened through the guest's encrypted provider under wasmtime (runner.ts), and the
 * guest's request handler (apps/guest/src/runtime.ts) runs in this process with the values as
 * its environment and its compiled-in wasi:config, so it applies the later migrations, loads its
 * settings and checks bootstrap exactly as on its first start. Checks:
 *
 *   - /ready is 200 with every check true, and the schema is at the latest migration;
 *   - the stored bootstrap fingerprint is unchanged, so the guest did not reconcile bootstrap;
 *   - only bootstrap state is left in identity_runtime_secret (V16 deleted nothing it needed);
 *   - discovery's issuer is ISSUER_URL and the JWKS serves the kid of AUTH_ACTIVE_PRIVATE_JWK;
 *   - the bootstrap owner (and viewer) sign in with the values' passwords;
 *   - the access, directory and provisioner clients authenticate with the values' secrets;
 *   - with --export, every table still has the exported row count.
 *
 * The copy is deleted afterwards; <data-dir> is never opened. Prints check names and results
 * only. Exit 1 when a check fails.
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { guestConfig } from '../../apps/guest/scripts/guest-config.ts';
import { DATABASE_ROOT_ENV } from '../../apps/guest/src/database.ts';
import { embeddedMigrations } from '../../apps/guest/src/migrations.ts';
import { handle } from '../../apps/guest/src/runtime.ts';
import { RUNTIME_SECRET_SETTINGS } from '../../apps/guest/src/settings.ts';
import { Browser } from '../../apps/server/tests/support/browser.ts';
import {
  assertPrivateMode,
  PGLITE_KEY,
  parseRuntimeValues,
} from '../platform/components/control-secret.ts';
import { loadExport } from './import-core.ts';
import {
  checkProvider,
  composeRunner,
  DATABASE_ROOT,
  DEFAULTS,
  describe,
  startRunner,
} from './runner.ts';
import { RUNTIME_SECRET_TABLE, V16_KEPT_ROW_NAMES } from './source.ts';

const { values: args } = parseArgs({
  options: {
    data: { type: 'string' },
    values: { type: 'string' },
    export: { type: 'string' },
    provider: { type: 'string', default: DEFAULTS.provider },
    guest: { type: 'string', default: DEFAULTS.guest },
    runner: { type: 'string', default: DEFAULTS.runner },
  },
});

function required(name: keyof typeof args): string {
  const value = args[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`--${name} is required`);
  return value;
}

const results: Array<[string, boolean, string]> = [];
const record = (name: string, ok: boolean, detail: string) => results.push([name, ok, detail]);

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;

async function main(): Promise<void> {
  const valuesPath = required('values');
  assertPrivateMode(statSync(valuesPath).mode, valuesPath);
  const values = parseRuntimeValues(readFileSync(valuesPath, 'utf8'), valuesPath);
  const key = values[PGLITE_KEY];
  if (!key) throw new Error(`${valuesPath} has no ${PGLITE_KEY}`);
  const loaded = args.export ? loadExport(args.export) : undefined;
  checkProvider(args.provider as string, args.guest as string);
  const work = mkdtempSync(join(tmpdir(), 'identity-rehearsal-'));
  try {
    const copy = join(work, 'data');
    cpSync(required('data'), copy, { recursive: true });
    const composed = composeRunner({
      provider: args.provider as string,
      runner: args.runner as string,
      out: join(work, 'runner.composed.wasm'),
    });
    const runner = await startRunner(composed, copy, key);
    try {
      await rehearse(runner.database, values, loaded);
    } finally {
      await runner.stop();
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  for (const [name, ok, detail] of results) {
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${detail}`);
  }
  if (results.some(([, ok]) => !ok)) process.exitCode = 1;
}

async function rehearse(
  database: Awaited<ReturnType<typeof startRunner>>['database'],
  values: Record<string, string>,
  loaded: ReturnType<typeof loadExport> | undefined,
): Promise<void> {
  const stored = async (name: string) =>
    (
      await database.first<{ value: unknown }>(
        `SELECT value FROM ${RUNTIME_SECRET_TABLE} WHERE name = ?`,
        [name],
      )
    )?.value;
  const fingerprintBefore = await stored('bootstrap_fingerprint');

  // The guest's compiled-in wasi:config, with the notification scheduler off: a rehearsal must
  // not send mail through the SMTP host in the values.
  const config = Object.entries({
    ...guestConfig(),
    GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED: 'false',
  });
  const env = {
    ...Object.fromEntries(
      RUNTIME_SECRET_SETTINGS.flatMap((name) => (values[name] ? [[name, values[name]]] : [])),
    ),
    [DATABASE_ROOT_ENV]: DATABASE_ROOT,
  };
  const origin = values.AUTH_PUBLIC_ORIGIN as string;
  const fetch = (request: Request) =>
    handle(request, {
      database: () => Promise.resolve(database),
      config: { getAll: () => config },
      env: () => env,
      assets: new Map(),
      shell: '<!doctype html><div id="root"></div>',
    });

  const ready = await fetch(new Request(`${origin}/ready`));
  const report = (await ready.json()) as Record<string, unknown>;
  record(
    'ready',
    ready.status === 200 && report.ok === true,
    `HTTP ${ready.status} ${JSON.stringify(report)}`,
  );

  const latest = embeddedMigrations.at(-1)?.version;
  const history = await database.first<{ v: unknown }>(
    'SELECT max(version::int)::text AS v FROM identity_schema_migrations',
  );
  record('schema', String(history?.v) === latest, `at V${history?.v}, latest V${latest}`);

  const fingerprintAfter = await stored('bootstrap_fingerprint');
  record(
    'bootstrap not reconciled',
    fingerprintBefore !== undefined && fingerprintBefore === fingerprintAfter,
    fingerprintBefore === undefined
      ? 'no fingerprint was imported'
      : `fingerprint ${fingerprintBefore === fingerprintAfter ? 'unchanged' : 'changed (bootstrap ran again)'}`,
  );
  const leftover = await database.query<{ name: string }>(
    `SELECT name FROM ${RUNTIME_SECRET_TABLE} ORDER BY name`,
  );
  const names = leftover.map((row) => String(row.name));
  record(
    'runtime secret table',
    names.every((name) => V16_KEPT_ROW_NAMES.includes(name)),
    `rows: ${names.join(', ') || 'none'}`,
  );

  // Before any sign-in, which adds sessions and audit rows.
  if (loaded) {
    for (const table of loaded.manifest.tables) {
      const row = await database.first<{ n: unknown }>(
        `SELECT count(*)::int AS n FROM "${table.name}"`,
      );
      record(`rows ${table.name}`, Number(row?.n) === table.count, `${row?.n}/${table.count}`);
    }
  }

  const discovery = (await (
    await fetch(new Request(`${origin}/.well-known/openid-configuration`))
  ).json()) as { issuer?: string };
  record('issuer', discovery.issuer === values.ISSUER_URL, 'discovery issuer equals ISSUER_URL');
  const kid = (JSON.parse(values.AUTH_ACTIVE_PRIVATE_JWK as string) as { kid?: string }).kid;
  const jwks = (await (await fetch(new Request(`${origin}/oauth2/jwks`))).json()) as {
    keys: Array<{ kid?: string }>;
  };
  record(
    'signing key',
    jwks.keys.some((jwk) => jwk.kid === kid),
    `JWKS serves kid ${kid}`,
  );

  // A wrong password also answers 303 (back to the login page), so a sign-in counts only when
  // the session it set is signed in.
  const signIn = async (login: string, password: string) => {
    const browser = new Browser(fetch);
    const posted = await browser.signIn(login, password);
    const page = await browser.send('GET', '/account/identity-links', { json: true });
    const signedIn =
      page.status === 200 && ((await page.json()) as { signedIn?: unknown }).signedIn;
    return {
      ok: posted.status === 303 && signedIn === true,
      detail: `HTTP ${posted.status}, signed in: ${signedIn === true}`,
    };
  };
  const named = Object.fromEntries(config);
  const owner = await signIn(
    named.AUTH_BOOTSTRAP_OWNER_LOGIN as string,
    values.AUTH_BOOTSTRAP_OWNER_PASSWORD as string,
  );
  record('owner sign-in', owner.ok, owner.detail);
  if (named.AUTH_BOOTSTRAP_VIEWER_LOGIN && values.AUTH_BOOTSTRAP_VIEWER_PASSWORD) {
    const viewer = await signIn(
      named.AUTH_BOOTSTRAP_VIEWER_LOGIN,
      values.AUTH_BOOTSTRAP_VIEWER_PASSWORD,
    );
    record('viewer sign-in', viewer.ok, viewer.detail);
  }
  const clientIds = named;
  for (const [client, secretName] of [
    [clientIds.AUTH_ACCESS_CLIENT_ID, 'AUTH_ACCESS_CLIENT_SECRET'],
    [clientIds.AUTH_DIRECTORY_CLIENT_ID, 'AUTH_DIRECTORY_CLIENT_SECRET'],
    [clientIds.AUTH_PROVISIONER_CLIENT_ID, 'AUTH_PROVISIONER_CLIENT_SECRET'],
  ] as const) {
    const response = await fetch(
      new Request(`${origin}/oauth2/introspect`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic(client as string, values[secretName] as string),
        },
        body: new URLSearchParams({ token: 'rehearsal-not-a-token' }),
      }),
    );
    record(`client ${client}`, response.status === 200, `introspect HTTP ${response.status}`);
  }
}

try {
  await main();
} catch (error) {
  console.error(`rehearse: ${describe(error)}`);
  process.exitCode = 2;
}
