/**
 * The cutover rehearsal's checks (docs/guest-http-api.md#authproto-cutover), run by rehearse.ts
 * on a copy of the imported data directory and by roundtrip.test.ts on a real import. The guest's
 * request handler runs in this process on `database`, with the values as its environment and its
 * compiled-in wasi:config, so it applies the later migrations, loads its settings and checks
 * bootstrap exactly as on its first start.
 *
 * Results carry names and details only: logins, emails, passwords, secrets and password hashes
 * never appear in them. A password hash is compared as a SHA-256 digest and only the comparison
 * is reported.
 */
import { createHash } from 'node:crypto';
import { guestConfig } from '../../apps/guest/scripts/guest-config.ts';
import { DATABASE_ROOT_ENV, type SqlDatabase } from '../../apps/guest/src/database.ts';
import { embeddedMigrations } from '../../apps/guest/src/migrations.ts';
import { handle } from '../../apps/guest/src/runtime.ts';
import { RUNTIME_ENV_SETTINGS } from '../../apps/guest/src/settings.ts';
import { Browser } from '../../apps/server/tests/support/browser.ts';
import { parseJsonQuietly } from '../platform/components/control-secret.ts';
import type { LoadedExport } from './import-core.ts';
import { RUNTIME_SECRET_TABLE, V16_KEPT_ROW_NAMES } from './source.ts';

/** `ok` passes; `note` passes but is worth reading; `fail` makes the rehearsal exit 1. */
export type CheckStatus = 'ok' | 'note' | 'fail';

export interface CheckResult {
  name: string;
  status: CheckStatus;
  detail: string;
}

/** One printed line per result: `ok  `, `note` or `FAIL`, the name, the detail. */
export function formatResult(result: CheckResult): string {
  const tag = { ok: 'ok  ', note: 'note', fail: 'FAIL' }[result.status];
  return `${tag} ${result.name}: ${result.detail}`;
}

/** Hex SHA-256 of a stored password hash, or undefined when there is none. Never the hash. */
export function passwordHashDigest(hash: unknown): string | undefined {
  if (typeof hash !== 'string' || hash === '') return undefined;
  return createHash('sha256').update(hash).digest('hex');
}

/** The login as the directory matches it (`normalized_login`). */
const normalizeLogin = (login: string) => login.trim().toLowerCase();

/** Digest of `login`'s password hash in the export's `users` rows (undefined: no such user). */
export function exportedPasswordHashDigest(
  loaded: LoadedExport,
  login: string,
): { found: boolean; digest: string | undefined } {
  const rows = parseJsonQuietly<Array<Record<string, unknown>> | null>(
    loaded.rows.get('users') ?? '[]',
    'the exported users',
  );
  const wanted = normalizeLogin(login);
  const row = (rows ?? []).find(
    (candidate) =>
      typeof candidate.login === 'string' && normalizeLogin(candidate.login) === wanted,
  );
  return { found: row !== undefined, digest: passwordHashDigest(row?.password_hash) };
}

/** Digest of `login`'s password hash in the imported database. */
export async function importedPasswordHashDigest(
  database: SqlDatabase,
  login: string,
): Promise<{ found: boolean; digest: string | undefined }> {
  const row = await database.first<{ password_hash: unknown }>(
    'SELECT password_hash FROM users WHERE normalized_login = ?',
    [normalizeLogin(login)],
  );
  return { found: row !== undefined, digest: passwordHashDigest(row?.password_hash) };
}

/** Whether the import kept a user's password hash exactly as exported. */
export type HashCarried = 'same' | 'differs' | 'missing' | 'no-export';

export function compareHashes(
  exported: { found: boolean; digest: string | undefined } | undefined,
  imported: { found: boolean; digest: string | undefined },
): HashCarried {
  if (exported === undefined) return 'no-export';
  if (!exported.found || !imported.found) return 'missing';
  return exported.digest !== undefined && exported.digest === imported.digest ? 'same' : 'differs';
}

/** The outcome of one sign-in attempt through the login page. */
export interface SignInOutcome {
  /** Status of the POST /login. */
  status: number;
  /** Whether the session it set then reads as signed in. */
  signedIn: boolean;
}

/**
 * Classifies a bootstrap user's sign-in with the values file's bootstrap password.
 *
 * The bootstrap password in values.json is only what bootstrap first set; the user may have
 * changed it since, and the cutover carries the stored hash, not the bootstrap password. A
 * rejected sign-in (the login page's 303 without a signed-in session) is therefore a `note`, not
 * a failure, but only when the stored hash is proven carried (`same`: the imported hash's digest
 * equals the export's). Everything else fails: a rejected sign-in whose hash differs, is missing,
 * or cannot be compared (no --export), and any other answer (5xx, a page that is not the login
 * redirect).
 *
 * The owner gets the same rule as the viewer. A strict owner check would add no proof the
 * rehearsal lacks: the three bootstrap clients authenticate with their carried Argon2id hashes
 * through the same PasswordHasher (fatal checks), and the digest comparison proves the owner's
 * hash was not reset. And the owner is the account most likely to have rotated its bootstrap
 * password, so a strict check would fail exactly the well-run sources.
 */
export function classifySignIn(
  who: string,
  outcome: SignInOutcome,
  carried: HashCarried,
): CheckResult {
  const name = `${who} sign-in`;
  const seen = `HTTP ${outcome.status}, signed in: ${outcome.signedIn}`;
  if (outcome.status === 303 && outcome.signedIn) {
    return { name, status: 'ok', detail: `${seen} with the bootstrap password` };
  }
  const rejected = outcome.status === 303 && !outcome.signedIn;
  if (!rejected) {
    return { name, status: 'fail', detail: `${seen}; the login page did not answer as expected` };
  }
  switch (carried) {
    case 'same':
      return {
        name,
        status: 'note',
        detail: `${seen}: password changed since bootstrap (expected if the user changed it); the stored hash was carried unchanged (digest equals the export's)`,
      };
    case 'no-export':
      return {
        name,
        status: 'fail',
        detail: `${seen} with the bootstrap password; pass --export to tell a changed password from a lost hash`,
      };
    case 'missing':
      return {
        name,
        status: 'fail',
        detail: `${seen}; the user is missing from the export or the import`,
      };
    case 'differs':
      return {
        name,
        status: 'fail',
        detail: `${seen}; the stored hash differs from the export's (it was not carried as exported)`,
      };
  }
}

/** The guest's compiled-in wasi:config, with the notification scheduler off. */
export function rehearsalConfig(): Record<string, string> {
  // A rehearsal must not send mail through the SMTP host in the values.
  return { ...guestConfig(), GSIO_IDENTITY_NOTIFICATION_SCHEDULER_ENABLED: 'false' };
}

/**
 * A bootstrap setting as the guest resolves it: the values file (its environment) over the
 * compiled-in wasi:config, as `loadGuestSettings` merges them.
 */
export function bootstrapSetting(
  name: string,
  values: Record<string, string>,
  config: Record<string, string>,
): string | undefined {
  return values[name] ?? config[name];
}

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;

/**
 * Every rehearsal check against `database` (already holding the import), in order:
 *
 *   - /ready is 200 with every check true, and the schema is at the latest migration;
 *   - the stored bootstrap fingerprint is unchanged, so the guest did not reconcile bootstrap;
 *   - only bootstrap state is left in identity_runtime_secret (V16 deleted nothing it needed);
 *   - the bootstrap organization (values over wasi:config) exists;
 *   - with the export: every table still has the exported row count, and each bootstrap user's
 *     stored password hash equals the export's (digests compared);
 *   - discovery's issuer is ISSUER_URL and the JWKS serves the kid of AUTH_ACTIVE_PRIVATE_JWK;
 *   - the bootstrap owner and viewer sign in with the values' passwords (`classifySignIn`);
 *   - the access, directory and provisioner clients authenticate with the values' secrets.
 */
export async function rehearseChecks(
  database: SqlDatabase,
  values: Record<string, string>,
  loaded: LoadedExport | undefined,
  options: { databaseRoot: string },
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const record = (name: string, ok: boolean, detail: string) =>
    results.push({ name, status: ok ? 'ok' : 'fail', detail });
  const stored = async (name: string) =>
    (
      await database.first<{ value: unknown }>(
        `SELECT value FROM ${RUNTIME_SECRET_TABLE} WHERE name = ?`,
        [name],
      )
    )?.value;
  const fingerprintBefore = await stored('bootstrap_fingerprint');

  const named = rehearsalConfig();
  const config = Object.entries(named);
  const env = {
    ...Object.fromEntries(
      RUNTIME_ENV_SETTINGS.flatMap((name) =>
        values[name] !== undefined ? [[name, values[name]]] : [],
      ),
    ),
    [DATABASE_ROOT_ENV]: options.databaseRoot,
  };
  const setting = (name: string) => bootstrapSetting(name, values, named);
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
  const organization = await database.first<{ n: unknown }>(
    'SELECT count(*)::int AS n FROM organizations WHERE slug = ?',
    [setting('AUTH_BOOTSTRAP_ORGANIZATION_SLUG') ?? ''],
  );
  record(
    'bootstrap organization',
    Number(organization?.n) === 1,
    `the bootstrap organization slug (${values.AUTH_BOOTSTRAP_ORGANIZATION_SLUG === undefined ? 'wasi:config default' : 'from the values'}) matches ${organization?.n} organization(s)`,
  );

  // Before any sign-in, which adds sessions and audit rows (and could rehash a password).
  if (loaded) {
    for (const table of loaded.manifest.tables) {
      const row = await database.first<{ n: unknown }>(
        `SELECT count(*)::int AS n FROM "${table.name}"`,
      );
      record(`rows ${table.name}`, Number(row?.n) === table.count, `${row?.n}/${table.count}`);
    }
  }
  const people: Array<{ who: string; login: string; password: string }> = [];
  for (const [who, prefix] of [
    ['owner', 'AUTH_BOOTSTRAP_OWNER'],
    ['viewer', 'AUTH_BOOTSTRAP_VIEWER'],
  ] as const) {
    const login = setting(`${prefix}_LOGIN`);
    const password = values[`${prefix}_PASSWORD`];
    // The viewer is optional: bootstrap skips it without a login or password.
    if (who === 'viewer' && (!login || !password)) continue;
    people.push({ who, login: login ?? '', password: password ?? '' });
  }
  const carried = new Map<string, HashCarried>();
  for (const { who, login } of people) {
    const state = compareHashes(
      loaded ? exportedPasswordHashDigest(loaded, login) : undefined,
      await importedPasswordHashDigest(database, login),
    );
    carried.set(who, state);
    if (state !== 'no-export') {
      record(
        `${who} password hash carried`,
        state === 'same',
        {
          same: "the stored hash's digest equals the export's",
          differs: "the stored hash's digest differs from the export's",
          missing: 'the user is missing from the export or the import',
        }[state],
      );
    }
  }

  const discovery = (await (
    await fetch(new Request(`${origin}/.well-known/openid-configuration`))
  ).json()) as { issuer?: string };
  record('issuer', discovery.issuer === values.ISSUER_URL, 'discovery issuer equals ISSUER_URL');
  const kid = parseJsonQuietly<{ kid?: string }>(
    values.AUTH_ACTIVE_PRIVATE_JWK as string,
    'AUTH_ACTIVE_PRIVATE_JWK',
  ).kid;
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
  const signIn = async (login: string, password: string): Promise<SignInOutcome> => {
    const browser = new Browser(fetch);
    const posted = await browser.signIn(login, password);
    const page = await browser.send('GET', '/account/identity-links', { json: true });
    const signedIn =
      page.status === 200 && ((await page.json()) as { signedIn?: unknown }).signedIn === true;
    return { status: posted.status, signedIn };
  };
  for (const { who, login, password } of people) {
    results.push(
      classifySignIn(who, await signIn(login, password), carried.get(who) ?? 'no-export'),
    );
  }

  for (const [client, secretName] of [
    [named.AUTH_ACCESS_CLIENT_ID, 'AUTH_ACCESS_CLIENT_SECRET'],
    [named.AUTH_DIRECTORY_CLIENT_ID, 'AUTH_DIRECTORY_CLIENT_SECRET'],
    [named.AUTH_PROVISIONER_CLIENT_ID, 'AUTH_PROVISIONER_CLIENT_SECRET'],
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
  return results;
}
