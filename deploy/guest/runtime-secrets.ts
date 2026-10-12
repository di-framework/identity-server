#!/usr/bin/env bun
/**
 * Runtime secrets for the identity guest, kept in its `identity-control` Secret.
 *
 *   bun deploy/guest/runtime-secrets.ts generate --out <file> --origin <url> --smtp-host <host>
 *       [--issuer <url>] [--redirect-uris <list>] [--column-encryption] [--plaintext-pglite]
 *     Writes a new values file (mode 0600): issuer and origin, an RS256 signing key, bootstrap
 *     passwords, client secrets, SMTP settings, the two column encryption keys
 *     (IDENTITY_COLUMN_KEY, IDENTITY_BIDX_KEY) and the data directory key DI_PGLITE_KEY.
 *     `--column-encryption` also opts in (IDENTITY_COLUMN_ENCRYPTION=enabled).
 *     `--plaintext-pglite` leaves out DI_PGLITE_KEY, for a development guest built without
 *     pglite.encryption. Prints the key's KCV, never the key. Refuses to overwrite a file.
 *
 *   bun deploy/guest/runtime-secrets.ts pglite-key --values <file>
 *     Adds DI_PGLITE_KEY to an existing values file when it has none, for a new data directory
 *     (an existing key is never replaced: the volume encrypted under it would become
 *     unreadable). Prints the KCV. Run `apply` afterwards.
 *
 *   bun deploy/guest/runtime-secrets.ts kcv --values <file>
 *     Prints the key-check value of DI_PGLITE_KEY (and DI_PGLITE_KEY_PREVIOUS): record it with
 *     each backup. It matches bytes 8..24 of the data directory's `.di-encfs` marker.
 *
 *   bun deploy/guest/runtime-secrets.ts preflight --values <file> [--config <file>]
 *     Checks a values file against the guest config (apps/guest/di-framework.config.json):
 *     every name declared in controlSecretKeys, DI_PGLITE_KEY present when the data directory
 *     is encrypted, and a plaintext guest only with IDENTITY_PGLITE_PLAINTEXT=1. `apply` runs it
 *     too. Prints the workload name, then the KCVs on stderr.
 *
 *   bun deploy/guest/runtime-secrets.ts column-keys --values <file> [--enable]
 *     Adds the column encryption keys to an existing values file when they are missing (an
 *     existing key is never replaced: rows encrypted under it would become unreadable).
 *     `--enable` also sets IDENTITY_COLUMN_ENCRYPTION=enabled. Run `apply` afterwards.
 *
 *   bun deploy/guest/runtime-secrets.ts guard --kubeconfig <path> --tenant <name> [--context <name>]
 *     Fails when di-tenant-<tenant> still has the Postgres `directory` BackingService (the
 *     Postgres-era guest, i.e. authproto). `apply` runs the same check first.
 *
 *   bun deploy/guest/runtime-secrets.ts apply --values <file> --kubeconfig <path> --tenant <name>
 *       [--context <name>] [--config <file>]
 *     Runs `preflight`, writes the control Secret of the workload the config names with those
 *     values, and rolls the workload onto them.
 *     Run it on its own to recover when a deploy stopped after deleting or resetting the Secret.
 *
 *   bun deploy/guest/runtime-secrets.ts names --values <file>
 *     Checks a values file (mode 0600, known names, required names) and lists its names.
 *
 * The rules and the reasons for this Secret are in deploy/platform/components/control-secret.ts,
 * which the Pulumi program uses too. The Secret document goes to kubectl on stdin; no value is
 * written to disk (other than by `generate`), put in an argument list, or printed.
 */
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  applyRuntimeSecrets,
  assertDeployable,
  assertPrivateMode,
  COLUMN_KEY_NAMES,
  ensurePgliteKey,
  type Kubectl,
  newPgliteKey,
  type PgliteKeyCheck,
  PLAINTEXT_OPT_OUT,
  parseGuestConfig,
  parseRuntimeValues,
  pgliteKeyCheckValues,
  refuseLegacyTenant,
} from '../platform/components/control-secret.ts';

const { positionals, values: args } = parseArgs({
  allowPositionals: true,
  options: {
    out: { type: 'string' },
    values: { type: 'string' },
    origin: { type: 'string' },
    issuer: { type: 'string' },
    'smtp-host': { type: 'string' },
    'redirect-uris': { type: 'string' },
    kubeconfig: { type: 'string' },
    context: { type: 'string' },
    tenant: { type: 'string' },
    config: {
      type: 'string',
      default: join(import.meta.dir, '..', '..', 'apps', 'guest', 'di-framework.config.json'),
    },
    'column-encryption': { type: 'boolean', default: false },
    'plaintext-pglite': { type: 'boolean', default: false },
    enable: { type: 'boolean', default: false },
  },
});

function required(name: keyof typeof args): string {
  const value = args[name];
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`--${name} is required`);
  return value;
}

const secret = (bytes: number) => randomBytes(bytes).toString('base64url');
/** A column encryption key: 32 random bytes, base64. */
const columnKey = () => randomBytes(32).toString('base64');

/** RS256 private JWK with `kid` = RFC 7638 thumbprint, as the guest expects. */
function signingJwk(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' }) as Record<string, string>;
  const kid = createHash('sha256')
    .update(JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n }))
    .digest('base64url');
  return JSON.stringify({ ...jwk, kid, alg: 'RS256', use: 'sig' });
}

function readValues(path: string): Record<string, string> {
  assertPrivateMode(statSync(path).mode, path);
  return parseRuntimeValues(readFileSync(path, 'utf8'), path);
}

/** kubectl bound to --kubeconfig/--context; stdout is returned, never printed. */
const kubectl: Kubectl = async (argv, input) => {
  const base = [
    '--kubeconfig',
    required('kubeconfig'),
    ...(args.context ? ['--context', args.context] : []),
  ];
  const child = Bun.spawn(['kubectl', ...base, ...argv], {
    stdin: input === undefined ? 'ignore' : new Blob([input]),
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [stdout, stderr] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { code: await child.exited, stdout, stderr };
};

const PGLITE_KEY_CHECK_MESSAGES: Record<PgliteKeyCheck, (secret: string) => string> = {
  new: (secret) => `${secret} had no DI_PGLITE_KEY yet`,
  matched: (secret) => `${secret} already holds this DI_PGLITE_KEY (same KCV)`,
  rotation: (secret) =>
    `rotation: ${secret} holds the values' DI_PGLITE_KEY_PREVIOUS; the guest re-wraps its files on the next start`,
  unverified: (secret) =>
    `cannot read ${secret} as this user, so its DI_PGLITE_KEY was not compared. Replacing it is irreversible: the KCV above must match your custody record`,
};

/** Prints `name KCV <hex>` lines: one-way values that identify a key, safe to record. */
function printKcvs(values: Record<string, string>, stream: typeof console.log = console.log): void {
  for (const [name, kcv] of Object.entries(pgliteKeyCheckValues(values))) {
    stream(`${name} KCV ${kcv}`);
  }
}

/** The values file checked against the guest config; returns the values and the workload. */
function preflight(): { values: Record<string, string>; workload: string } {
  const source = required('values');
  const values = readValues(source);
  const configPath = args.config as string;
  const config = parseGuestConfig(readFileSync(configPath, 'utf8'), configPath);
  assertDeployable(config, values, {
    allowPlaintext: process.env[PLAINTEXT_OPT_OUT] === '1',
    source,
  });
  if (config.encryption === undefined) {
    console.error(
      `warning: ${config.name} is built without pglite.encryption (${PLAINTEXT_OPT_OUT}=1): its data directory is plaintext`,
    );
  }
  return { values, workload: config.name };
}

async function apply(): Promise<void> {
  const { values, workload } = preflight();
  printKcvs(values);
  const result = await applyRuntimeSecrets(kubectl, {
    tenant: required('tenant'),
    workload,
    values,
    token: secret(32),
    revision: createHash('sha256').update(randomBytes(16)).digest('hex').slice(0, 16),
  });
  console.log(PGLITE_KEY_CHECK_MESSAGES[result.pgliteKey](`${workload}-control`));
  console.log(`wrote di-tenant-${args.tenant}/${workload}-control: ${result.names.join(', ')}`);
  console.log(
    `rolled workloaddeployment/${workload} (IDENTITY_RUNTIME_REVISION=${result.revision})`,
  );
}

function generate(): void {
  const out = required('out');
  if (existsSync(out)) throw new Error(`${out} exists; refusing to overwrite runtime secrets`);
  const origin = required('origin').replace(/\/+$/, '');
  const values: Record<string, string> = {
    ISSUER_URL: (args.issuer ?? origin).replace(/\/+$/, ''),
    AUTH_PUBLIC_ORIGIN: origin,
    AUTH_ACTIVE_PRIVATE_JWK: signingJwk(),
    AUTH_ACCESS_REDIRECT_URIS: args['redirect-uris'] ?? 'http://localhost:3000/callback',
    AUTH_BOOTSTRAP_OWNER_PASSWORD: secret(24),
    AUTH_BOOTSTRAP_VIEWER_PASSWORD: secret(24),
    AUTH_ACCESS_CLIENT_SECRET: secret(36),
    AUTH_DIRECTORY_CLIENT_SECRET: secret(36),
    AUTH_PROVISIONER_CLIENT_SECRET: secret(36),
    SMTP_HOST: required('smtp-host'),
    SMTP_PASSWORD: secret(24),
    IDENTITY_COLUMN_KEY: columnKey(),
    IDENTITY_BIDX_KEY: columnKey(),
    ...(args['column-encryption'] ? { IDENTITY_COLUMN_ENCRYPTION: 'enabled' } : {}),
    ...(args['plaintext-pglite'] ? {} : { DI_PGLITE_KEY: newPgliteKey(randomBytes) }),
  };
  writeFileSync(out, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  console.log(`wrote ${out} (mode 0600): ${Object.keys(values).sort().join(', ')}`);
  printKcvs(values);
}

/** Adds DI_PGLITE_KEY when missing (never replacing one) and prints its KCV. */
function pgliteKey(): void {
  const path = required('values');
  const values = readValues(path);
  const added = ensurePgliteKey(values, () => newPgliteKey(randomBytes));
  if (added) writeFileSync(path, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600 });
  console.log(
    added
      ? `updated ${path}: added DI_PGLITE_KEY (for a new data directory only)`
      : `${path} already has DI_PGLITE_KEY; kept it`,
  );
  printKcvs(values);
}

/** Adds missing column keys (never replacing one) and, with --enable, opts in. */
function columnKeys(): void {
  const path = required('values');
  assertPrivateMode(statSync(path).mode, path);
  // Parsed before validation, so a file that opted in without its keys can be repaired here.
  const values = JSON.parse(readFileSync(path, 'utf8')) as Record<string, string>;
  const added: string[] = [];
  for (const name of COLUMN_KEY_NAMES) {
    if (values[name]?.trim()) continue;
    values[name] = columnKey();
    added.push(name);
  }
  if (args.enable) values.IDENTITY_COLUMN_ENCRYPTION = 'enabled';
  parseRuntimeValues(JSON.stringify(values), path);
  writeFileSync(path, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600 });
  console.log(
    `updated ${path}: added ${added.length > 0 ? added.join(', ') : 'no keys'}${
      args.enable ? '; IDENTITY_COLUMN_ENCRYPTION=enabled' : ''
    }`,
  );
}

try {
  switch (positionals[0]) {
    case 'generate':
      generate();
      break;
    case 'guard':
      await refuseLegacyTenant(kubectl, `di-tenant-${required('tenant')}`);
      console.log(`di-tenant-${args.tenant} has no Postgres directory BackingService`);
      break;
    case 'apply':
      await apply();
      break;
    case 'column-keys':
      columnKeys();
      break;
    case 'pglite-key':
      pgliteKey();
      break;
    case 'kcv':
      printKcvs(readValues(required('values')));
      break;
    case 'preflight': {
      const { values, workload } = preflight();
      console.log(workload);
      printKcvs(values, console.error);
      break;
    }
    case 'names':
      console.log(
        Object.keys(readValues(required('values')))
          .sort()
          .join('\n'),
      );
      break;
    default:
      throw new Error(
        'usage: runtime-secrets.ts generate|column-keys|pglite-key|kcv|preflight|guard|apply|names [options]',
      );
  }
} catch (error) {
  console.error(`runtime-secrets: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 2;
}
