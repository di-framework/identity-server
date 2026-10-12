#!/usr/bin/env bun
/**
 * Runtime secrets for the identity guest, kept in its `identity-control` Secret.
 *
 *   bun deploy/guest/runtime-secrets.ts generate --out <file> --origin <url> --smtp-host <host>
 *       [--issuer <url>] [--redirect-uris <list>]
 *     Writes a new values file (mode 0600): issuer and origin, an RS256 signing key, bootstrap
 *     passwords, client secrets, SMTP settings. Refuses to overwrite an existing file.
 *
 *   bun deploy/guest/runtime-secrets.ts apply --values <file> --kubeconfig <path> --tenant <name>
 *       [--context <name>] [--workload identity]
 *     Writes the workload's control Secret with those values and rolls the workload onto them.
 *
 *   bun deploy/guest/runtime-secrets.ts names --values <file>
 *     Lists the names in a values file (never the values).
 *
 * Why the control Secret: tenant admission lets a workload without an environment label read
 * only `<workload>-control` through `localResources.environment.secretFrom`, and the platform
 * refuses secrets and URLs in wasi:config. The guest reads these names from its WASI environment
 * (apps/guest/src/settings.ts); they never reach the database.
 *
 * `di-framework platform deploy` (cli-plugin-platform 6.1.2) rewrites that Secret on every deploy
 * with only DI_CONTROL_TOKEN and DI_CONTROL_IDENTITY, so `apply` must run after each deploy. As a
 * tenant developer the CLI cannot replace a control Secret that has extra keys (the platform's
 * `tenant-secret-update` policy refuses a replace that drops a key), so `deploy.sh` deletes the
 * Secret before deploying. The guest fails closed (HTTP 503, naming the missing keys) while the
 * Secret lacks the values.
 *
 * Tenant developers can create, replace and delete Secrets but never read them. `apply` therefore
 * writes the whole Secret blind, like the CLI does: a fresh DI_CONTROL_TOKEN (the identity
 * workload has no cron or queue invokers that use it), DI_CONTROL_IDENTITY, and the values. The
 * document goes to kubectl through a private temporary file; nothing here prints a value.
 */
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

/** Every name the guest reads from its environment (apps/guest/src/settings.ts). */
const KNOWN = new Set([
  'ISSUER_URL',
  'AUTH_PUBLIC_ORIGIN',
  'AUTH_ACTIVE_PRIVATE_JWK',
  'AUTH_PREVIOUS_PUBLIC_JWK_SET',
  'SMTP_HOST',
  'SMTP_USERNAME',
  'SMTP_PASSWORD',
  'AUTH_ACCESS_REDIRECT_URIS',
  'AUTH_BOOTSTRAP_OWNER_PASSWORD',
  'AUTH_BOOTSTRAP_VIEWER_PASSWORD',
  'AUTH_ACCESS_CLIENT_SECRET',
  'AUTH_DIRECTORY_CLIENT_SECRET',
  'AUTH_PROVISIONER_CLIENT_SECRET',
  'AUTH_CLI_CLIENT_ID',
  'AUTH_CLI_REDIRECT_URIS',
]);
const REQUIRED = ['ISSUER_URL', 'AUTH_PUBLIC_ORIGIN', 'AUTH_ACTIVE_PRIVATE_JWK'];
/** WorkloadDeployment config entry that rolls the workload when the values change. */
const REVISION_KEY = 'IDENTITY_RUNTIME_REVISION';

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
    workload: { type: 'string', default: 'identity' },
  },
});

function fail(message: string): never {
  console.error(`runtime-secrets: ${message}`);
  process.exit(2);
}

function required(name: keyof typeof args): string {
  const value = args[name];
  if (typeof value !== 'string' || value.trim() === '') fail(`--${name} is required`);
  return value;
}

const secret = (bytes: number) => randomBytes(bytes).toString('base64url');

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
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail(`${path} must hold a JSON object of names to strings`);
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  const unknown = entries.filter(([name]) => !KNOWN.has(name)).map(([name]) => name);
  if (unknown.length > 0) fail(`unknown names in ${path}: ${unknown.join(', ')}`);
  const notStrings = entries.filter(([, value]) => typeof value !== 'string').map(([n]) => n);
  if (notStrings.length > 0) fail(`values must be strings: ${notStrings.join(', ')}`);
  const missing = REQUIRED.filter((name) => !(parsed as Record<string, string>)[name]?.trim());
  if (missing.length > 0) fail(`missing required names: ${missing.join(', ')}`);
  return parsed as Record<string, string>;
}

async function kubectl(argv: string[]): Promise<{ code: number; stderr: string }> {
  const base = [
    '--kubeconfig',
    required('kubeconfig'),
    ...(args.context ? ['--context', args.context] : []),
  ];
  const child = Bun.spawn(['kubectl', ...base, ...argv], { stdout: 'ignore', stderr: 'pipe' });
  const stderr = await new Response(child.stderr).text();
  return { code: await child.exited, stderr };
}

async function apply(): Promise<void> {
  const values = readValues(required('values'));
  const tenant = required('tenant');
  const workload = args.workload as string;
  const namespace = `di-tenant-${tenant}`;
  const name = `${workload}-control`;
  const encode = (value: string) => Buffer.from(value, 'utf8').toString('base64');
  const data: Record<string, string> = {
    DI_CONTROL_TOKEN: encode(secret(32)),
    DI_CONTROL_IDENTITY: encode(workload),
  };
  for (const [key, value] of Object.entries(values)) data[key] = encode(value);
  const document = {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name,
      namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'di-framework',
        'app.kubernetes.io/name': workload,
      },
    },
    type: 'Opaque',
    data,
  };
  const directory = mkdtempSync(join(tmpdir(), 'identity-control-'));
  const path = join(directory, 'secret.json');
  const collection = `/api/v1/namespaces/${namespace}/secrets`;
  try {
    writeFileSync(path, JSON.stringify(document), { mode: 0o600 });
    const created = await kubectl(['create', '--raw', collection, '-f', path]);
    if (created.code !== 0) {
      if (!/AlreadyExists/.test(created.stderr)) {
        fail(`creating ${name} failed (exit ${created.code})`);
      }
      const replaced = await kubectl(['replace', '--raw', `${collection}/${name}`, '-f', path]);
      if (replaced.code !== 0) fail(`replacing ${name} failed (exit ${replaced.code})`);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  console.log(`wrote ${namespace}/${name}: ${Object.keys(values).sort().join(', ')}`);

  // The running instance keeps the environment it started with; a changed template rolls it.
  const revision = createHash('sha256')
    .update(JSON.stringify(Object.entries(values).sort()))
    .update(String(Date.now()))
    .digest('hex')
    .slice(0, 16);
  // The CLI renders environment config for every pglite workload; add the map itself if not.
  const environment = '/spec/template/spec/components/0/localResources/environment';
  const attempts = [
    [{ op: 'add', path: `${environment}/config/${REVISION_KEY}`, value: revision }],
    [{ op: 'add', path: `${environment}/config`, value: { [REVISION_KEY]: revision } }],
  ];
  let patched = { code: 1, stderr: '' };
  for (const patch of attempts) {
    patched = await kubectl([
      '--namespace',
      namespace,
      'patch',
      'workloaddeployment',
      workload,
      '--type',
      'json',
      '-p',
      JSON.stringify(patch),
    ]);
    if (patched.code === 0) break;
  }
  if (patched.code !== 0) {
    fail(`rolling workloaddeployment/${workload} failed: ${patched.stderr.trim().slice(0, 300)}`);
  }
  console.log(`rolled workloaddeployment/${workload} (${REVISION_KEY}=${revision})`);
}

function generate(): void {
  const out = required('out');
  if (existsSync(out)) fail(`${out} exists; refusing to overwrite runtime secrets`);
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
  };
  writeFileSync(out, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  console.log(`wrote ${out} (mode 0600): ${Object.keys(values).sort().join(', ')}`);
}

switch (positionals[0]) {
  case 'generate':
    generate();
    break;
  case 'apply':
    await apply();
    break;
  case 'names':
    console.log(
      Object.keys(readValues(required('values')))
        .sort()
        .join('\n'),
    );
    break;
  default:
    fail('usage: runtime-secrets.ts generate|apply|names [options]; see the header comment');
}
