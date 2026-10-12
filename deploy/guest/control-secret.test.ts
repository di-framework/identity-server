import { expect, test } from 'bun:test';
import { readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import {
  applyRuntimeSecrets,
  assertPrivateMode,
  controlSecretDocument,
  type Kubectl,
  type KubectlResult,
  parseRuntimeValues,
  REQUIRED_RUNTIME_SECRETS,
  REVISION_KEY,
  refuseLegacyTenant,
  rollWorkload,
  writeControlSecret,
} from '../platform/components/control-secret.ts';

const VALUES = {
  ISSUER_URL: 'http://identity.test',
  AUTH_PUBLIC_ORIGIN: 'http://identity.test',
  AUTH_ACTIVE_PRIVATE_JWK: 'private-key-material',
  AUTH_ACCESS_CLIENT_SECRET: 'client-secret-material',
};
const SECRET_TEXT = ['private-key-material', 'client-secret-material', 'token-material'];

interface Call {
  args: string[];
  input?: string;
}

/** A scripted kubectl: each call takes the next result; every call is recorded. */
function scripted(...results: Array<Partial<KubectlResult>>): { kubectl: Kubectl; calls: Call[] } {
  const calls: Call[] = [];
  const kubectl: Kubectl = async (args, input) => {
    calls.push({ args, input });
    const next = results.shift() ?? {};
    return { code: 0, stdout: '', stderr: '', ...next };
  };
  return { kubectl, calls };
}

const tempEntries = () => new Set(readdirSync(tmpdir()));

function expectNoSecretOutside(calls: Call[], error: unknown): void {
  const visible = [String(error), ...calls.flatMap((call) => call.args)].join('\n');
  for (const text of SECRET_TEXT) expect(visible).not.toContain(text);
}

test('values files: known names, strings, required names, owner-only mode', () => {
  expect(parseRuntimeValues(JSON.stringify(VALUES), 'v.json')).toEqual(VALUES);
  expect(() => parseRuntimeValues('{', 'v.json')).toThrow('v.json is not JSON');
  expect(() => parseRuntimeValues('[]', 'v.json')).toThrow('must hold a JSON object');
  expect(() => parseRuntimeValues('null', 'v.json')).toThrow('must hold a JSON object');
  expect(() => parseRuntimeValues(JSON.stringify({ ...VALUES, DATABASE_URL: 'x' }), 'v')).toThrow(
    'unknown names in v: DATABASE_URL',
  );
  expect(() => parseRuntimeValues(JSON.stringify({ ...VALUES, SMTP_HOST: 1 }), 'v')).toThrow(
    'values must be strings: SMTP_HOST',
  );
  expect(() => parseRuntimeValues(JSON.stringify({ ISSUER_URL: 'x' }), 'v')).toThrow(
    `missing required names: ${REQUIRED_RUNTIME_SECRETS.slice(1).join(', ')}`,
  );
  expect(() => assertPrivateMode(0o100600, 'v')).not.toThrow();
  expect(() => assertPrivateMode(0o100400, 'v')).not.toThrow();
  expect(() => assertPrivateMode(0o100640, 'v')).toThrow('(mode 640); chmod 600 it');
  expect(() => assertPrivateMode(0o100604, 'v')).toThrow('(mode 604)');
});

test('a tenant with the Postgres directory BackingService is refused, and so is a failed check', async () => {
  const clean = scripted({ stdout: '' });
  await refuseLegacyTenant(clean.kubectl, 'di-tenant-pgprove');
  expect(clean.calls[0]?.args).toEqual([
    '--namespace',
    'di-tenant-pgprove',
    'get',
    'backingservices.platform.di-framework.dev',
    'directory',
    '--ignore-not-found',
    '-o',
    'name',
  ]);

  const legacy = scripted({ stdout: 'backingservice.platform.di-framework.dev/directory\n' });
  await expect(refuseLegacyTenant(legacy.kubectl, 'di-tenant-identity')).rejects.toThrow(
    'di-tenant-identity has the Postgres BackingService `directory`',
  );

  const forbidden = scripted({ code: 1, stderr: 'Forbidden' });
  await expect(refuseLegacyTenant(forbidden.kubectl, 'di-tenant-x')).rejects.toThrow(
    'cannot check di-tenant-x',
  );

  // The guard runs before anything is written: a legacy tenant gets no Secret and no roll.
  const guarded = scripted({ stdout: 'backingservice.platform.di-framework.dev/directory' });
  await expect(
    applyRuntimeSecrets(guarded.kubectl, {
      tenant: 'identity',
      workload: 'identity',
      values: VALUES,
      token: 'token-material',
      revision: 'r1',
    }),
  ).rejects.toThrow('refusing to deploy');
  expect(guarded.calls).toHaveLength(1);
});

test('the Secret goes to kubectl on stdin, never into a file or an argument', async () => {
  const before = tempEntries();
  const { kubectl, calls } = scripted({ code: 0 });
  await writeControlSecret(kubectl, {
    namespace: 'di-tenant-pgprove',
    workload: 'identity',
    values: VALUES,
    token: 'token-material',
  });
  expect(calls).toHaveLength(1);
  expect(calls[0]?.args).toEqual([
    'create',
    '--raw',
    '/api/v1/namespaces/di-tenant-pgprove/secrets',
    '-f',
    '-',
  ]);
  const document = JSON.parse(calls[0]?.input ?? '{}') as {
    metadata: { name: string; namespace: string };
    data: Record<string, string>;
  };
  expect(document.metadata).toMatchObject({
    name: 'identity-control',
    namespace: 'di-tenant-pgprove',
  });
  expect(Object.keys(document.data).sort()).toEqual(
    ['DI_CONTROL_IDENTITY', 'DI_CONTROL_TOKEN', ...Object.keys(VALUES)].sort(),
  );
  expect(Buffer.from(document.data.AUTH_ACTIVE_PRIVATE_JWK ?? '', 'base64').toString()).toBe(
    'private-key-material',
  );
  expectNoSecretOutside(calls, '');
  expect([...tempEntries()].filter((name) => !before.has(name))).toEqual([]);
});

test('an existing Secret is replaced; a failed create or replace leaves no secret file behind', async () => {
  const options = {
    namespace: 'di-tenant-pgprove',
    workload: 'identity',
    values: VALUES,
    token: 'token-material',
  };
  const replaced = scripted({ code: 1, stderr: 'Error from server (AlreadyExists): exists' }, {});
  await writeControlSecret(replaced.kubectl, options);
  expect(replaced.calls.map((call) => call.args.slice(0, 3))).toEqual([
    ['create', '--raw', '/api/v1/namespaces/di-tenant-pgprove/secrets'],
    ['replace', '--raw', '/api/v1/namespaces/di-tenant-pgprove/secrets/identity-control'],
  ]);
  expect(replaced.calls[1]?.input).toBe(replaced.calls[0]?.input);

  const before = tempEntries();
  const createFails = scripted({ code: 1, stderr: 'Error from server (Forbidden): no' });
  const createError = await writeControlSecret(createFails.kubectl, options).catch((e) => e);
  expect(String(createError)).toContain(
    'creating di-tenant-pgprove/identity-control failed (kubectl exit 1)',
  );
  expectNoSecretOutside(createFails.calls, createError);

  const replaceFails = scripted(
    { code: 1, stderr: 'Error from server (AlreadyExists): exists' },
    {
      code: 1,
      stderr: 'tenant users may update a Secret only if it keeps every existing data key',
    },
  );
  const replaceError = await writeControlSecret(replaceFails.kubectl, options).catch((e) => e);
  expect(String(replaceError)).toContain('replacing di-tenant-pgprove/identity-control failed');
  expectNoSecretOutside(replaceFails.calls, replaceError);
  expect([...tempEntries()].filter((name) => !before.has(name))).toEqual([]);
});

test('the roll sets only the revision key and adds the config map only when it is missing', async () => {
  const path = '/spec/template/spec/components/0/localResources/environment';
  const operations = (call?: Call) => JSON.parse(call?.args.at(-1) ?? '[]');
  const options = { namespace: 'di-tenant-pgprove', workload: 'identity', revision: 'abc' };

  const direct = scripted({});
  await rollWorkload(direct.kubectl, options);
  expect(direct.calls).toHaveLength(1);
  expect(operations(direct.calls[0])).toEqual([
    { op: 'add', path: `${path}/config/${REVISION_KEY}`, value: 'abc' },
  ]);

  const missing = scripted(
    { code: 1, stderr: 'The request is invalid: doc is missing path: "/spec/…/config"' },
    {},
  );
  await rollWorkload(missing.kubectl, options);
  expect(operations(missing.calls[1])).toEqual([
    { op: 'add', path: `${path}/config`, value: { [REVISION_KEY]: 'abc' } },
  ]);

  // Any other failure (a webhook timeout, a conflict) must not fall back to replacing the map,
  // which would drop DI_PGLITE_DATA_DIR and the rest of the environment config.
  const transient = scripted({ code: 1, stderr: 'Internal error: webhook timed out' });
  await expect(rollWorkload(transient.kubectl, options)).rejects.toThrow('webhook timed out');
  expect(transient.calls).toHaveLength(1);

  const stillMissing = scripted(
    { code: 1, stderr: "path doesn't exist" },
    { code: 1, stderr: 'environment missing too' },
  );
  await expect(rollWorkload(stillMissing.kubectl, options)).rejects.toThrow(
    'environment missing too',
  );
});

test('apply guards, writes and rolls, and reports names only', async () => {
  const { kubectl, calls } = scripted({ stdout: '' }, {}, {});
  const result = await applyRuntimeSecrets(kubectl, {
    tenant: 'pgprove',
    workload: 'identity',
    values: VALUES,
    token: 'token-material',
    revision: 'r2',
  });
  expect(result).toEqual({ names: Object.keys(VALUES).sort(), revision: 'r2' });
  expect(calls.map((call) => call.args[2] ?? call.args[0])).toEqual([
    'get',
    '/api/v1/namespaces/di-tenant-pgprove/secrets',
    'patch',
  ]);
  expect(controlSecretDocument('n', 'w', {}, 't')).toContain('"w-control"');
});
