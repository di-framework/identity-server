import { describe, expect, test } from 'bun:test';
import { readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import {
  applyRuntimeSecrets,
  assertColumnEncryption,
  assertDeployable,
  assertPgliteKeys,
  assertPrivateMode,
  COLUMN_KEY_NAMES,
  checkStoredPgliteKey,
  controlSecretDocument,
  decodePgliteKey,
  defaultKubeStateDir,
  ensurePgliteKey,
  type GuestConfig,
  type Kubectl,
  type KubectlResult,
  newPgliteKey,
  PGLITE_KEY_NAMES,
  parseGuestConfig,
  parseRuntimeValues,
  pgliteKeyCheckValue,
  pgliteKeyCheckValues,
  preflightCluster,
  REQUIRED_RUNTIME_SECRETS,
  REVISION_KEY,
  refuseLegacyTenant,
  resolveKubeTarget,
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

/** Temp entries that could hold a Secret document (other processes share $TMPDIR). */
const tempEntries = () =>
  new Set(readdirSync(tmpdir()).filter((name) => /identity|control|secret/i.test(name)));

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

test('column encryption values: valid keys, distinct keys, and the switch needs both', () => {
  const column = Buffer.alloc(32, 1).toString('base64');
  const bidx = Buffer.alloc(32, 2).toString('base64');
  const keyed = { ...VALUES, IDENTITY_COLUMN_KEY: column, IDENTITY_BIDX_KEY: bidx };
  expect(COLUMN_KEY_NAMES).toEqual(['IDENTITY_COLUMN_KEY', 'IDENTITY_BIDX_KEY']);
  expect(parseRuntimeValues(JSON.stringify(keyed), 'v')).toEqual(keyed);
  const enabled = { ...keyed, IDENTITY_COLUMN_ENCRYPTION: 'enabled' };
  expect(parseRuntimeValues(JSON.stringify(enabled), 'v')).toEqual(enabled);
  expect(() =>
    assertColumnEncryption({ IDENTITY_COLUMN_ENCRYPTION: 'disabled' }, 'v'),
  ).not.toThrow();
  expect(() => assertColumnEncryption({ IDENTITY_COLUMN_ENCRYPTION: 'on' }, 'v')).toThrow(
    'IDENTITY_COLUMN_ENCRYPTION in v must be enabled or disabled',
  );
  expect(() => assertColumnEncryption({ IDENTITY_COLUMN_KEY: 'c2hvcnQ=' }, 'v')).toThrow(
    'IDENTITY_COLUMN_KEY in v must be at least 32 random bytes, base64 encoded',
  );
  expect(() =>
    assertColumnEncryption({ IDENTITY_COLUMN_KEY: column, IDENTITY_BIDX_KEY: column }, 'v'),
  ).toThrow('must differ');
  const missing = (() => {
    try {
      assertColumnEncryption(
        { IDENTITY_COLUMN_ENCRYPTION: 'enabled', IDENTITY_COLUMN_KEY: column },
        'v',
      );
    } catch (error) {
      return String(error);
    }
  })();
  expect(missing).toContain('needs IDENTITY_COLUMN_KEY and IDENTITY_BIDX_KEY');
  expect(missing).not.toContain(column);
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
  expect(result).toEqual({
    names: Object.keys(VALUES).sort(),
    revision: 'r2',
    pgliteKey: 'unverified',
  });
  expect(calls.map((call) => call.args[2] ?? call.args[0])).toEqual([
    'get',
    'auth',
    '/api/v1/namespaces/di-tenant-pgprove/secrets',
    'patch',
  ]);
  expect(controlSecretDocument('n', 'w', {}, 't')).toContain('"w-control"');
});

describe('the Pulumi preflight before any resource', () => {
  const state = '/state/di-framework-kube';
  const io = (files: string[], result: Partial<KubectlResult> = {}) => {
    const calls: Array<{ kubeconfig: string; context?: string; args: string[] }> = [];
    return {
      calls,
      io: {
        exists: (path: string) => files.includes(path),
        kubectl: (kubeconfig: string, context: string | undefined, args: string[]) => {
          calls.push({ kubeconfig, context, args });
          return { code: 0, stdout: '', stderr: '', ...result };
        },
      },
    };
  };

  test('refuses the authproto instance by name, without touching the cluster', () => {
    const probe = io([`${state}/authproto`, `${state}/authproto/kubeconfig`]);
    expect(() => preflightCluster({ instance: 'authproto', stateDir: state }, probe.io)).toThrow(
      'kubeInstance authproto runs the Postgres-era identity guest',
    );
    expect(probe.calls).toEqual([]);
  });

  test('a managed instance that does not exist yet is new', () => {
    const probe = io([]);
    expect(preflightCluster({ instance: 'fresh', stateDir: state }, probe.io)).toBe('new-instance');
    expect(probe.calls).toEqual([]);
  });

  test('an existing managed instance is checked through its kubeconfig in the state directory', () => {
    const files = [`${state}/other`, `${state}/other/kubeconfig`];
    const clean = io(files, { stdout: 'di-tenant-other/cache\n' });
    expect(preflightCluster({ instance: 'other', stateDir: state }, clean.io)).toBe('checked');
    expect(clean.calls[0]?.kubeconfig).toBe(`${state}/other/kubeconfig`);
    expect(clean.calls[0]?.args.slice(0, 3)).toEqual([
      'get',
      'backingservices.platform.di-framework.dev',
      '--all-namespaces',
    ]);

    // A `directory` in any namespace refuses: `kube up` rewrites the whole platform install.
    const legacy = io(files, { stdout: 'di-tenant-pgprove/cache\ndi-tenant-identity/directory\n' });
    expect(() => preflightCluster({ instance: 'other', stateDir: state }, legacy.io)).toThrow(
      'other has the Postgres BackingService di-tenant-identity/directory',
    );

    const down = io(files, { code: 1 });
    expect(() => preflightCluster({ instance: 'other', stateDir: state }, down.io)).toThrow(
      'cannot list BackingServices on other (kubectl exit 1)',
    );
  });

  test('an existing instance without a kubeconfig fails closed', () => {
    const probe = io([`${state}/broken`]);
    expect(() => preflightCluster({ instance: 'broken', stateDir: state }, probe.io)).toThrow(
      'kube instance broken exists in /state/di-framework-kube but has no kubeconfig',
    );
    expect(probe.calls).toEqual([]);
  });

  test('an existing cluster named by kubeconfig is checked even when the instance is new', () => {
    const legacy = io([], { stdout: 'di-tenant-identity/directory' });
    expect(() =>
      preflightCluster(
        { instance: 'new-name', stateDir: state, kubeconfig: '/kc', context: 'ctx' },
        legacy.io,
      ),
    ).toThrow('Refusing');
    expect(legacy.calls[0]).toMatchObject({ kubeconfig: '/kc', context: 'ctx' });
  });

  test("kube's default state directory follows Go's os.UserConfigDir", () => {
    expect(defaultKubeStateDir('darwin', '/Users/u', {})).toBe(
      '/Users/u/Library/Application Support/di-framework-kube',
    );
    expect(defaultKubeStateDir('linux', '/home/u', {})).toBe('/home/u/.config/di-framework-kube');
    expect(defaultKubeStateDir('linux', '/home/u', { XDG_CONFIG_HOME: '/xdg' })).toBe(
      '/xdg/di-framework-kube',
    );
    expect(defaultKubeStateDir('win32', 'C:\\Users\\u', { AppData: 'D:\\AD' })).toBe(
      'D:\\AD\\di-framework-kube',
    );
    expect(defaultKubeStateDir('win32', 'C:\\Users\\u', {})).toBe(
      'C:\\Users\\u\\AppData\\Roaming\\di-framework-kube',
    );
  });
});

describe('one resolved kube target for the preflight and for kube', () => {
  const host = {
    resolve: (path: string) => (path.startsWith('/') ? path : `/project/deploy/platform/${path}`),
    platform: 'darwin',
    home: '/Users/u',
    env: {},
  };
  const defaultDir = '/Users/u/Library/Application Support/di-framework-kube';
  /** What runKube passes: `--state-dir` only for a non-empty value, else kube's default. */
  const kubeStateDirUsed = (stateDir: string | undefined) => stateDir || defaultDir;

  test('empty kubeStateDir and kubeconfig are unset, so the check runs on the instance kube upgrades', () => {
    const target = resolveKubeTarget(
      { kubeInstance: 'other', kubeStateDir: '', kubeconfig: '', context: '' },
      host,
    );
    expect(target).toEqual({
      instance: 'other',
      configuredStateDir: undefined,
      stateDir: defaultDir,
      kubeconfig: undefined,
      context: undefined,
    });
    expect(target.stateDir).toBe(kubeStateDirUsed(target.configuredStateDir));

    const kubectlCalls: string[] = [];
    const files = [`${defaultDir}/other`, `${defaultDir}/other/kubeconfig`];
    expect(() =>
      preflightCluster(target, {
        exists: (path) => files.includes(path),
        kubectl: (kubeconfig) => {
          kubectlCalls.push(kubeconfig);
          return { code: 0, stdout: 'di-tenant-identity/directory', stderr: '' };
        },
      }),
    ).toThrow('Refusing');
    expect(kubectlCalls).toEqual([`${defaultDir}/other/kubeconfig`]);
  });

  test('relative paths resolve once, to the same absolute paths for the preflight and kube', () => {
    const target = resolveKubeTarget(
      { kubeInstance: 'other', kubeStateDir: 'state', kubeconfig: '../kc', context: 'ctx' },
      host,
    );
    expect(target).toEqual({
      instance: 'other',
      configuredStateDir: '/project/deploy/platform/state',
      stateDir: '/project/deploy/platform/state',
      kubeconfig: '/project/deploy/platform/../kc',
      context: 'ctx',
    });
    expect(target.stateDir).toBe(kubeStateDirUsed(target.configuredStateDir));
    expect(resolveKubeTarget({}, host).instance).toBe('identity');
    expect(resolveKubeTarget({ kubeInstance: '  ' }, host).instance).toBe('identity');
  });

  test('values are trimmed, so a padded authproto is refused by the name check itself', () => {
    const target = resolveKubeTarget(
      { kubeInstance: ' authproto ', kubeStateDir: ' state ', kubeconfig: ' ', context: ' ctx ' },
      host,
    );
    expect(target).toMatchObject({
      instance: 'authproto',
      stateDir: '/project/deploy/platform/state',
      kubeconfig: undefined,
      context: 'ctx',
    });
    const calls: string[] = [];
    expect(() =>
      preflightCluster(target, {
        exists: () => true,
        kubectl: (kubeconfig) => {
          calls.push(kubeconfig);
          return { code: 0, stdout: '', stderr: '' };
        },
      }),
    ).toThrow('kubeInstance authproto runs the Postgres-era identity guest');
    expect(calls).toEqual([]);
  });
});

/** 0x00..0x1f: its KCV below was computed independently (Python hmac, RFC 5869 HKDF). */
const PGLITE_KEY = Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString('base64');
const PGLITE_KCV = 'f9e35e24255015d6477a445dec381e8c';
const OTHER_PGLITE_KEY = Buffer.alloc(32, 7).toString('base64');

describe('pglite-encfs keys', () => {
  test('decode as the layer does: 32 bytes, standard or URL-safe, padding optional', () => {
    const urlSafe = Buffer.alloc(32, 0xfb).toString('base64url');
    expect(urlSafe).toMatch(/[-_]/);
    expect(decodePgliteKey(PGLITE_KEY)?.length).toBe(32);
    expect(decodePgliteKey(` ${PGLITE_KEY.replace(/=$/, '')}\n`)?.length).toBe(32);
    expect(decodePgliteKey(urlSafe)).toEqual(Buffer.alloc(32, 0xfb));
    expect(decodePgliteKey(Buffer.alloc(31).toString('base64'))).toBeUndefined();
    expect(decodePgliteKey(Buffer.alloc(33).toString('base64'))).toBeUndefined();
    expect(decodePgliteKey(`${'A'.repeat(42)}B=`)).toBeUndefined(); // non-canonical tail bits
    expect(decodePgliteKey(`${'+'.repeat(21)}${'_'.repeat(22)}`)).toBeUndefined(); // mixed
    expect(decodePgliteKey('')).toBeUndefined();
  });

  test('the KCV is HKDF-SHA256(salt di-framework/encfs/v1, info key-check-value), 16 bytes', () => {
    expect(pgliteKeyCheckValue(PGLITE_KEY)).toBe(PGLITE_KCV);
    expect(pgliteKeyCheckValue(PGLITE_KEY.replace(/=$/, ''))).toBe(PGLITE_KCV);
    expect(pgliteKeyCheckValue(OTHER_PGLITE_KEY)).not.toBe(PGLITE_KCV);
    expect(() => pgliteKeyCheckValue('not-a-key')).toThrow('DI_PGLITE_KEY must be 32 random');
    expect(
      pgliteKeyCheckValues({
        ...VALUES,
        DI_PGLITE_KEY: OTHER_PGLITE_KEY,
        DI_PGLITE_KEY_PREVIOUS: PGLITE_KEY,
      }),
    ).toEqual({
      DI_PGLITE_KEY: pgliteKeyCheckValue(OTHER_PGLITE_KEY),
      DI_PGLITE_KEY_PREVIOUS: PGLITE_KCV,
    });
    expect(pgliteKeyCheckValues(VALUES)).toEqual({});
  });

  test('a new key is 32 random bytes, base64, and an existing key is never replaced', () => {
    const fixed = (size: number) => Buffer.alloc(size, 9);
    expect(newPgliteKey(fixed)).toBe(Buffer.alloc(32, 9).toString('base64'));
    const values: Record<string, string> = { ...VALUES };
    expect(ensurePgliteKey(values, () => PGLITE_KEY)).toBe(true);
    expect(values.DI_PGLITE_KEY).toBe(PGLITE_KEY);
    // A later deploy, or a second run, keeps the key the data directory was encrypted with.
    expect(ensurePgliteKey(values, () => OTHER_PGLITE_KEY)).toBe(false);
    expect(values.DI_PGLITE_KEY).toBe(PGLITE_KEY);
  });

  test('values files accept the keys, validate them and never echo them', () => {
    expect(PGLITE_KEY_NAMES).toEqual(['DI_PGLITE_KEY', 'DI_PGLITE_KEY_PREVIOUS']);
    const keyed = { ...VALUES, DI_PGLITE_KEY: PGLITE_KEY };
    expect(parseRuntimeValues(JSON.stringify(keyed), 'v')).toEqual(keyed);
    const rotating = {
      ...keyed,
      DI_PGLITE_KEY: OTHER_PGLITE_KEY,
      DI_PGLITE_KEY_PREVIOUS: PGLITE_KEY,
    };
    expect(parseRuntimeValues(JSON.stringify(rotating), 'v')).toEqual(rotating);
    const refused = (values: Record<string, string>) => {
      try {
        assertPgliteKeys(values, 'v');
      } catch (error) {
        return String(error);
      }
      throw new Error('accepted');
    };
    const short = Buffer.alloc(16, 3).toString('base64');
    expect(refused({ DI_PGLITE_KEY: short })).toContain(
      'DI_PGLITE_KEY in v must be 32 random bytes, base64 encoded',
    );
    expect(refused({ DI_PGLITE_KEY: PGLITE_KEY, DI_PGLITE_KEY_PREVIOUS: short })).toContain(
      'DI_PGLITE_KEY_PREVIOUS in v must be 32 random bytes',
    );
    expect(refused({ DI_PGLITE_KEY_PREVIOUS: PGLITE_KEY })).toContain(
      'DI_PGLITE_KEY_PREVIOUS in v needs DI_PGLITE_KEY',
    );
    const same = refused({
      DI_PGLITE_KEY: PGLITE_KEY,
      DI_PGLITE_KEY_PREVIOUS: PGLITE_KEY.replace(/=$/, ''),
    });
    expect(same).toContain('must differ');
    for (const message of [same, refused({ DI_PGLITE_KEY: short })]) {
      expect(message).not.toContain(PGLITE_KEY.slice(0, 20));
      expect(message).not.toContain(short.slice(0, 20));
    }
  });
});

describe('guest config and deploy preflight', () => {
  const ENCFS = `ghcr.io/di-framework/pglite-encfs@sha256:${'a'.repeat(64)}`;
  const config = (extra: Record<string, unknown> = {}) =>
    JSON.stringify({ name: 'identity', pglite: { image: 'x' }, ...extra });

  test('parses the name, the pinned layer and controlSecretKeys', () => {
    expect(
      parseGuestConfig(
        config({ controlSecretKeys: ['ISSUER_URL'], pglite: { encryption: { image: ENCFS } } }),
        'c',
      ),
    ).toEqual({ name: 'identity', encryption: ENCFS, controlSecretKeys: ['ISSUER_URL'] });
    expect(parseGuestConfig(config(), 'c')).toEqual({ name: 'identity', controlSecretKeys: [] });
    expect(() => parseGuestConfig(config({ name: 'Identity' }), 'c')).toThrow('c needs a "name"');
    expect(() => parseGuestConfig(config({ controlSecretKeys: 'ISSUER_URL' }), 'c')).toThrow(
      '"controlSecretKeys" must be an array of names',
    );
    expect(() => parseGuestConfig(config({ controlSecretKeys: [1] }), 'c')).toThrow(
      'must be an array of names',
    );
    expect(() =>
      parseGuestConfig(config({ pglite: { encryption: { wasm: 'encfs.wasm' } } }), 'c'),
    ).toThrow('pglite.encryption.wasm is a local build');
    expect(() =>
      parseGuestConfig(
        config({ pglite: { encryption: { image: 'ghcr.io/di-framework/pglite-encfs:0.1.0' } } }),
        'c',
      ),
    ).toThrow('must pin ghcr.io/di-framework/pglite-encfs by digest');
  });

  const encrypted: GuestConfig = {
    name: 'identity',
    encryption: ENCFS,
    controlSecretKeys: [...Object.keys(VALUES), ...PGLITE_KEY_NAMES],
  };
  const plaintext: GuestConfig = { ...encrypted, encryption: undefined };

  test('an encrypted guest needs its key, and every value name declared', () => {
    const keyed = { ...VALUES, DI_PGLITE_KEY: PGLITE_KEY };
    expect(assertDeployable(encrypted, keyed, { allowPlaintext: false, source: 'v' })).toEqual({
      DI_PGLITE_KEY: PGLITE_KCV,
    });
    expect(() =>
      assertDeployable(encrypted, VALUES, { allowPlaintext: true, source: 'v' }),
    ).toThrow('v has no DI_PGLITE_KEY, which the encrypted data directory needs');
    const keyless = (() => {
      try {
        assertDeployable(encrypted, VALUES, { allowPlaintext: false, source: 'v' });
      } catch (error) {
        return String(error);
      }
    })();
    expect(keyless).toContain('If identity already has a data directory');
    expect(keyless).toContain('an encrypted build refuses it (every request answers 503');
    expect(keyless).toContain('docs/configuration.md#existing-plaintext-deployments');
    expect(keyless).toContain('only for a new, empty data directory');
    expect(() =>
      assertDeployable({ ...encrypted, controlSecretKeys: ['ISSUER_URL'] }, keyed, {
        allowPlaintext: false,
        source: 'v',
      }),
    ).toThrow(
      'controlSecretKeys in di-framework.config.json does not declare AUTH_PUBLIC_ORIGIN, AUTH_ACTIVE_PRIVATE_JWK, AUTH_ACCESS_CLIENT_SECRET, DI_PGLITE_KEY from v',
    );
  });

  test('a plaintext guest needs the explicit opt-out and a values file without a key', () => {
    expect(() =>
      assertDeployable(plaintext, VALUES, { allowPlaintext: false, source: 'v' }),
    ).toThrow('has no pglite.encryption, so the data directory would be plaintext');
    expect(assertDeployable(plaintext, VALUES, { allowPlaintext: true, source: 'v' })).toEqual({});
    expect(() =>
      assertDeployable(
        plaintext,
        { ...VALUES, DI_PGLITE_KEY: PGLITE_KEY },
        { allowPlaintext: true, source: 'v' },
      ),
    ).toThrow('v holds DI_PGLITE_KEY, so its data directory is encrypted');
  });
});

describe('the data directory key already in the cluster', () => {
  const options = (values: Record<string, string>) => ({
    namespace: 'di-tenant-pgprove',
    name: 'identity-control',
    values,
  });
  /** `auth can-i` answers yes, then the read returns the stored key (base64 of its text). */
  const readable = (stored?: string, read: Partial<KubectlResult> = {}) =>
    scripted(
      { stdout: 'yes\n' },
      {
        stdout: stored === undefined ? '' : Buffer.from(stored).toString('base64'),
        ...read,
      },
    );
  const keyed = { ...VALUES, DI_PGLITE_KEY: PGLITE_KEY };

  test('a caller that may not read the Secret compares nothing and sends no read', async () => {
    for (const answer of [
      { code: 1, stdout: 'no\n' },
      { code: 0, stdout: 'no\n' },
    ]) {
      const { kubectl, calls } = scripted(answer);
      expect(await checkStoredPgliteKey(kubectl, options(keyed))).toBe('unverified');
      expect(calls).toHaveLength(1);
      expect(calls[0]?.args).toEqual([
        '--namespace',
        'di-tenant-pgprove',
        'auth',
        'can-i',
        'get',
        'secrets/identity-control',
      ]);
    }
  });

  test('no Secret or no key yet, the same key, or a rotation from the stored key', async () => {
    const absent = readable();
    expect(await checkStoredPgliteKey(absent.kubectl, options(keyed))).toBe('new');
    expect(absent.calls[1]?.args).toEqual([
      '--namespace',
      'di-tenant-pgprove',
      'get',
      'secret',
      'identity-control',
      '--ignore-not-found',
      '-o',
      'jsonpath={.data.DI_PGLITE_KEY}',
    ]);
    const same = readable(PGLITE_KEY.replace(/=$/, ''));
    expect(await checkStoredPgliteKey(same.kubectl, options(keyed))).toBe('matched');
    const rotating = readable(PGLITE_KEY);
    expect(
      await checkStoredPgliteKey(
        rotating.kubectl,
        options({ ...VALUES, DI_PGLITE_KEY: OTHER_PGLITE_KEY, DI_PGLITE_KEY_PREVIOUS: PGLITE_KEY }),
      ),
    ).toBe('rotation');
  });

  test('a different key, a dropped key, or a failed read is refused with KCVs only', async () => {
    const message = async (
      stored: string | undefined,
      values: Record<string, string>,
      read = {},
    ) => {
      const { kubectl } = readable(stored, read);
      try {
        await checkStoredPgliteKey(kubectl, options(values));
      } catch (error) {
        const text = String(error);
        for (const key of [PGLITE_KEY, OTHER_PGLITE_KEY])
          expect(text).not.toContain(key.slice(0, 16));
        return text;
      }
      throw new Error('accepted');
    };
    const otherKcv = pgliteKeyCheckValue(OTHER_PGLITE_KEY);
    expect(await message(PGLITE_KEY, { ...VALUES, DI_PGLITE_KEY: OTHER_PGLITE_KEY })).toContain(
      `di-tenant-pgprove/identity-control holds DI_PGLITE_KEY with KCV ${PGLITE_KCV}, the values hold KCV ${otherKcv}`,
    );
    // A previous key that is not the stored one is not a rotation of this volume.
    expect(
      await message(PGLITE_KEY, {
        ...VALUES,
        DI_PGLITE_KEY: OTHER_PGLITE_KEY,
        DI_PGLITE_KEY_PREVIOUS: Buffer.alloc(32, 5).toString('base64'),
      }),
    ).toContain('put that key in DI_PGLITE_KEY_PREVIOUS');
    expect(await message(PGLITE_KEY, VALUES)).toContain(
      `holds DI_PGLITE_KEY (KCV ${PGLITE_KCV}) and the values have none`,
    );
    expect(await message('not-a-key', keyed)).toContain('with KCV invalid');
    expect(await message(undefined, keyed, { code: 1, stderr: 'boom' })).toContain(
      'reading di-tenant-pgprove/identity-control failed (kubectl exit 1); refusing to replace it',
    );
  });

  test('apply checks before it writes: a mismatch changes nothing in the cluster', async () => {
    const { kubectl, calls } = scripted(
      { stdout: '' },
      { stdout: 'yes' },
      { stdout: Buffer.from(PGLITE_KEY).toString('base64') },
    );
    await expect(
      applyRuntimeSecrets(kubectl, {
        tenant: 'pgprove',
        workload: 'identity',
        values: { ...VALUES, DI_PGLITE_KEY: OTHER_PGLITE_KEY },
        token: 'token-material',
        revision: 'r3',
      }),
    ).rejects.toThrow('would lock the guest out');
    expect(calls.map((call) => call.args[2])).toEqual(['get', 'auth', 'get']);
  });
});
