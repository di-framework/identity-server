import { afterAll, describe, expect, test } from 'bun:test';
import {
  chmodSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  decodePgliteKey,
  PGLITE_KEY_NAMES,
  parseGuestConfig,
  pgliteKeyCheckValue,
  RUNTIME_SECRET_NAMES,
  VALUE_NAMES,
} from '../platform/components/control-secret.ts';

const root = join(import.meta.dir, '..', '..');
const script = join(import.meta.dir, 'runtime-secrets.ts');
const deployScript = join(import.meta.dir, 'deploy.sh');
const guestConfigPath = join(root, 'apps', 'guest', 'di-framework.config.json');
const work = mkdtempSync(join(tmpdir(), 'identity-runtime-secrets-test-'));
afterAll(() => rmSync(work, { recursive: true, force: true }));

let files = 0;
const fresh = (name: string) => join(work, `${files++}-${name}`);

/** Runs runtime-secrets.ts; the environment never carries a key. */
function run(args: string[], env: Record<string, string> = {}) {
  const child = Bun.spawnSync(['bun', script, ...args], {
    cwd: root,
    env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', ...env },
  });
  return {
    code: child.exitCode,
    stdout: child.stdout.toString(),
    stderr: child.stderr.toString(),
  };
}

function generate(...extra: string[]): { path: string; values: Record<string, string> } {
  const path = fresh('values.json');
  const result = run([
    'generate',
    '--out',
    path,
    '--origin',
    'http://identity.test/',
    '--smtp-host',
    'smtp.test',
    ...extra,
  ]);
  expect(result.code).toBe(0);
  const values = JSON.parse(readFileSync(path, 'utf8')) as Record<string, string>;
  for (const secret of Object.values(values).filter((value) => value.length >= 24)) {
    expect(result.stdout + result.stderr).not.toContain(secret);
  }
  return { path, values };
}

/** Every value in `output`, which must hold names and KCVs only. */
function expectNoValues(output: string, values: Record<string, string>): void {
  for (const value of Object.values(values).filter((value) => value.length >= 24)) {
    expect(output).not.toContain(value);
  }
}

describe('runtime-secrets.ts', () => {
  test('generate writes a data directory key, prints its KCV and never the key', () => {
    const { path, values } = generate();
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const key = values.DI_PGLITE_KEY as string;
    expect(decodePgliteKey(key)?.length).toBe(32);
    expect(key).not.toBe(values.IDENTITY_COLUMN_KEY);
    expect(key).not.toBe(values.IDENTITY_BIDX_KEY);
    const kcv = run(['kcv', '--values', path]);
    expect(kcv.code).toBe(0);
    expect(kcv.stdout).toBe(`DI_PGLITE_KEY KCV ${pgliteKeyCheckValue(key)}\n`);
    expect(generate().values.DI_PGLITE_KEY).not.toBe(key);

    const plaintext = generate('--plaintext-pglite').values;
    expect(Object.keys(plaintext)).not.toContain('DI_PGLITE_KEY');
  });

  test('pglite-key adds a missing key once and keeps it on every later run', () => {
    const { path, values } = generate('--plaintext-pglite');
    const added = run(['pglite-key', '--values', path]);
    expect(added.code).toBe(0);
    expect(added.stdout).toContain('added DI_PGLITE_KEY (for a new data directory only)');
    const before = readFileSync(path, 'utf8');
    const key = (JSON.parse(before) as Record<string, string>).DI_PGLITE_KEY as string;
    expect(decodePgliteKey(key)?.length).toBe(32);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expectNoValues(added.stdout + added.stderr, { ...values, DI_PGLITE_KEY: key });

    const kept = run(['pglite-key', '--values', path]);
    expect(kept.code).toBe(0);
    expect(kept.stdout).toContain('already has DI_PGLITE_KEY; kept it');
    expect(kept.stdout).toContain(`DI_PGLITE_KEY KCV ${pgliteKeyCheckValue(key)}`);
    expect(readFileSync(path, 'utf8')).toBe(before);
  });

  test('preflight checks values against the guest config and prints the workload', () => {
    const { path, values } = generate();
    const ok = run(['preflight', '--values', path]);
    expect(ok.code).toBe(0);
    expect(ok.stdout).toBe('identity\n');
    expect(ok.stderr).toBe(
      `DI_PGLITE_KEY KCV ${pgliteKeyCheckValue(values.DI_PGLITE_KEY as string)}\n`,
    );

    const keyless = generate('--plaintext-pglite').path;
    const refused = run(['preflight', '--values', keyless]);
    expect(refused.code).toBe(2);
    expect(refused.stderr).toContain('has no DI_PGLITE_KEY');

    // A development guest built without pglite.encryption: refused unless opted out.
    const config = JSON.parse(readFileSync(guestConfigPath, 'utf8'));
    delete config.pglite.encryption;
    const plaintextConfig = fresh('di-framework.config.json');
    writeFileSync(plaintextConfig, JSON.stringify(config));
    const notOptedOut = run(['preflight', '--values', keyless, '--config', plaintextConfig]);
    expect(notOptedOut.code).toBe(2);
    expect(notOptedOut.stderr).toContain('set IDENTITY_PGLITE_PLAINTEXT=1');
    const optedOut = run(['preflight', '--values', keyless, '--config', plaintextConfig], {
      IDENTITY_PGLITE_PLAINTEXT: '1',
    });
    expect(optedOut.code).toBe(0);
    expect(optedOut.stderr).toContain('warning: identity is built without pglite.encryption');
    const keyed = run(['preflight', '--values', path, '--config', plaintextConfig], {
      IDENTITY_PGLITE_PLAINTEXT: '1',
    });
    expect(keyed.code).toBe(2);
    expect(keyed.stderr).toContain('so its data directory is encrypted');

    chmodSync(path, 0o644);
    expect(run(['preflight', '--values', path]).stderr).toContain('chmod 600 it');
  });

  test('an unknown command prints the usage', () => {
    const result = run(['rotate']);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain('generate|column-keys|pglite-key|kcv|preflight');
  });
});

describe('the committed guest config', () => {
  const config = parseGuestConfig(readFileSync(guestConfigPath, 'utf8'), guestConfigPath);

  test('encrypts the data directory at rest by default, with the pinned pglite-encfs', () => {
    expect(config.encryption).toBe(
      'ghcr.io/di-framework/pglite-encfs@sha256:46863e8bc92be13104f4be1b489f5500ba008f51f4662f382a211f7a78a5d414',
    );
  });

  test('declares every runtime value and both data directory keys in controlSecretKeys', () => {
    expect(config.controlSecretKeys).toEqual([...VALUE_NAMES]);
    expect(VALUE_NAMES).toEqual([...RUNTIME_SECRET_NAMES, ...PGLITE_KEY_NAMES]);
    expect(config.controlSecretKeys).toContain('DI_PGLITE_KEY');
    expect(config.controlSecretKeys).toContain('DI_PGLITE_KEY_PREVIOUS');
    // The column encryption keys stay alongside.
    expect(config.controlSecretKeys).toContain('IDENTITY_COLUMN_KEY');
    expect(config.controlSecretKeys).toContain('IDENTITY_BIDX_KEY');
  });
});

describe('deploy.sh', () => {
  /** kubectl and di-framework stand-ins that record their arguments and kubectl's stdin. */
  function stubs(): { bin: string; calls: string } {
    const bin = fresh('bin');
    const calls = fresh('calls');
    Bun.spawnSync(['mkdir', '-p', bin, calls]);
    const record = (name: string, body: string) => {
      const path = join(bin, name);
      writeFileSync(
        path,
        `#!/bin/sh\nn=$(ls "${calls}" | wc -l | tr -d ' ')\nprintf '%s\\n' "${name} $*" >"${calls}/$n.args"\n${body}\n`,
        { mode: 0o755 },
      );
    };
    // STUB_DEPLOY_EXIT makes `platform deploy` stop as the CLI does when its readiness wait ends.
    record(
      'di-framework',
      `case "$*" in "platform deploy"*) if [ -n "\${STUB_DEPLOY_EXIT:-}" ]; then echo "WorkloadDeployment x did not become ready"; exit "$STUB_DEPLOY_EXIT"; fi ;; esac\nexit 0`,
    );
    // STUB_READY is what the WorkloadDeployment's Ready condition reads (default True).
    record(
      'kubectl',
      `case "$*" in *" create --raw "*|*" replace --raw "*) cat >"${calls}/$n.stdin" ;; *" get workloaddeployment "*) printf '%s' "\${STUB_READY:-True}" ;; esac\nexit 0`,
    );
    return { bin, calls };
  }

  test('keeps the values, data directory key included, across deploys and never deletes the Secret', () => {
    const { path, values } = generate();
    const before = readFileSync(path, 'utf8');
    const { bin, calls } = stubs();
    const deploy = () =>
      Bun.spawnSync(['sh', deployScript, 'pgprove', 'pgprove', path], {
        cwd: root,
        env: {
          PATH: `${bin}:${process.env.PATH ?? ''}`,
          HOME: process.env.HOME ?? '',
          IDENTITY_KUBECONFIG: join(work, 'kubeconfig'),
          IDENTITY_KUBE_CONTEXT: 'test',
        },
      });
    for (const _ of [1, 2]) {
      const result = deploy();
      // preflight logs the key's KCV on stderr; nothing else goes there.
      expect(result.stderr.toString()).toBe(
        `DI_PGLITE_KEY KCV ${pgliteKeyCheckValue(values.DI_PGLITE_KEY as string)}\n`,
      );
      expect(result.exitCode).toBe(0);
      expectNoValues(result.stdout.toString() + result.stderr.toString(), values);
    }
    expect(readFileSync(path, 'utf8')).toBe(before);

    const entries = readdirSync(calls).sort(
      (a, b) => Number.parseInt(a, 10) - Number.parseInt(b, 10),
    );
    const argv = entries
      .filter((name) => name.endsWith('.args'))
      .map((name) => readFileSync(join(calls, name), 'utf8').trim());
    expect(argv.some((line) => / delete /.test(line))).toBe(false);
    expect(argv.filter((line) => line === 'di-framework platform build')).toHaveLength(2);
    expect(
      argv.filter(
        (line) => line === 'di-framework platform deploy identity --target identity --yes',
      ),
    ).toHaveLength(2);
    const documents = entries
      .filter((name) => name.endsWith('.stdin'))
      .map((name) => JSON.parse(readFileSync(join(calls, name), 'utf8')));
    expect(documents).toHaveLength(2);
    for (const document of documents) {
      expect(document.metadata.name).toBe('identity-control');
      expect(Buffer.from(String(document.data.DI_PGLITE_KEY), 'base64').toString()).toBe(
        values.DI_PGLITE_KEY as string,
      );
    }
  });

  /** deploy.sh against the stubs, with `extra` in its environment. */
  function deployWith(path: string, bin: string, extra: Record<string, string>) {
    const result = Bun.spawnSync(['sh', deployScript, 'pgprove', 'pgprove', path], {
      cwd: root,
      env: {
        PATH: `${bin}:${process.env.PATH ?? ''}`,
        HOME: process.env.HOME ?? '',
        IDENTITY_KUBECONFIG: join(work, 'kubeconfig'),
        IDENTITY_KUBE_CONTEXT: 'test',
        ...extra,
      },
    });
    return { code: result.exitCode, stderr: result.stderr.toString() };
  }
  const argvOf = (calls: string) =>
    readdirSync(calls)
      .filter((name) => name.endsWith('.args'))
      .map((name) => readFileSync(join(calls, name), 'utf8').trim());

  test('a first deploy that outlasts the CLI readiness wait waits for Ready, then applies', () => {
    const { path } = generate();
    const { bin, calls } = stubs();
    const result = deployWith(path, bin, { STUB_DEPLOY_EXIT: '3' });
    expect(result.code).toBe(0);
    expect(result.stderr).toContain('the CLI stopped waiting for identity to become Ready');
    expect(result.stderr).toContain('identity is Ready after 0s more');
    const argv = argvOf(calls);
    expect(argv.some((line) => line.includes(' get workloaddeployment identity '))).toBe(true);
    expect(argv.some((line) => line.includes('patch workloaddeployment identity'))).toBe(true);
  });

  test('not Ready in time, or another deploy failure, prints the exact recovery command', () => {
    const { path } = generate();
    const notReady = stubs();
    const late = deployWith(path, notReady.bin, {
      STUB_DEPLOY_EXIT: '3',
      STUB_READY: 'False',
      IDENTITY_READY_TIMEOUT: '0',
    });
    expect(late.code).toBe(3);
    const recovery = `run: bun ${script} apply --values ${path} --kubeconfig ${join(work, 'kubeconfig')} --context test --tenant pgprove`;
    expect(late.stderr).toContain(`identity is not Ready after 0s; once it is, ${recovery}`);
    expect(argvOf(notReady.calls).some((line) => line.includes('patch'))).toBe(false);

    const broken = stubs();
    const failed = deployWith(path, broken.bin, { STUB_DEPLOY_EXIT: '2' });
    expect(failed.code).toBe(3);
    expect(failed.stderr).toContain(`deploy of identity failed (exit 2); once fixed, ${recovery}`);
    expect(argvOf(broken.calls).some((line) => line.includes('workloaddeployment'))).toBe(false);
  });

  test('refuses a values file without the data directory key before touching the cluster', () => {
    const { path } = generate('--plaintext-pglite');
    const { bin, calls } = stubs();
    const result = Bun.spawnSync(['sh', deployScript, 'pgprove', 'pgprove', path], {
      cwd: root,
      env: {
        PATH: `${bin}:${process.env.PATH ?? ''}`,
        HOME: process.env.HOME ?? '',
        IDENTITY_KUBECONFIG: join(work, 'kubeconfig'),
        IDENTITY_KUBE_CONTEXT: 'test',
      },
    });
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr.toString()).toContain('has no DI_PGLITE_KEY');
    expect(readdirSync(calls)).toEqual([]);
  });
});
