import { afterAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { embeddedMigrations } from '../../apps/guest/src/migrations.ts';
import { pgliteKeyCheckValue } from '../platform/components/control-secret.ts';
import { bridgeModule } from './bridge.ts';
import {
  type ExportTarget,
  exportCommand,
  failure,
  type Run,
  type Snapshot,
  writeExport,
} from './export-core.ts';
import { needlesOf } from './import-core.ts';
import {
  type InstallKubectl,
  type InstallOptions,
  installCommand,
  localTree,
} from './install-core.ts';
import {
  checkProvider,
  composeRunner,
  DATABASE_ROOT,
  DEFAULTS,
  describe as describeError,
  importCommand,
  runSync,
  startRunner,
  tool,
  wasmtimeArgv,
} from './runner.ts';

const work = mkdtempSync(join(tmpdir(), 'identity-cutover-commands-'));
afterAll(() => rmSync(work, { recursive: true, force: true }));
let dirs = 0;
const fresh = (name: string) => join(work, `${dirs++}-${name}`);
const fakeRunner = join(import.meta.dir, 'tests', 'support', 'fake-runner.ts');
const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1)).toString('base64');
const SECRET = 'hunter2-secret-value';

const values = {
  ISSUER_URL: 'https://issuer.test',
  AUTH_PUBLIC_ORIGIN: 'https://issuer.test',
  AUTH_ACTIVE_PRIVATE_JWK: SECRET,
};

function snapshot(): Snapshot {
  return {
    version: 15,
    guestHistoryMax: 15,
    runnerHistoryMax: null,
    serverVersionNum: '160015',
    tables: [{ name: 'users', columns: ['id'], count: 1, rows: '[{"id":"u1"}]' }],
    runtime: { values, state: { bootstrap_fingerprint: 'f' }, dropped: [] },
  };
}

/** Everything left in `parent`, so a test can show nothing partial stayed behind. */
const leftovers = (parent: string) => readdirSync(parent).sort();

describe('the export directory is written whole or not at all', () => {
  test('a complete export is renamed into place with private modes', async () => {
    const parent = fresh('parent');
    mkdirSync(parent);
    const out = join(parent, 'export');
    const manifest = await writeExport(out, snapshot(), {
      createdAt: '2026-10-12T00:00:00.000Z',
      backup: async (dir) => {
        writeFileSync(join(dir, 'directory.dump'), 'dump', { mode: 0o600 });
        return { file: 'directory.dump', sha256: 'x' };
      },
    });
    expect(manifest.backup?.file).toBe('directory.dump');
    expect(leftovers(parent)).toEqual(['export']);
    expect(statSync(out).mode & 0o777).toBe(0o700);
    expect(leftovers(out)).toEqual([
      'directory.dump',
      'manifest.json',
      'state.json',
      'tables',
      'values.json',
    ]);
    // An existing empty directory is replaced; a non-empty one is refused before anything.
    const empty = join(parent, 'empty');
    mkdirSync(empty);
    await writeExport(empty, snapshot(), { createdAt: 'x' });
    expect(existsSync(join(empty, 'manifest.json'))).toBe(true);
    await expect(writeExport(out, snapshot(), { createdAt: 'x' })).rejects.toThrow(
      'exists and is not an empty directory',
    );
    expect(leftovers(parent)).toEqual(['empty', 'export']);
  });

  test('a failing backup removes everything already written, secrets included', async () => {
    const parent = fresh('failing');
    mkdirSync(parent);
    const out = join(parent, 'export');
    let partial = '';
    const error = await writeExport(out, snapshot(), {
      createdAt: 'x',
      backup: async (dir) => {
        partial = dir;
        expect(readFileSync(join(dir, 'values.json'), 'utf8')).toContain(SECRET);
        throw new Error('pg_dump failed (exit 1): nope');
      },
    }).catch((caught: unknown) => caught as Error);
    expect(String(error)).toContain(
      `pg_dump failed (exit 1): nope; the partial export was removed, ${out} was not written`,
    );
    expect(String(error)).not.toContain(SECRET);
    expect(existsSync(partial)).toBe(false);
    expect(existsSync(out)).toBe(false);
    expect(leftovers(parent)).toEqual([]);
    // A table file that cannot be written fails the same way.
    const bad = snapshot();
    bad.tables.push({ name: 'users', columns: ['id'], count: 1, rows: '[]' });
    await expect(writeExport(out, bad, { createdAt: 'x' })).rejects.toThrow(
      'the partial export was removed',
    );
    expect(leftovers(parent)).toEqual([]);
  });

  test('values that are not a deployable values file are refused before anything is written', async () => {
    const out = fresh('refused');
    const bad = snapshot();
    bad.runtime.values = { ISSUER_URL: 'x' };
    await expect(writeExport(out, bad, { createdAt: 'x' })).rejects.toThrow(
      'missing required names',
    );
    expect(existsSync(out)).toBe(false);
  });
});

describe('exportCommand', () => {
  const inventory = JSON.stringify({
    server: '160015',
    tables: [
      { name: 'identity_runtime_secret', columns: ['name', 'value'] },
      { name: 'identity_schema_migrations', columns: ['version'] },
      { name: 'users', columns: ['id'] },
    ],
  });
  const raw = JSON.stringify({
    guest: Array.from({ length: 15 }, (_, i) => String(i + 1)),
    runner: null,
    runtime: [
      { name: 'ISSUER_URL', value: values.ISSUER_URL },
      { name: 'AUTH_PUBLIC_ORIGIN', value: values.AUTH_PUBLIC_ORIGIN },
      { name: 'AUTH_ACTIVE_PRIVATE_JWK', value: SECRET },
    ],
    tables: { users: { count: 1, rows: '[{"id":"u1"}]' } },
  });
  /** psql, pg_dump and kubectl stand-ins; `overrides` replaces one by its program name. */
  const fake = (overrides: Record<string, Awaited<ReturnType<Run>>> = {}) => {
    const calls: Array<{ argv: string[]; input?: string }> = [];
    const run: Run = async (argv, input) => {
      calls.push({ argv, input });
      const program = argv.find((part) => ['psql', 'pg_dump', 'get'].includes(part)) ?? '';
      const override = overrides[program];
      if (override) return override;
      if (program === 'get') return { code: 0, stdout: Buffer.from('directory-0\n'), stderr: '' };
      if (program === 'pg_dump') return { code: 0, stdout: Uint8Array.from([1, 2, 3]), stderr: '' };
      const body = input?.includes('server_version_num') ? inventory : raw;
      return { code: 0, stdout: Buffer.from(`${body}\n`), stderr: '' };
    };
    return { run, calls };
  };
  const options = (target: ExportTarget, out = fresh('export')) => ({
    out,
    target,
    user: 'app',
    database: 'app',
    backup: true,
    createdAt: 'x',
  });

  test('podman: two read-only psql statements on stdin, then pg_dump; logs no values', async () => {
    const { run, calls } = fake();
    const lines: string[] = [];
    const manifest = await exportCommand(options({ podman: 'source-pg' }), {
      run,
      log: (line) => lines.push(line),
    });
    expect(manifest.source.version).toBe(15);
    expect(manifest.backup).toEqual({
      file: 'directory.dump',
      sha256: createHash('sha256')
        .update(Uint8Array.from([1, 2, 3]))
        .digest('hex'),
    });
    expect(calls.map((call) => call.argv.slice(0, 5))).toEqual([
      ['podman', 'exec', '-i', 'source-pg', 'psql'],
      ['podman', 'exec', '-i', 'source-pg', 'psql'],
      ['podman', 'exec', '-i', 'source-pg', 'pg_dump'],
    ]);
    expect(calls[0]?.input).toStartWith('BEGIN READ ONLY;\n');
    expect(lines.join('\n')).toContain('source schema V15');
    expect(lines.join('\n')).not.toContain(SECRET);
  });

  test('kubectl: finds the one Running pod by service label, or takes --pod and -c', async () => {
    const { run, calls } = fake();
    await exportCommand(
      options({
        kubeconfig: '/kc',
        context: 'ctx',
        namespace: 'di-runtime-identity',
        service: 'directory',
      }),
      { run, log: () => {} },
    );
    expect(calls[0]?.argv).toContain('app=di-bs-directory');
    expect(calls[1]?.argv.slice(0, 10)).toEqual([
      'kubectl',
      '--kubeconfig',
      '/kc',
      '--context',
      'ctx',
      '--namespace',
      'di-runtime-identity',
      'exec',
      '-i',
      'directory-0',
    ]);
    const explicit = fake();
    await exportCommand(
      {
        ...options({ kubeconfig: '/kc', namespace: 'n', pod: 'p', container: 'postgres' }),
        backup: false,
      },
      { run: explicit.run, log: () => {} },
    );
    expect(explicit.calls[0]?.argv).toEqual(
      expect.arrayContaining(['exec', '-i', 'p', '-c', 'postgres', '--']),
    );
    expect(explicit.calls.some((call) => call.argv.includes('pg_dump'))).toBe(false);
    await expect(
      exportCommand(options({ kubeconfig: '/kc', namespace: 'n' }), { run, log: () => {} }),
    ).rejects.toThrow('--pod or --service is required');
    const none = fake({ get: { code: 0, stdout: Buffer.from(''), stderr: '' } });
    await expect(
      exportCommand(options({ kubeconfig: '/kc', namespace: 'n', service: 'directory' }), {
        run: none.run,
        log: () => {},
      }),
    ).rejects.toThrow(
      'expected one Running pod labelled app=di-bs-directory, found 0 (kubectl exit 0)',
    );
  });

  test('psql and pg_dump failures stop the export, stderr cut short, nothing left behind', async () => {
    const long = `ERROR: ${'x'.repeat(1000)}`;
    expect(failure('psql', { code: 3, stderr: long }).message).toHaveLength(
      'psql failed (exit 3): '.length + 400,
    );
    const psql = fake({ psql: { code: 2, stdout: Buffer.from(''), stderr: 'relation missing' } });
    const out = fresh('psql-fails');
    await expect(
      exportCommand(options({ podman: 'p' }, out), { run: psql.run, log: () => {} }),
    ).rejects.toThrow('psql failed (exit 2): relation missing');
    expect(existsSync(out)).toBe(false);
    const parent = fresh('dump-fails');
    mkdirSync(parent);
    const dump = fake({ pg_dump: { code: 1, stdout: new Uint8Array(), stderr: 'no space' } });
    await expect(
      exportCommand(options({ podman: 'p' }, join(parent, 'export')), {
        run: dump.run,
        log: () => {},
      }),
    ).rejects.toThrow('pg_dump failed (exit 1): no space; the partial export was removed');
    expect(leftovers(parent)).toEqual([]);
  });

  test('output psql garbles is reported by size, never echoed', async () => {
    const garbled = fake({
      psql: { code: 0, stdout: Buffer.from(`${SECRET} not json`), stderr: '' },
    });
    const error = await exportCommand(options({ podman: 'p' }), {
      run: garbled.run,
      log: () => {},
    }).catch((caught: unknown) => String(caught));
    expect(error).toContain('the inventory psql returned is not JSON (29 bytes)');
    expect(error).not.toContain('hunter2');
  });
});

describe('the runner under wasmtime', () => {
  const provider = fresh('provider.wasm');
  const guest = fresh('guest.wasm');
  writeFileSync(provider, Buffer.from('\0asm..di-framework:pglite-encfs..provider'));
  writeFileSync(
    guest,
    Buffer.concat([Buffer.from('guest'), readFileSync(provider), Buffer.from('end')]),
  );

  test('the provider must be encrypted and be the one inside the guest', () => {
    expect(() => checkProvider(provider, guest)).not.toThrow();
    const plain = fresh('plain.wasm');
    writeFileSync(plain, 'provider without the section');
    expect(() => checkProvider(plain, guest)).toThrow('it is not encrypted');
    const other = fresh('other.wasm');
    writeFileSync(other, 'di-framework:pglite-encfs but another build');
    expect(() => checkProvider(other, guest)).toThrow('is not the provider inside');
  });

  test('tools, commands and the composition', () => {
    expect(tool('wac', { WAC: '/opt/wac' })).toBe('/opt/wac');
    expect(tool('sh', { PATH: process.env.PATH })).toEndWith('/sh');
    expect(() => tool('no-such-tool-here', { PATH: process.env.PATH })).toThrow(
      'no-such-tool-here not found on PATH',
    );
    expect(runSync(['sh', '-c', 'printf ok'])).toBe('ok');
    expect(() => runSync(['sh', '-c', 'echo bad >&2; exit 4'])).toThrow('sh failed (exit 4): bad');
    expect(wasmtimeArgv('/r.wasm', '/d')).toEqual([
      'wasmtime',
      'run',
      '--dir',
      '/d::/data',
      '--env',
      'DI_PGLITE_KEY',
      '/r.wasm',
    ]);
    expect(DEFAULTS.runner).toEndWith('identity-pglite-runner.wasm');

    const calls: string[][] = [];
    const logs: string[] = [];
    const deps = (wit: string) => ({
      run: (argv: string[]) => {
        calls.push(argv);
        return argv.includes('wit') ? wit : '';
      },
      tool: (name: string) => `/bin/${name}`,
      log: (line: string) => logs.push(line),
    });
    const options = { provider: '/p.wasm', runner: provider, out: '/o.wasm' };
    expect(composeRunner(options, deps('world { export wasi:cli/run; }'))).toBe('/o.wasm');
    expect(calls[0]).toEqual(['/bin/wac', 'plug', '--plug', '/p.wasm', provider, '-o', '/o.wasm']);
    expect(() =>
      composeRunner(options, deps('  import di-framework:pglite/database@0.2.0;')),
    ).toThrow('still imports the database or sockets');
    calls.length = 0;
    composeRunner({ ...options, runner: fresh('missing.wasm') }, deps(''));
    expect(calls[0]?.slice(0, 2)).toEqual(['cargo', 'build']);
    expect(logs).toContain('building the pglite runner (cargo, wasm32-wasip2)...');
  });

  test('the guest adapter runs through the runner process; encfs lines are passed on', async () => {
    const dir = fresh('runner-data');
    const warnings: string[] = [];
    const runner = await startRunner(['bun', fakeRunner, dir], KEY, (line) => warnings.push(line));
    await runner.database.exec('CREATE TABLE t (n int8)');
    await runner.database.run('INSERT INTO t VALUES (?)', [7]);
    expect(await runner.database.first<{ n: unknown }>('SELECT n FROM t')).toEqual({ n: 7 });
    expect(await runner.stop()).toBe(0);
    expect(warnings).toEqual(['pglite-encfs: fake layer ready']);
    expect(readFileSync(join(dir, '.di-encfs')).subarray(8, 24).toString('hex')).toBe(
      pgliteKeyCheckValue(KEY),
    );
    expect(DATABASE_ROOT).toBe('/data/pglite');
  });

  test('a runner that exits at once fails the open and is reaped', async () => {
    await expect(
      startRunner(['bun', fakeRunner, fresh('x'), 'exit'], KEY, () => {}),
    ).rejects.toThrow('connection-lost');
  });

  test('errors are described without PostgreSQL messages, and replies that are not JSON are not echoed', async () => {
    const pgError = Object.assign(new Error(`PostgreSQL 23505: Key (email)=(${SECRET})`), {
      tag: 'execution-failed',
      code: '23505',
    });
    expect(describeError(pgError)).toBe('pglite execution-failed (SQLSTATE 23505)');
    expect(describeError(Object.assign(new Error('x'), { tag: 'closed' }))).toBe('pglite closed');
    expect(describeError(new Error('plain'))).toBe('plain');
    expect(describeError('text')).toBe('text');
    const module = bridgeModule({ send() {}, receive: async () => `${SECRET} garbage` });
    const error = await Promise.resolve(module.open('/x')).catch((caught: unknown) =>
      String(caught),
    );
    expect(error).toContain('a runner reply is not JSON');
    expect(error).not.toContain('hunter2');
    expect(() => needlesOf(new Map([['users', `[${SECRET}`]]))).toThrow(
      'the exported users is not JSON',
    );
    expect(needlesOf(new Map())).toEqual(['PostgreSQL', 'pg_catalog', 'template1']);
    expect(
      needlesOf(
        new Map([
          ['users', '[{"login":"legacy-user","email":"a@b.c","password_hash":"x"},{"login":null}]'],
        ]),
      ),
    ).toEqual(['PostgreSQL', 'pg_catalog', 'template1', 'legacy-user']);
  });
});

describe('importCommand', () => {
  /** An export with no tables beyond the manifest's one empty `users`, at V15. */
  function exportDir(): { dir: string; valuesPath: string } {
    const dir = fresh('export');
    mkdirSync(join(dir, 'tables'), { recursive: true, mode: 0o700 });
    const columns = [
      'id',
      'login',
      'normalized_login',
      'email',
      'normalized_email',
      'password_hash',
      'display_name',
      'avatar_url',
      'email_verified',
      'status',
      'created_at',
      'updated_at',
      'system_role',
    ];
    const rows = '[]';
    writeFileSync(join(dir, 'tables', 'users.json'), rows, { mode: 0o600 });
    writeFileSync(
      join(dir, 'manifest.json'),
      JSON.stringify({
        format: 1,
        source: { version: 15 },
        tables: [
          {
            name: 'users',
            columns,
            count: 0,
            sha256: createHash('sha256').update(rows).digest('hex'),
          },
        ],
      }),
      { mode: 0o600 },
    );
    writeFileSync(join(dir, 'state.json'), '{}', { mode: 0o600 });
    const valuesPath = join(dir, 'values.json');
    writeFileSync(valuesPath, JSON.stringify({ ...values, DI_PGLITE_KEY: KEY }), { mode: 0o600 });
    return { dir, valuesPath };
  }
  const provider = fresh('provider.wasm');
  const guest = fresh('guest.wasm');
  writeFileSync(provider, 'di-framework:pglite-encfs provider');
  writeFileSync(guest, 'guest di-framework:pglite-encfs provider guest');
  const deps = (mode: string, logs: string[] = []) => ({
    compose: (out: string) => out,
    start: (_composed: string, dataDir: string, key: string) =>
      startRunner(['bun', fakeRunner, dataDir, mode], key, () => {}),
    log: (line: string) => logs.push(line),
    warn: (line: string) => logs.push(line),
  });
  const run = (
    exported: ReturnType<typeof exportDir>,
    out: string,
    mode: string,
    logs?: string[],
  ) =>
    importCommand(
      {
        exportDir: exported.dir,
        valuesPath: exported.valuesPath,
        out,
        provider,
        guest,
        migrations: embeddedMigrations,
      },
      deps(mode, logs),
    );

  test('the import table schema mismatch refuses and removes the partly written directory', async () => {
    const exported = exportDir();
    const out = fresh('data');
    // The manifest lists only `users`, so the V15 schema has tables the export lacks.
    const error = await run(exported, out, 'marker').catch((caught: unknown) => String(caught));
    expect(error).toContain("the export's tables differ from V15's");
    expect(error).toContain(`removed the partly written ${out}`);
    expect(existsSync(out)).toBe(false);
  });

  test('the data directory is checked on disk after the import', async () => {
    const exported = exportDir();
    const manifest = JSON.parse(readFileSync(join(exported.dir, 'manifest.json'), 'utf8'));
    // Every V15 table, empty: a complete export of an empty database.
    const tables = await (async () => {
      const dir = fresh('schema');
      const runner = await startRunner(['bun', fakeRunner, dir], KEY, () => {});
      const { applySchema } = await import('../../apps/guest/src/migrations.ts');
      await applySchema(
        runner.database,
        embeddedMigrations.filter((m) => Number(m.version) <= 15),
      );
      const rows = await runner.database.query<{ name: string; columns: unknown }>(
        `SELECT c.relname AS name, (SELECT json_agg(a.attname::text ORDER BY a.attnum) FROM pg_attribute a
           WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped) AS columns
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'r'
           AND c.relname NOT IN ('identity_schema_migrations', 'identity_runtime_secret')`,
      );
      await runner.stop();
      return rows.map((row) => ({
        name: row.name,
        columns: typeof row.columns === 'string' ? JSON.parse(row.columns) : row.columns,
      }));
    })();
    const empty = createHash('sha256').update('[]').digest('hex');
    manifest.tables = tables.map((table) => ({ ...table, count: 0, sha256: empty }));
    for (const table of tables) {
      writeFileSync(join(exported.dir, 'tables', `${table.name}.json`), '[]', { mode: 0o600 });
    }
    writeFileSync(join(exported.dir, 'manifest.json'), JSON.stringify(manifest), { mode: 0o600 });

    const logs: string[] = [];
    const out = fresh('data');
    await run(exported, out, 'marker', logs);
    expect(logs).toContain(`DI_PGLITE_KEY KCV ${pgliteKeyCheckValue(KEY)}`);
    expect(logs.join('\n')).toContain('identity_runtime_secret rows V16 would delete: 0');
    expect(logs.join('\n')).toContain('0 without a header; .di-encfs KCV matches: true');
    expect(logs.join('\n')).not.toContain(SECRET);
    expect(statSync(out).mode & 0o777).toBe(0o700);

    // A plaintext file on disk fails the check, and the directory is removed.
    const plainOut = fresh('plain');
    await expect(run(exported, plainOut, 'plain')).rejects.toThrow(
      `the data directory is not fully encrypted under this key; removed the partly written ${plainOut}`,
    );
    expect(existsSync(plainOut)).toBe(false);
  }, 120_000);

  test('nothing is created when the values, the provider or the output are wrong', async () => {
    const exported = exportDir();
    const noKey = join(exported.dir, 'no-key.json');
    writeFileSync(noKey, JSON.stringify(values), { mode: 0o600 });
    const out = fresh('never');
    await expect(
      importCommand(
        { exportDir: exported.dir, valuesPath: noKey, out, provider, guest, migrations: [] },
        deps('marker'),
      ),
    ).rejects.toThrow('has no DI_PGLITE_KEY; run `bun deploy/guest/runtime-secrets.ts pglite-key');
    await expect(
      importCommand(
        {
          exportDir: exported.dir,
          valuesPath: exported.valuesPath,
          out,
          provider: guest,
          guest: provider,
          migrations: [],
        },
        deps('marker'),
      ),
    ).rejects.toThrow('is not the provider inside');
    const busy = fresh('busy');
    mkdirSync(busy);
    writeFileSync(join(busy, 'keep'), 'operator data');
    await expect(run(exported, busy, 'marker')).rejects.toThrow(
      'exists and is not an empty directory',
    );
    expect(readFileSync(join(busy, 'keep'), 'utf8')).toBe('operator data');
    expect(existsSync(out)).toBe(false);
  });
});

describe('installCommand', () => {
  const uid = '0b5c3a7e-1d2f-4a6b-8c9d-0e1f2a3b4c5d';
  const kcv = '22'.repeat(16);
  const data = fresh('install-data');
  mkdirSync(join(data, 'pglite'), { recursive: true });
  writeFileSync(join(data, '.di-encfs'), Buffer.concat([Buffer.alloc(8), Buffer.from(kcv, 'hex')]));
  writeFileSync(join(data, 'pglite', 'f'), 'ciphertext');
  const tree = localTree(data);
  const digests = tree.files.map((file) => `${file.sha256}  ./${file.path}`).join('\n');

  /** A cluster stand-in; `answers` overrides a step by a substring of its arguments. */
  const cluster = (
    answers: Record<string, { code?: number; stdout?: string; stderr?: string }> = {},
  ) => {
    const calls: Array<{ args: string; input?: string | Uint8Array }> = [];
    const kubectl: InstallKubectl = async (args, input) => {
      const line = args.join(' ');
      calls.push({ args: line, input });
      const key = Object.keys(answers).find((part) => line.includes(part));
      const defaults: Record<string, string> = {
        'get tenants.platform.di-framework.dev': uid,
        'get deployments --all-namespaces': `/var/lib/kubesolo/di-tenants/${uid}/workloads/other\n`,
        'get nodes': 'node-1',
        sha256sum: digests,
      };
      const fallback = Object.keys(defaults).find((part) => line.includes(part));
      return {
        code: 0,
        stdout: fallback ? (defaults[fallback] as string) : '',
        stderr: '',
        ...(key ? answers[key] : {}),
      };
    };
    return { kubectl, calls };
  };
  const options = (overrides: Partial<InstallOptions> = {}): InstallOptions => ({
    data,
    kcv,
    tenant: 'identity-pg',
    workload: 'identity',
    image: 'busybox:1.37.0',
    namespace: 'kube-system',
    allowExistingWorkload: false,
    yes: true,
    podName: 'helper',
    ...overrides,
  });
  const run = (
    stand: ReturnType<typeof cluster>,
    overrides: Partial<InstallOptions> = {},
    sink: { logs: string[]; warnings: string[] } = { logs: [], warnings: [] },
    legacy: string[] = [],
  ) =>
    installCommand(options(overrides), {
      kubectl: stand.kubectl,
      refuseLegacyTenant: async (namespace) => {
        legacy.push(namespace);
      },
      log: (line) => sink.logs.push(line),
      warn: (line) => sink.warnings.push(line),
    });
  const target = `/var/lib/kubesolo/di-tenants/${uid}/workloads/identity`;
  const deleted = (stand: ReturnType<typeof cluster>) =>
    stand.calls.some(
      (call) => call.args === '--namespace kube-system delete pod helper --wait=false',
    );

  test('a dry run reads the cluster and changes nothing', async () => {
    const stand = cluster();
    const sink = { logs: [] as string[], warnings: [] as string[] };
    const legacy: string[] = [];
    expect(await run(stand, { yes: false }, sink, legacy)).toBe('dry-run');
    expect(legacy).toEqual(['di-tenant-identity-pg']);
    expect(sink.logs).toContain(`target ${target} (the guest's /data)`);
    expect(stand.calls.some((call) => /create|exec|delete/.test(call.args))).toBe(false);
  });

  test('installs: empty check, archive, modes before owner, digests, and the pod is deleted', async () => {
    const stand = cluster();
    const sink = { logs: [] as string[], warnings: [] as string[] };
    expect(await run(stand, { storageRoot: '/var/lib/kubesolo', node: 'n' }, sink)).toBe(
      'installed',
    );
    const steps = stand.calls.map((call) => call.args);
    const created = stand.calls.find((call) => call.args === 'create -f -');
    const pod = JSON.parse(String(created?.input));
    expect(pod.spec.volumes[0].hostPath).toEqual({ path: target, type: 'DirectoryOrCreate' });
    expect(pod.spec.nodeName).toBe('n');
    const exec = steps.filter((line) => line.includes(' exec '));
    expect(exec.map((line) => line.split(' -- sh -c ')[1])).toEqual([
      'ls -A /target',
      'tar -x -o -f - -C /target',
      'cd /target && find . -type d -exec chmod 700 {} + && find . -type f -exec chmod 600 {} + && chown -R 65532:65532 .',
      'cd /target && find . -type f -exec sha256sum {} +',
      'cd /target && find . ! -user 65532',
    ]);
    expect(stand.calls.find((call) => call.args.includes('tar -x'))?.input).toBeInstanceOf(
      Uint8Array,
    );
    expect(sink.logs).toContain(
      'installed: 2/2 files match, 0 missing, 0 changed, 0 extra; 0 not owned by 65532',
    );
    expect(deleted(stand)).toBe(true);
  });

  test('a non-empty target is refused before any archive is sent, and the pod is deleted', async () => {
    const stand = cluster({ 'ls -A /target': { stdout: 'PG_VERSION\n' } });
    await expect(run(stand)).rejects.toThrow(
      `${target} is not empty (1 entries); refusing to install`,
    );
    expect(stand.calls.some((call) => call.args.includes('tar -x'))).toBe(false);
    expect(deleted(stand)).toBe(true);
  });

  test('digest or owner mismatches fail, and the pod is still deleted', async () => {
    const mismatches: Array<Record<string, { stdout: string }>> = [
      { sha256sum: { stdout: `${'0'.repeat(64)}  ./.di-encfs` } },
      { '! -user': { stdout: './pglite/f\n' } },
    ];
    for (const answers of mismatches) {
      const stand = cluster(answers);
      await expect(run(stand)).rejects.toThrow('the installed directory does not match');
      expect(deleted(stand)).toBe(true);
    }
  });

  test('pod steps that fail are reported, and a pod that cannot be deleted is named', async () => {
    const created = cluster({ 'create -f -': { code: 1, stderr: 'forbidden' } });
    await expect(run(created)).rejects.toThrow('cannot create the helper pod: forbidden');
    expect(deleted(created)).toBe(false);
    const waiting = cluster({ 'wait --for=condition=Ready': { code: 1, stderr: 'timed out' } });
    await expect(run(waiting)).rejects.toThrow('the helper pod did not start: timed out');
    expect(deleted(waiting)).toBe(true);
    const step = cluster({ 'tar -x': { code: 2, stderr: 'disk full' } });
    await expect(run(step)).rejects.toThrow('helper step failed (exit 2): disk full');

    const stuck = cluster({ 'delete pod helper': { code: 1 } });
    await expect(run(stuck)).rejects.toThrow(
      'could not delete the helper pod kube-system/helper (kubectl exit 1); it mounts',
    );
    const both = cluster({ 'delete pod helper': { code: 1 }, 'ls -A /target': { stdout: 'x' } });
    const sink = { logs: [] as string[], warnings: [] as string[] };
    await expect(run(both, {}, sink)).rejects.toThrow('is not empty');
    expect(sink.warnings[0]).toContain('kubectl --namespace kube-system delete pod helper');
  });

  test('refuses a KCV mismatch, an existing workload and a failed check before any pod', async () => {
    const stand = cluster();
    await expect(run(stand, { kcv: '33'.repeat(16) })).rejects.toThrow(
      `is encrypted under KCV ${kcv}, the values file's key has KCV ${'33'.repeat(16)}; refusing`,
    );
    expect(stand.calls).toEqual([]);
    const existing = cluster({
      'get workloaddeployment identity': { stdout: 'workloaddeployment/identity' },
    });
    await expect(run(existing)).rejects.toThrow(
      'WorkloadDeployment identity already exists in di-tenant-identity-pg',
    );
    expect(existing.calls.some((call) => call.args.includes('create'))).toBe(false);
    const allowed = cluster({
      'get workloaddeployment identity': { stdout: 'workloaddeployment/identity' },
    });
    expect(await run(allowed, { allowExistingWorkload: true })).toBe('installed');
    const unreadable = cluster({ 'get workloaddeployment identity': { code: 1 } });
    await expect(run(unreadable)).rejects.toThrow(
      'cannot check for WorkloadDeployment identity (kubectl exit 1)',
    );
  });
});
