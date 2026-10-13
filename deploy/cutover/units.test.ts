import { afterAll, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WasmPgValue } from '../../apps/guest/src/database.ts';
import { pgliteFixture } from '../../apps/guest/tests/support/pglite.ts';
import {
  BOOTSTRAP_IDENTITY_NAMES,
  type KubectlResult,
  parseRuntimeValues,
} from '../platform/components/control-secret.ts';
import { bridgeModule, type Channel, fromWire, replyLine, toWire } from './bridge.ts';
import {
  type Inventory,
  privateDirectory,
  privateFile,
  readSource,
  snapshotSql,
} from './export-core.ts';
import { loadOrder, verifyCiphertext } from './import-core.ts';
import {
  compareDigests,
  discoverStorageRoot,
  entries,
  HOST_UID,
  helperPod,
  localTree,
  singleNode,
  tarball,
  tenantUid,
  workloadStoragePath,
} from './install-core.ts';
import {
  bootstrapSetting,
  classifyHashFormat,
  classifySignIn,
  compareHashes,
  exportedPasswordHashDigest,
  formatResult,
  hashFormat,
  passwordHashDigest,
} from './rehearse-core.ts';
import {
  identifier,
  parseManifest,
  SUPPORTED_SOURCE_VERSIONS,
  sourceVersion,
  splitRuntimeRows,
  versionNumber,
} from './source.ts';
import { serveLine } from './tests/support/fake-runner.ts';

const work = mkdtempSync(join(tmpdir(), 'identity-cutover-units-'));
afterAll(() => rmSync(work, { recursive: true, force: true }));
let dirs = 0;
const fresh = (name: string) => join(work, `${dirs++}-${name}`);

describe('runtime secret rows', () => {
  test('setting rows map to the values file under their own names, state rows are carried', () => {
    const split = splitRuntimeRows([
      { name: 'ISSUER_URL', value: 'https://issuer.test' },
      { name: 'AUTH_ACTIVE_PRIVATE_JWK', value: '{}' },
      { name: 'SMTP_USERNAME', value: 'mailer' },
      { name: 'bootstrap_fingerprint', value: 'f' },
      { name: 'bootstrap_client_fingerprints', value: '{}' },
      { name: 'bootstrap_lease', value: '2026-01-01T00:00:00.000Z' },
    ]);
    expect(split).toEqual({
      values: {
        ISSUER_URL: 'https://issuer.test',
        AUTH_ACTIVE_PRIVATE_JWK: '{}',
        SMTP_USERNAME: 'mailer',
      },
      state: { bootstrap_fingerprint: 'f', bootstrap_client_fingerprints: '{}' },
      dropped: ['bootstrap_lease'],
    });
  });

  test('the bootstrap identity rows authproto holds are carried name for name', () => {
    // authproto's identity_runtime_secret overrides all eight compiled-in bootstrap defaults.
    const identity = {
      AUTH_BOOTSTRAP_ORGANIZATION_NAME: 'Org',
      AUTH_BOOTSTRAP_ORGANIZATION_SLUG: 'org',
      AUTH_BOOTSTRAP_OWNER_DISPLAY_NAME: 'Owner Person',
      AUTH_BOOTSTRAP_OWNER_EMAIL: 'owner@org.test',
      AUTH_BOOTSTRAP_OWNER_LOGIN: 'owner-person',
      AUTH_BOOTSTRAP_VIEWER_DISPLAY_NAME: 'Viewer Person',
      AUTH_BOOTSTRAP_VIEWER_EMAIL: 'viewer@org.test',
      AUTH_BOOTSTRAP_VIEWER_LOGIN: 'viewer-person',
    };
    const split = splitRuntimeRows([
      { name: 'ISSUER_URL', value: 'https://issuer.test' },
      ...Object.entries(identity).map(([name, value]) => ({ name, value })),
      { name: 'bootstrap_fingerprint', value: 'f' },
    ]);
    expect(split.values).toEqual({ ISSUER_URL: 'https://issuer.test', ...identity });
    expect(split.state).toEqual({ bootstrap_fingerprint: 'f' });
    expect(Object.keys(identity).sort()).toEqual([...BOOTSTRAP_IDENTITY_NAMES].sort());
    // And the values file the export writes takes them.
    expect(() =>
      parseRuntimeValues(
        JSON.stringify({ ...split.values, AUTH_PUBLIC_ORIGIN: 'x', AUTH_ACTIVE_PRIVATE_JWK: '{}' }),
        'values.json',
      ),
    ).not.toThrow();
  });

  test('unknown names are refused, named but never with their values', () => {
    const run = () =>
      splitRuntimeRows([
        { name: 'SMTP_PORT', value: 'secret-ish-1' },
        { name: 'DI_PGLITE_KEY', value: 'secret-ish-2' },
        { name: 'ISSUER_URL', value: 'x' },
      ]);
    expect(run).toThrow('rows the new guest has no setting for: DI_PGLITE_KEY, SMTP_PORT');
    try {
      run();
    } catch (error) {
      expect(String(error)).not.toContain('secret-ish');
    }
    expect(() =>
      splitRuntimeRows([
        { name: 'ISSUER_URL', value: 'a' },
        { name: 'ISSUER_URL', value: 'b' },
      ]),
    ).toThrow('has the row ISSUER_URL twice');
  });
});

describe('source schema version', () => {
  const guest = (n: number) => Array.from({ length: n }, (_, i) => String(i + 1));

  test('versions as either history spells them', () => {
    expect(versionNumber('15')).toBe(15);
    expect(versionNumber('V7')).toBe(7);
    expect(versionNumber(' 3.0 ')).toBe(3);
    expect(() => versionNumber('15a')).toThrow('unexpected migration version');
  });

  test('accepts V13..V15 and refuses everything else', () => {
    expect(SUPPORTED_SOURCE_VERSIONS).toEqual({ min: 13, max: 15 });
    expect(sourceVersion({ guest: guest(15), runner: null })).toBe(15);
    expect(sourceVersion({ guest: guest(13), runner: ['1', '13'] })).toBe(13);
    expect(() => sourceVersion({ guest: guest(16), runner: null })).toThrow(
      'the source schema is at V16; the cutover supports V13..V15 (V16 and later have already deleted the runtime secret rows)',
    );
    expect(() => sourceVersion({ guest: guest(12), runner: null })).toThrow(
      'the source schema is at V12; the cutover supports V13..V15',
    );
    expect(() => sourceVersion({ guest: null, runner: guest(15) })).toThrow(
      'the source has no identity_schema_migrations',
    );
    expect(() => sourceVersion({ guest: [], runner: null })).toThrow(
      'no identity_schema_migrations',
    );
    expect(() => sourceVersion({ guest: ['1', '2', '4'], runner: null })).toThrow(
      'is not 1..4 without gaps',
    );
    expect(() => sourceVersion({ guest: guest(15), runner: ['16'] })).toThrow(
      '_migrations is at V16, ahead of identity_schema_migrations (V15)',
    );
  });

  test('identifiers and manifests are checked before anything is interpolated', () => {
    expect(identifier('users')).toBe('"users"');
    expect(() => identifier('users; drop')).toThrow('unexpected identifier');
    const manifest = (overrides: Record<string, unknown>) =>
      JSON.stringify({
        format: 1,
        source: { version: 15 },
        tables: [{ name: 'users', columns: ['id'], count: 0, sha256: '' }],
        ...overrides,
      });
    expect(parseManifest(manifest({}), 'm').tables).toHaveLength(1);
    expect(() => parseManifest(manifest({ format: 2 }), 'm')).toThrow('not a cutover export');
    expect(() => parseManifest(manifest({ source: { version: 16 } }), 'm')).toThrow(
      'unsupported source version',
    );
    expect(() => parseManifest(manifest({ tables: [] }), 'm')).toThrow('lists no tables');
    expect(() =>
      parseManifest(
        manifest({ tables: [{ name: 'identity_runtime_secret', columns: ['name'] }] }),
        'm',
      ),
    ).toThrow('carries identity_runtime_secret');
    expect(() =>
      parseManifest(manifest({ tables: [{ name: 'users', columns: ['bad col'] }] }), 'm'),
    ).toThrow('unexpected identifier');
  });
});

describe('the source snapshot', () => {
  const inventory = (names: string[]): Inventory => ({
    server: '160015',
    tables: names.map((name) => ({ name, columns: ['id'] })),
  });

  test('one statement reads every data table, both histories when present, and the secret rows', () => {
    const sql = snapshotSql(
      inventory(['identity_runtime_secret', 'identity_schema_migrations', 'users', '_migrations']),
    );
    expect(sql).toContain(
      `(SELECT coalesce(json_agg(version::text), '[]'::json) FROM "_migrations")`,
    );
    expect(sql).toContain(`'users', json_build_object('count', (SELECT count(*) FROM "users")`);
    expect(sql).not.toContain(`'identity_runtime_secret', json_build_object`);
    expect(snapshotSql(inventory(['identity_runtime_secret']))).toContain(`'runner', NULL::json`);
    expect(() => snapshotSql(inventory(['users']))).toThrow('older than V13');
    const many = Array.from({ length: 41 }, (_, i) => `t${i}`);
    expect(() => snapshotSql(inventory(['identity_runtime_secret', ...many]))).toThrow(
      'the source has 41 tables; too many',
    );
  });

  test('refuses before writing anything: bad names, versions, unknown rows', async () => {
    const session = (tables: Inventory['tables'], snapshot: unknown) => {
      let call = 0;
      return async () => JSON.stringify(call++ === 0 ? { server: '160015', tables } : snapshot);
    };
    const tables = [
      { name: 'identity_runtime_secret', columns: ['name', 'value'] },
      { name: 'identity_schema_migrations', columns: ['version'] },
      { name: '_migrations', columns: ['version'] },
      { name: 'users', columns: ['id'] },
    ];
    const history = Array.from({ length: 15 }, (_, i) => String(i + 1));
    const snapshot = await readSource(
      session(tables, {
        guest: history,
        runner: ['V1', 'V15'],
        runtime: [{ name: 'ISSUER_URL', value: 'x' }],
        tables: { users: { count: '2', rows: '[{"id":1},{"id":2}]' } },
      }),
    );
    expect(snapshot).toMatchObject({
      version: 15,
      guestHistoryMax: 15,
      runnerHistoryMax: 15,
      serverVersionNum: '160015',
      tables: [{ name: 'users', columns: ['id'], count: 2 }],
    });
    await expect(readSource(session([{ name: 'bad name', columns: [] }], {}))).rejects.toThrow(
      'unexpected identifier',
    );
    await expect(
      readSource(
        session(tables, {
          guest: history,
          runner: null,
          runtime: [{ name: 'SMTP_PORT', value: '25' }],
          tables: { users: { count: 0, rows: '[]' } },
        }),
      ),
    ).rejects.toThrow('no setting for: SMTP_PORT');
    const noRunner = await readSource(
      session(tables.slice(0, 2).concat(tables[3] as Inventory['tables'][number]), {
        guest: history.slice(0, 13),
        runner: [],
        runtime: [],
        tables: { users: { count: 0, rows: '[]' } },
      }),
    );
    expect(noRunner.runnerHistoryMax).toBeNull();
  });

  test('the export directory is private and never overwritten', () => {
    const dir = fresh('private');
    privateDirectory(dir);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    privateFile(join(dir, 'a'), 'x');
    expect(statSync(join(dir, 'a')).mode & 0o777).toBe(0o600);
    expect(() => privateFile(join(dir, 'a'), 'y')).toThrow();
    expect(() => privateDirectory(dir)).toThrow('exists and is not an empty directory');
    expect(() => privateDirectory(join(dir, 'a'))).toThrow('exists and is not an empty directory');
    const empty = fresh('empty');
    mkdirSync(empty, { mode: 0o755 });
    privateDirectory(empty);
    expect(statSync(empty).mode & 0o777).toBe(0o700);
  });
});

describe('the import order and the encrypted directory check', () => {
  test('referenced tables load first; a cycle is refused', () => {
    expect(
      loadOrder(
        ['organization_memberships', 'users', 'organizations', 'browser_sessions'],
        [
          { child: 'organization_memberships', parent: 'users' },
          { child: 'organization_memberships', parent: 'organizations' },
          { child: 'browser_sessions', parent: 'users' },
          { child: 'users', parent: 'users' },
          { child: 'users', parent: 'not_loaded' },
        ],
      ),
    ).toEqual(['organizations', 'users', 'browser_sessions', 'organization_memberships']);
    expect(() =>
      loadOrder(
        ['a', 'b'],
        [
          { child: 'a', parent: 'b' },
          { child: 'b', parent: 'a' },
        ],
      ),
    ).toThrow('foreign keys form a cycle among a, b');
  });

  test('every non-empty file must carry the encfs header under the key, and no needle', () => {
    const kcv = 'ab'.repeat(16);
    const other = 'cd'.repeat(16);
    const header = (check: string, body = 'ciphertext') =>
      Buffer.concat([
        Buffer.from('DIPGENC1'),
        Buffer.alloc(24),
        Buffer.from(check, 'hex'),
        Buffer.from(body),
      ]);
    const dir = fresh('encfs');
    mkdirSync(join(dir, 'pglite', 'data'), { recursive: true });
    writeFileSync(
      join(dir, '.di-encfs'),
      Buffer.concat([Buffer.alloc(8), Buffer.from(kcv, 'hex')]),
    );
    writeFileSync(join(dir, 'pglite', 'data', 'one'), header(kcv));
    writeFileSync(join(dir, 'pglite', 'data', 'empty'), '');
    symlinkSync('one', join(dir, 'pglite', 'data', 'link'));
    expect(verifyCiphertext(dir, kcv, ['PostgreSQL'])).toEqual({
      files: 2,
      encrypted: 1,
      empty: 1,
      plaintext: [],
      markerKcvMatches: true,
      needlesFound: 0,
    });
    writeFileSync(join(dir, 'pglite', 'plain'), 'PostgreSQL 17.5');
    writeFileSync(join(dir, 'pglite', 'foreign'), header(other, 'owner@example.test'));
    const report = verifyCiphertext(dir, kcv, ['PostgreSQL', 'owner@example.test', '']);
    expect(report).toMatchObject({ encrypted: 1, needlesFound: 2 });
    expect(report.plaintext.sort()).toEqual(['pglite/foreign', 'pglite/plain']);
    expect(verifyCiphertext(dir, other).markerKcvMatches).toBe(false);
  });
});

describe('the runner bridge', () => {
  test('values survive the wire in both directions', () => {
    const values: WasmPgValue[] = [
      { tag: 'null' },
      { tag: 'integer', val: 9007199254740993n },
      { tag: 'real', val: 1.5 },
      { tag: 'text', val: 'x' },
      { tag: 'blob', val: Uint8Array.from([0, 255]) },
      { tag: 'boolean', val: true },
      { tag: 'json', val: '{}' },
      { tag: 'timestamp', val: '2026-10-12T00:00:00Z' },
    ];
    const wire = values.map(toWire);
    expect(wire[1]).toEqual({ tag: 'integer', val: '9007199254740993' });
    expect(wire[4]).toEqual({ tag: 'blob', val: '00ff' });
    expect(JSON.parse(JSON.stringify(wire)).map(fromWire)).toEqual(values);
    expect(replyLine('@pglite {"ok":null}')).toBe('{"ok":null}');
    // Non-finite reals travel as JavaScript spells them, which the runner's f64 parser reads.
    for (const val of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(fromWire(JSON.parse(JSON.stringify(toWire({ tag: 'real', val }))))).toEqual({
        tag: 'real',
        val,
      });
    }
    expect(toWire({ tag: 'real', val: Number.NaN })).toEqual({ tag: 'real', val: 'NaN' });
    expect(Number.isNaN(fromWire({ tag: 'real', val: 'NaN' }).val)).toBe(true);
    expect(replyLine('engine noise')).toBeUndefined();
  });

  test('the guest adapter runs over the protocol the runner speaks', async () => {
    // The runner's side of the protocol, served by the in-process engine.
    const fixture = pgliteFixture();
    const state = {};
    const pending: string[] = [];
    const serve = (line: string) => serveLine(fixture, state, line);
    const channel: Channel = {
      send(line) {
        pending.push(line);
      },
      async receive() {
        return serve(pending.shift() as string);
      },
    };
    try {
      const module = bridgeModule(channel);
      const opened = (await module.open('/data/bridge')) as {
        tag: string;
        val: Record<string, (...args: unknown[]) => Promise<{ tag: string; val: unknown }>>;
      };
      expect(opened.tag).toBe('ok');
      const db = opened.val;
      expect((await db.exec?.('CREATE TABLE t (id int8, b bytea, j jsonb)'))?.tag).toBe('ok');
      expect(
        (
          await db.run?.('INSERT INTO t VALUES ($1, $2, $3)', [
            { tag: 'integer', val: 1n },
            { tag: 'blob', val: [1, 2] },
            { tag: 'json', val: '{"a":1}' },
          ])
        )?.val,
      ).toBe(1n);
      const rows = (await db.query?.('SELECT id, b, j FROM t', []))?.val as unknown[][];
      expect(rows[0]).toEqual([
        ['id', { tag: 'integer', val: 1n }],
        ['b', { tag: 'blob', val: Uint8Array.from([1, 2]) }],
        ['j', { tag: 'json', val: '{"a": 1}' }],
      ]);
      expect((await db.first?.('SELECT id FROM t WHERE id = 2', []))?.val).toBeUndefined();
      expect((await db.first?.('SELECT id FROM t', []))?.tag).toBe('ok');
      for (const op of ['begin', 'commit']) expect((await db[op]?.())?.tag).toBe('ok');
      await db.begin?.();
      for (const op of ['savepoint', 'rollbackToSavepoint', 'releaseSavepoint']) {
        expect((await db[op]?.('sp'))?.tag).toBe('ok');
      }
      expect((await db.rollback?.())?.tag).toBe('ok');
      const failed = await db.exec?.('SELEC nonsense');
      expect(failed?.tag).toBe('err');
      expect((await db.close?.())?.tag).toBe('ok');
      // A second open of the same root is the provider's own refusal, passed through.
      expect(((await module.open('/data/bridge')) as { tag: string }).tag).toBe('ok');
      expect(
        (
          (await bridgeModule({
            send() {},
            receive: async () => '{"err":{"tag":"other","val":"x"}}',
          }).open('/x')) as { tag: string }
        ).tag,
      ).toBe('err');
    } finally {
      await fixture.shutdown();
    }
  });
});

describe('the install plan', () => {
  const kubectl = (result: Partial<KubectlResult>, calls: string[][] = []) => {
    return async (args: string[]) => {
      calls.push(args);
      return { code: 0, stdout: '', stderr: '', ...result };
    };
  };
  const uid = '0b5c3a7e-1d2f-4a6b-8c9d-0e1f2a3b4c5d';

  test('lists the directory with digests and the marker KCV, and tars it for the host uid', () => {
    const dir = fresh('tree');
    const kcv = '11'.repeat(16);
    const deep = join(dir, 'pglite', 'd'.repeat(60), 'e'.repeat(60));
    mkdirSync(deep, { recursive: true });
    writeFileSync(
      join(dir, '.di-encfs'),
      Buffer.concat([Buffer.alloc(8), Buffer.from(kcv, 'hex')]),
    );
    writeFileSync(join(deep, 'f'.repeat(20)), 'x'.repeat(700));
    writeFileSync(join(dir, 'pglite', 'empty'), '');
    const tree = localTree(dir);
    expect(tree.markerKcv).toBe(kcv);
    expect(tree.files.map((file) => file.path)).toEqual([
      '.di-encfs',
      `pglite/${'d'.repeat(60)}/${'e'.repeat(60)}/${'f'.repeat(20)}`,
      'pglite/empty',
    ]);
    expect(tree.bytes).toBe(724);
    const out = fresh('untar');
    mkdirSync(out);
    writeFileSync(join(work, 'tree.tar'), tarball(dir, tree));
    const untar = Bun.spawnSync(['tar', '-xf', join(work, 'tree.tar'), '-C', out]);
    expect(untar.exitCode).toBe(0);
    const remote = tree.files
      .map((file) => {
        const digest = createHash('sha256')
          .update(readFileSync(join(out, file.path)))
          .digest('hex');
        return `${digest}  ./${file.path}`;
      })
      .join('\n');
    expect(compareDigests(tree, remote)).toEqual({
      matched: 3,
      missing: [],
      changed: [],
      extra: [],
    });
    expect(
      compareDigests(tree, `${'0'.repeat(64)}  ./.di-encfs\n${'1'.repeat(64)}  ./stray\n`),
    ).toMatchObject({ matched: 0, changed: ['.di-encfs'], extra: ['stray'] });
    const listing = Bun.spawnSync(['tar', '-tvf', join(work, 'tree.tar')]).stdout.toString();
    expect(listing).toContain(String(HOST_UID));

    writeFileSync(join(dir, 'pglite', 'g'.repeat(101)), 'x');
    expect(() => tarball(dir, localTree(dir))).toThrow('is too long for a tar header');
    rmSync(join(dir, 'pglite', 'g'.repeat(101)));
    const stale = localTree(dir);
    writeFileSync(join(dir, 'pglite', 'empty'), 'grew');
    expect(() => tarball(dir, stale)).toThrow('pglite/empty changed while installing');
    symlinkSync('empty', join(dir, 'pglite', 'link'));
    expect(() => localTree(dir)).toThrow('pglite/link is neither a file nor a directory');
    const short = fresh('short');
    mkdirSync(short);
    writeFileSync(join(short, '.di-encfs'), 'short');
    expect(() => localTree(short)).toThrow('is not an encfs marker');
  });

  test('tenant uid, storage root, node and target path come from the cluster', async () => {
    const calls: string[][] = [];
    expect(await tenantUid(kubectl({ stdout: `${uid}\n` }, calls), 'identity-pg')).toBe(uid);
    expect(calls[0]).toEqual([
      'get',
      'tenants.platform.di-framework.dev',
      'identity-pg',
      '-o',
      'jsonpath={.metadata.uid}',
    ]);
    await expect(tenantUid(kubectl({ code: 1 }), 'x')).rejects.toThrow('cannot read Tenant x');
    await expect(tenantUid(kubectl({ stdout: 'not-a-uid' }), 'x')).rejects.toThrow('create it');

    const paths = [
      `/var/lib/kubesolo/di-tenants/${uid}/workloads/identity`,
      `/var/lib/kubesolo/di-tenants/${uid}/directory`,
      '/lib/modules',
      '',
    ].join('\n');
    expect(await discoverStorageRoot(kubectl({ stdout: paths }))).toBe('/var/lib/kubesolo');
    await expect(discoverStorageRoot(kubectl({ stdout: '/lib/modules\n' }))).rejects.toThrow(
      'found no platform storage roots',
    );
    await expect(
      discoverStorageRoot(kubectl({ stdout: `/a/di-tenants/${uid}/x\n/b/di-tenants/${uid}/y\n` })),
    ).rejects.toThrow('found several platform storage roots (/a, /b)');
    await expect(discoverStorageRoot(kubectl({ code: 1 }))).rejects.toThrow(
      'cannot list deployments',
    );

    expect(workloadStoragePath('/var/lib/kubesolo/', uid, 'identity')).toBe(
      `/var/lib/kubesolo/di-tenants/${uid}/workloads/identity`,
    );
    expect(() => workloadStoragePath('relative', uid, 'identity')).toThrow('invalid storage root');
    expect(() => workloadStoragePath('/a/../b', uid, 'identity')).toThrow('invalid storage root');
    expect(() => workloadStoragePath('/a', 'nope', 'identity')).toThrow('invalid tenant uid');
    expect(() => workloadStoragePath('/a', uid, 'Bad')).toThrow('invalid workload');

    expect(await singleNode(kubectl({ stdout: 'kubesolo-node' }))).toBe('kubesolo-node');
    await expect(singleNode(kubectl({ stdout: 'a b' }))).rejects.toThrow(
      'expected one node, found 2',
    );
    expect(entries(' a\n\n b \n')).toEqual(['a', 'b']);
  });

  test('the helper pod is pinned, minimal and mounts only the tenant workloads directory', () => {
    const pod = helperPod({
      name: 'p',
      namespace: 'kube-system',
      node: 'n',
      image: 'busybox:1.37.0',
      target: `/var/lib/kubesolo/di-tenants/${uid}/workloads/identity`,
    }) as { spec: Record<string, unknown> };
    expect(pod.spec).toMatchObject({
      nodeName: 'n',
      automountServiceAccountToken: false,
      volumes: [
        {
          name: 'target',
          hostPath: {
            path: `/var/lib/kubesolo/di-tenants/${uid}/workloads/identity`,
            type: 'DirectoryOrCreate',
          },
        },
      ],
    });
    const [container] = pod.spec.containers as Array<Record<string, unknown>>;
    expect(container?.securityContext).toMatchObject({
      allowPrivilegeEscalation: false,
      readOnlyRootFilesystem: true,
      capabilities: { drop: ['ALL'], add: ['CHOWN', 'DAC_OVERRIDE'] },
    });
  });
});

test("the runner's WIT is the provider package's `types` and `database` interfaces", () => {
  const strip = (wit: string) => {
    const lines = wit.split('\n').filter((line) => !line.trim().startsWith('//'));
    const text = lines.join('\n');
    const block = (name: string) => {
      const start = text.indexOf(`interface ${name} {`);
      return text.slice(start, text.indexOf('\n}', start) + 2);
    };
    return [block('types'), block('database')];
  };
  const root = join(import.meta.dir, '..', '..');
  const vendored = readFileSync(join(import.meta.dir, 'pglite-runner/wit/world.wit'), 'utf8');
  const published = readFileSync(
    join(root, 'apps/guest/node_modules/@di-framework/pglite-component/wit/world.wit'),
    'utf8',
  );
  expect(vendored).toStartWith('package di-framework:pglite@0.2.0;');
  expect(strip(vendored)).toEqual(strip(published));
  expect(strip(vendored)[1]).toContain('resource connection');
});

describe('the rehearsal sign-in checks', () => {
  const HASH = '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA';
  const loaded = {
    manifest: {} as never,
    state: {},
    rows: new Map([
      [
        'users',
        JSON.stringify([
          { login: 'Root-Admin', password_hash: HASH },
          { login: 'no-password', password_hash: null },
        ]),
      ],
    ]),
  };

  test('password hashes are compared as digests, never shown', () => {
    expect(passwordHashDigest(HASH)).toBe(createHash('sha256').update(HASH).digest('hex'));
    expect(passwordHashDigest(null)).toBeUndefined();
    expect(passwordHashDigest('')).toBeUndefined();
    // Logins match as the directory normalises them.
    const exported = exportedPasswordHashDigest(loaded, ' root-admin ');
    expect(exported).toEqual({ found: true, digest: passwordHashDigest(HASH) });
    expect(exportedPasswordHashDigest(loaded, 'ghost')).toEqual({
      found: false,
      digest: undefined,
    });
    const same = { found: true, digest: passwordHashDigest(HASH) };
    expect(compareHashes(exported, same)).toBe('same');
    expect(compareHashes(exported, { found: true, digest: passwordHashDigest('other') })).toBe(
      'differs',
    );
    // A user without a hash never counts as carried.
    const none = exportedPasswordHashDigest(loaded, 'no-password');
    expect(compareHashes(none, { found: true, digest: undefined })).toBe('differs');
    expect(compareHashes(exported, { found: false, digest: undefined })).toBe('missing');
    expect(compareHashes(undefined, same)).toBe('no-export');
  });

  test('a changed password is a note only when the hash was carried; other failures stay fatal', () => {
    const signedIn = { status: 303, signedIn: true };
    const rejected = { status: 303, signedIn: false };
    expect(classifySignIn('owner', signedIn, 'no-export')).toEqual({
      name: 'owner sign-in',
      status: 'ok',
      detail: 'HTTP 303, signed in: true with the bootstrap password',
    });
    const changed = classifySignIn('viewer', rejected, 'same');
    expect(changed.status).toBe('note');
    expect(changed.detail).toBe(
      "HTTP 303, signed in: false: password changed since bootstrap (expected if the user changed it); the stored hash was carried unchanged (digest equals the export's)",
    );
    expect(formatResult(changed)).toStartWith('note viewer sign-in: HTTP 303');
    // The owner gets the same rule.
    expect(classifySignIn('owner', rejected, 'same').status).toBe('note');
    // Not provable, or not carried: fatal.
    expect(classifySignIn('viewer', rejected, 'no-export')).toMatchObject({
      status: 'fail',
      detail: expect.stringContaining('pass --export'),
    });
    expect(classifySignIn('viewer', rejected, 'differs')).toMatchObject({
      status: 'fail',
      detail: expect.stringContaining("differs from the export's"),
    });
    expect(classifySignIn('viewer', rejected, 'missing').status).toBe('fail');
    // Anything but the login page's redirect is fatal, whatever the hash says.
    for (const status of [200, 400, 500, 503]) {
      expect(classifySignIn('owner', { status, signedIn: false }, 'same').status).toBe('fail');
    }
    expect(
      formatResult(classifySignIn('owner', { status: 500, signedIn: false }, 'same')),
    ).toStartWith('FAIL owner sign-in: HTTP 500');
  });

  test('the hash format is compared with the bootstrap clients, never showing the hash', () => {
    const head = '$argon2id$v=19$m=19456,t=2,p=1';
    expect(hashFormat(HASH)).toBe(head);
    for (const bad of [
      null,
      '',
      'plain',
      '$2b$10$abc',
      '$argon2id$v=19$m=1',
      '$argon2id$v=19$m=1$$h',
    ]) {
      expect(hashFormat(bad)).toBeUndefined();
    }
    const same = classifyHashFormat('owner', head, [head, head, head]);
    expect(same).toEqual({
      name: 'owner password hash format',
      status: 'ok',
      detail: "argon2id, same version and parameters as the bootstrap clients' hashes",
    });
    expect(
      classifyHashFormat('viewer', '$argon2id$v=19$m=65536,t=3,p=4', [head, undefined]).status,
    ).toBe('note');
    expect(classifyHashFormat('viewer', '$argon2i$v=19$m=19456,t=2,p=1', [head]).status).toBe(
      'fail',
    );
    expect(classifyHashFormat('viewer', '$argon2id$v=16$m=19456,t=2,p=1', [head]).status).toBe(
      'fail',
    );
    expect(classifyHashFormat('viewer', undefined, [head])).toMatchObject({
      status: 'fail',
      detail: expect.stringContaining('not an Argon2 PHC string'),
    });
    expect(classifyHashFormat('viewer', head, [undefined]).status).toBe('fail');
    const printed = JSON.stringify([same, classifyHashFormat('viewer', head, [head])]);
    expect(printed).not.toContain('c2FsdHNhbHQ');
    expect(printed).not.toContain('aGFzaGhhc2hoYXNoaGFzaA');
  });

  test('bootstrap settings come from the values before wasi:config', () => {
    const config = { AUTH_BOOTSTRAP_OWNER_LOGIN: 'owner' };
    expect(bootstrapSetting('AUTH_BOOTSTRAP_OWNER_LOGIN', {}, config)).toBe('owner');
    expect(
      bootstrapSetting(
        'AUTH_BOOTSTRAP_OWNER_LOGIN',
        { AUTH_BOOTSTRAP_OWNER_LOGIN: 'root' },
        config,
      ),
    ).toBe('root');
  });
});
