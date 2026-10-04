import * as pulumi from '@pulumi/pulumi';
import { portForward, runLogged, runProcess } from './process';

/**
 * Rows in a wasmCloud guest's `identity_runtime_secret` table, the channel for settings that
 * wasi:config refuses (keys, passwords, URLs).
 *
 * The table lives in a platform Postgres BackingService. Its network policy admits only
 * wasmCloud host pods, so rows are written by `psql` inside the Postgres pod through
 * `kubectl exec`, with the SQL on stdin. The guest's own migrations create the table on its
 * first request, so this resource sends one request through the tenant's `di-http` Service
 * first, and afterwards waits until the guest boots healthy with the new values.
 *
 * Only the names in `values` are managed. Other rows, such as the guest's bootstrap
 * fingerprint, are left alone.
 */
export interface RuntimeSecretsInputs {
  kubeconfig: string;
  context?: string;
  /** Tenant runtime namespace holding Postgres and the `di-http` Service. */
  runtimeNamespace: string;
  /** BackingService name; its Postgres pods carry `app=di-bs-<service>`. */
  service: string;
  /** Host header that routes to the workload through `di-http`. */
  workloadHost: string;
  /** Loopback port for the `di-http` port-forward. */
  localPort: number;
  /** Row name to value. */
  values: Record<string, string>;
}

interface RuntimeSecretsState extends RuntimeSecretsInputs {
  /** Managed row names, so a later update or delete knows which rows are ours. */
  names: string[];
}

type DeepInput<T> = pulumi.Input<
  T extends string | number | boolean ? T : { [K in keyof T]: DeepInput<T[K]> }
>;
type RuntimeSecretsArgs = { [K in keyof RuntimeSecretsInputs]: DeepInput<RuntimeSecretsInputs[K]> };

export class RuntimeSecrets extends pulumi.dynamic.Resource {
  declare readonly names: pulumi.Output<string[]>;

  constructor(name: string, args: RuntimeSecretsArgs, opts?: pulumi.CustomResourceOptions) {
    super(
      secretsProvider,
      name,
      { ...args, names: undefined },
      {
        ...opts,
        additionalSecretOutputs: ['values'],
      },
    );
  }
}

const secretsProvider: pulumi.dynamic.ResourceProvider = {
  async diff(_id: string, olds: RuntimeSecretsState, news: RuntimeSecretsInputs) {
    const keys = ['runtimeNamespace', 'service', 'values'];
    const differs = (key: string) =>
      JSON.stringify((olds as unknown as Record<string, unknown>)[key]) !==
      JSON.stringify((news as unknown as Record<string, unknown>)[key]);
    return { changes: keys.some(differs) };
  },
  async create(inputs: RuntimeSecretsInputs) {
    return { id: `${inputs.runtimeNamespace}/${inputs.service}`, outs: await write(inputs, []) };
  },
  async update(_id: string, olds: RuntimeSecretsState, news: RuntimeSecretsInputs) {
    return { outs: await write(news, olds.names ?? []) };
  },
  async delete(_id: string, state: RuntimeSecretsState) {
    const pod = await postgresPod(state, false);
    if (!pod) return; // The database is already gone.
    await psql(state, pod, deleteRows(state.names ?? Object.keys(state.values)).join('\n'));
  },
};

async function write(
  inputs: RuntimeSecretsInputs,
  previous: string[],
): Promise<RuntimeSecretsState> {
  const pod = (await postgresPod(inputs, true)) as string;
  const forward = await portForward({
    kubeconfig: inputs.kubeconfig,
    context: inputs.context,
    namespace: inputs.runtimeNamespace,
    service: 'di-http',
    localPort: inputs.localPort,
    remotePort: 80,
  });
  try {
    await waitForTable(inputs, pod);
    const names = Object.keys(inputs.values).sort();
    const stale = previous.filter((name) => !names.includes(name));
    const upserts = names.map(
      (name) =>
        `INSERT INTO identity_runtime_secret (name, value) VALUES (${literal(name)}, ${literal(
          inputs.values[name] as string,
        )}) ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;`,
    );
    await psql(inputs, pod, ['BEGIN;', ...upserts, ...deleteRows(stale), 'COMMIT;'].join('\n'));
    await waitForHealthy(inputs);
    return { ...inputs, names };
  } finally {
    await forward.stop();
  }
}

/** The guest creates the table in its first request's migrations; prompt one and wait. */
async function waitForTable(inputs: RuntimeSecretsInputs, pod: string): Promise<void> {
  for (let attempt = 1; attempt <= 60; attempt++) {
    const exists = await psql(
      inputs,
      pod,
      "SELECT to_regclass('public.identity_runtime_secret') IS NOT NULL;",
      true,
    );
    if (exists.trim() === 't') return;
    await request(inputs, '/health').catch(() => undefined);
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  throw new Error('the guest did not create identity_runtime_secret within 5 minutes');
}

/** Boot runs Argon2id over the bootstrap secrets on QuickJS, which takes a minute or two. */
async function waitForHealthy(inputs: RuntimeSecretsInputs): Promise<void> {
  const deadline = Date.now() + 10 * 60_000;
  let last = '';
  while (Date.now() < deadline) {
    try {
      const response = await request(inputs, '/health', Math.min(180_000, deadline - Date.now()));
      if (response.status === 200) return;
      last = `${response.status} ${response.body.slice(0, 300)}`;
    } catch (error) {
      last = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  throw new Error(`the guest did not become healthy within 10 minutes: ${last}`);
}

/** GET through the `di-http` port-forward. node:http, because fetch cannot set Host. */
function request(
  inputs: RuntimeSecretsInputs,
  path: string,
  timeout = 180_000,
): Promise<{ status: number; body: string }> {
  const http = require('node:http') as typeof import('node:http');
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: inputs.localPort,
        path,
        headers: { host: inputs.workloadHost },
        timeout,
      },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => {
          body += chunk;
        });
        response.on('end', () => resolve({ status: response.statusCode ?? 0, body }));
      },
    );
    req.on('timeout', () => req.destroy(new Error(`GET ${path} timed out`)));
    req.on('error', reject);
    req.end();
  });
}

async function postgresPod(
  inputs: RuntimeSecretsInputs,
  required: boolean,
): Promise<string | undefined> {
  const result = await runProcess(
    'kubectl',
    [
      ...kubectlBase(inputs),
      'get',
      'pods',
      '-l',
      `app=di-bs-${inputs.service}`,
      '--field-selector=status.phase=Running',
      '-o',
      'jsonpath={.items[0].metadata.name}',
    ],
    { log: `runtime-secrets-${inputs.service}.log`, capture: true },
  );
  const pod = result.code === 0 ? result.stdout.trim() : '';
  if (!pod && required) {
    throw new Error(`no running Postgres pod for ${inputs.service} in ${inputs.runtimeNamespace}`);
  }
  return pod || undefined;
}

/**
 * Runs SQL as the local superuser over the pod's Unix socket, in the single application
 * database the BackingService created.
 */
async function psql(
  inputs: RuntimeSecretsInputs,
  pod: string,
  sql: string,
  capture = false,
): Promise<string> {
  const log = `runtime-secrets-${inputs.service}.log`;
  const exec = (args: string[], input: string, quiet: boolean) =>
    runLogged(
      'kubectl',
      [...kubectlBase(inputs), 'exec', '-i', pod, '-c', 'postgres', '--', ...args],
      { log, input, capture: quiet },
    );
  const database = (
    await exec(
      ['psql', '-U', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1'],
      "SELECT datname FROM pg_database WHERE NOT datistemplate AND datname <> 'postgres';",
      true,
    )
  )
    .trim()
    .split('\n');
  if (database.length !== 1 || !database[0]) {
    throw new Error(`expected one application database, found: ${database.join(', ')}`);
  }
  return exec(
    ['psql', '-U', 'postgres', '-d', database[0], '-At', '-v', 'ON_ERROR_STOP=1'],
    sql,
    capture,
  );
}

function kubectlBase(inputs: RuntimeSecretsInputs): string[] {
  return [
    '--kubeconfig',
    inputs.kubeconfig,
    ...(inputs.context ? ['--context', inputs.context] : []),
    '--namespace',
    inputs.runtimeNamespace,
  ];
}

function deleteRows(names: string[]): string[] {
  if (names.length === 0) return [];
  return [`DELETE FROM identity_runtime_secret WHERE name IN (${names.map(literal).join(', ')});`];
}

/** A standard SQL string literal; the only escape is a doubled single quote. */
function literal(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}
