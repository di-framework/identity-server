import * as pulumi from '@pulumi/pulumi';
import { applyRuntimeSecrets } from './control-secret';
import { kubectlRunner, portForward } from './process';

/**
 * The identity guest's runtime secrets (issuer, origin, signing key, passwords, client secrets,
 * SMTP host and password), written to the workload's `<workload>-control` Secret. The platform
 * merges that Secret into the guest's WASI environment (`localResources.environment.secretFrom`),
 * and the guest reads the values from there (apps/guest/src/settings.ts). They never reach the
 * database. Tenant admission lets a workload without an environment label reference only that
 * Secret, and wasi:config refuses secrets and URLs.
 *
 * `di-framework platform deploy` keeps the control Secret's declared keys (`controlSecretKeys`)
 * and rotates its token. This resource still writes the whole Secret after each deploy of
 * `CliWorkload` (its `deployment` input changes with every deploy), after checking that the
 * cluster's `DI_PGLITE_KEY` is the stack's (`checkStoredPgliteKey`): a fresh control
 * token (the identity workload has no cron or queue invokers that use it), the identity, and the
 * values. The document goes to kubectl on stdin; no value is in an argument list or a log.
 * It then rolls the workload with a revision entry in its environment config, since a running
 * instance keeps the environment it started with, and waits until `/health` answers 200 through
 * the tenant's `di-http` Service. Until then the guest fails closed with HTTP 503.
 */
export interface RuntimeSecretsInputs {
  kubeconfig: string;
  context?: string;
  /** Tenant namespace holding the WorkloadDeployment and its control Secret. */
  tenantNamespace: string;
  /** Tenant runtime namespace holding the `di-http` Service. */
  runtimeNamespace: string;
  /** WorkloadDeployment name; the Secret is `<workload>-control`. */
  workload: string;
  /** Host header that routes to the workload through `di-http`. */
  workloadHost: string;
  /** Loopback port for the `di-http` port-forward. */
  localPort: number;
  /** Changes with every CLI deploy, which drops the values from the Secret. */
  deployment: string;
  /** Environment name to value. */
  values: Record<string, string>;
}

type DeepInput<T> = pulumi.Input<
  T extends string | number | boolean ? T : { [K in keyof T]: DeepInput<T[K]> }
>;
type RuntimeSecretsArgs = { [K in keyof RuntimeSecretsInputs]: DeepInput<RuntimeSecretsInputs[K]> };

export class RuntimeSecrets extends pulumi.dynamic.Resource {
  constructor(name: string, args: RuntimeSecretsArgs, opts?: pulumi.CustomResourceOptions) {
    super(secretsProvider, name, args, { ...opts, additionalSecretOutputs: ['values'] });
  }
}

const secretsProvider: pulumi.dynamic.ResourceProvider = {
  async diff(_id: string, olds: RuntimeSecretsInputs, news: RuntimeSecretsInputs) {
    const keys = ['tenantNamespace', 'workload', 'deployment', 'values'];
    const differs = (key: string) =>
      JSON.stringify((olds as unknown as Record<string, unknown>)[key]) !==
      JSON.stringify((news as unknown as Record<string, unknown>)[key]);
    return { changes: keys.some(differs) };
  },
  async create(inputs: RuntimeSecretsInputs) {
    await write(inputs);
    return { id: `${inputs.tenantNamespace}/${inputs.workload}-control`, outs: inputs };
  },
  async update(_id: string, _olds: RuntimeSecretsInputs, news: RuntimeSecretsInputs) {
    await write(news);
    return { outs: news };
  },
  // `di-framework platform destroy` deletes the control Secret with the workload.
  async delete() {},
};

async function write(inputs: RuntimeSecretsInputs): Promise<void> {
  const crypto = require('node:crypto') as typeof import('node:crypto');
  const kubectl = kubectlRunner(
    inputs.kubeconfig,
    inputs.context,
    `runtime-secrets-${inputs.workload}.log`,
  );
  // Refuses a tenant that still has the Postgres `directory` BackingService (authproto), writes
  // the whole Secret on stdin, and rolls the workload by setting only the revision key. A new
  // revision on every write: the Secret always gets a fresh control token.
  await applyRuntimeSecrets(kubectl, {
    tenant: inputs.tenantNamespace.replace(/^di-tenant-/, ''),
    workload: inputs.workload,
    values: inputs.values,
    token: crypto.randomBytes(32).toString('base64url'),
    revision: crypto
      .createHash('sha256')
      .update(inputs.deployment)
      .update(crypto.randomBytes(16))
      .digest('hex')
      .slice(0, 16),
  });

  const forward = await portForward({
    kubeconfig: inputs.kubeconfig,
    context: inputs.context,
    namespace: inputs.runtimeNamespace,
    service: 'di-http',
    localPort: inputs.localPort,
    remotePort: 80,
  });
  try {
    await waitForHealthy(inputs);
  } finally {
    await forward.stop();
  }
}

/** The first boot runs initdb and hashes the bootstrap secrets; later rolls take seconds. */
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
