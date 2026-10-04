import * as pulumi from '@pulumi/pulumi';
import { portForward, runProcess } from './process';

/**
 * A di-framework application deployed with the di-framework CLI, as a Pulumi resource.
 * Create and update run `di-framework platform deploy`, which builds the component,
 * publishes it, and applies its WorkloadDeployment, Service, and bindings. Delete runs
 * `di-framework platform destroy`. The CLI keeps owning the generated manifests; this
 * resource decides when they are applied.
 *
 * `sourceDigest` is the change trigger: when it differs, the next update redeploys.
 */
export interface CliWorkloadInputs {
  /** Project name from its di-framework.config.json. */
  application: string;
  /** Target in di-framework.deploy.toml. */
  target: string;
  /** Workspace root containing di-framework.deploy.toml. */
  workspaceRoot: string;
  /** di-framework CLI binary. */
  cli: string;
  /** Variables di-framework.deploy.toml interpolates for the target. */
  environment: Record<string, string>;
  /** Opened for the duration of a deploy, so pushes reach an in-cluster registry. */
  registryForward?: {
    kubeconfig: string;
    context?: string;
    namespace: string;
    service: string;
    localPort: number;
    remotePort: number;
  };
  sourceDigest: string;
}

interface CliWorkloadState extends CliWorkloadInputs {
  image: string;
  namespace: string;
}

/** Pulumi resolves outputs nested in resource inputs, so each field may be one. */
type DeepInput<T> = pulumi.Input<
  T extends string | number | boolean ? T : { [K in keyof T]: DeepInput<T[K]> }
>;
type CliWorkloadArgs = { [K in keyof CliWorkloadInputs]: DeepInput<CliWorkloadInputs[K]> };

/** Paths and tools can differ between machines without changing what is deployed. */
const LOCAL_ONLY = ['workspaceRoot', 'cli', 'registryForward'];
const REPLACE_ON_CHANGE = ['application', 'target'];

export class CliWorkload extends pulumi.dynamic.Resource {
  /** Pull reference of the deployed component. */
  declare readonly image: pulumi.Output<string>;
  declare readonly namespace: pulumi.Output<string>;

  constructor(name: string, args: CliWorkloadArgs, opts?: pulumi.CustomResourceOptions) {
    super(workloadProvider, name, { ...args, image: undefined, namespace: undefined }, opts);
  }
}

const workloadProvider: pulumi.dynamic.ResourceProvider = {
  async diff(_id: string, olds: CliWorkloadState, news: CliWorkloadInputs) {
    const keys = [...new Set([...Object.keys(olds), ...Object.keys(news)])].filter(
      // `__provider` is Pulumi's serialized provider code; a refactor must not redeploy.
      (key) =>
        !key.startsWith('__') &&
        !LOCAL_ONLY.includes(key) &&
        key !== 'image' &&
        key !== 'namespace',
    );
    const differs = (key: string) =>
      JSON.stringify((olds as unknown as Record<string, unknown>)[key]) !==
      JSON.stringify((news as unknown as Record<string, unknown>)[key]);
    return {
      changes: keys.some(differs),
      replaces: REPLACE_ON_CHANGE.filter(differs),
      deleteBeforeReplace: true,
    };
  },
  async create(inputs: CliWorkloadInputs) {
    return { id: `${inputs.target}/${inputs.application}`, outs: await deploy(inputs) };
  },
  async update(_id: string, _olds: CliWorkloadState, news: CliWorkloadInputs) {
    return { outs: await deploy(news) };
  },
  async delete(_id: string, state: CliWorkloadState) {
    await runCli(state, ['platform', 'destroy', state.application, '--target', state.target]);
  },
};

async function deploy(inputs: CliWorkloadInputs): Promise<CliWorkloadState> {
  const forward = inputs.registryForward ? await portForward(inputs.registryForward) : undefined;
  try {
    const data = await runCli(inputs, [
      'platform',
      'deploy',
      inputs.application,
      '--target',
      inputs.target,
      '--yes',
    ]);
    return {
      ...inputs,
      image: String(data.image ?? ''),
      namespace: String(data.namespace ?? ''),
    };
  } finally {
    await forward?.stop();
  }
}

/**
 * Runs a CLI command with `--json` and returns its `data`. A failure reports the CLI's
 * own error message, plus the log of its build and tool output.
 */
async function runCli(inputs: CliWorkloadInputs, args: string[]): Promise<Record<string, unknown>> {
  const command = `di-framework ${args.slice(0, 2).join(' ')}`;
  const result = await runProcess(inputs.cli, [...args, '--json'], {
    cwd: inputs.workspaceRoot,
    env: { ...process.env, ...inputs.environment },
    log: `di-framework-${args[1]}-${inputs.application}.log`,
    capture: true,
  });
  const line = result.stdout.trim().split('\n').pop() ?? '';
  let parsed: { ok?: boolean; data?: Record<string, unknown>; error?: { message?: string } };
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new Error(`${command} exited with ${result.code}; log: ${result.log}\n${result.tail}`);
  }
  if (result.code !== 0 || !parsed.ok) {
    const message = parsed.error?.message ?? `exited with ${result.code}`;
    throw new Error(`${command}: ${message}\nlog: ${result.log}\n${result.tail}`);
  }
  return parsed.data ?? {};
}

/**
 * sha256 over every source file under `roots` (paths relative to `base`), skipping
 * dependencies, build output, and tests, so the digest moves only when the code that
 * ends up in the component can have changed.
 */
export function sourceDigest(base: string, roots: string[]): string {
  const crypto = require('node:crypto') as typeof import('node:crypto');
  const fs = require('node:fs') as typeof import('node:fs');
  const path = require('node:path') as typeof import('node:path');
  const skipDirectories = new Set([
    'node_modules',
    'dist',
    'coverage',
    'tests',
    '.di-framework',
    '.git',
  ]);
  const files: string[] = [];
  const walk = (relative: string) => {
    const absolute = path.join(base, relative);
    if (!fs.existsSync(absolute)) return;
    if (fs.statSync(absolute).isFile()) {
      files.push(relative);
      return;
    }
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      if (entry.isDirectory() && skipDirectories.has(entry.name)) continue;
      if (entry.isFile() && /\.test\.tsx?$/.test(entry.name)) continue;
      walk(path.join(relative, entry.name));
    }
  };
  for (const root of roots) walk(root);
  const hash = crypto.createHash('sha256');
  for (const file of files.sort()) {
    hash.update(file.split(path.sep).join('/'));
    hash.update('\0');
    hash.update(fs.readFileSync(path.join(base, file)));
    hash.update('\0');
  }
  return hash.digest('hex');
}
