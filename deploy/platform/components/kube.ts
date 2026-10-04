import * as pulumi from '@pulumi/pulumi';
import { runLogged } from './process';

/**
 * A di-framework-kube instance as a Pulumi resource: create and update run
 * `di-framework-kube up`, delete runs `di-framework-kube down`. kube itself owns
 * the Kubesolo cluster and the @di-framework/platform install (in its own Pulumi
 * project under its state directory); this resource only drives its CLI.
 *
 * The provider downloads the release binary for this machine from GitHub, checks
 * it against the release's checksums.txt, and caches it. It does this on every
 * operation, so `pulumi destroy` works even after the cache is cleared.
 *
 * Everything below `KubeInstance` runs inside Pulumi's dynamic provider, which
 * serializes these functions. They load Node modules with `require` at call time
 * so the serialized code captures nothing but plain values.
 */

export const KUBE_REPOSITORY = 'di-framework/kube';

export interface KubeInstanceInputs {
  /** Instance name; one instance per stack. */
  name: string;
  /** Release tag to download, such as `v0.0.3`. Unused when `binary` is set. */
  version?: string;
  /** A local di-framework-kube build to use instead of a release download. */
  binary?: string;
  /** kube `--state-dir`; kube's per-user default when unset. */
  stateDir?: string;
  /** Install onto this existing cluster instead of creating Kubesolo. */
  existingKubeconfig?: string;
  existingContext?: string;
  /** Loopback gateway port; fixed when a local Kubesolo container is created. */
  httpPort?: number;
  /** Exact `@di-framework/platform` package kube installs. */
  platformPackage: string;
  /** `--platform-config` document: tenants, users, and tenant host settings. */
  platformConfig: unknown;
  /** Administrator Helm values documents, each passed as `--values`. */
  values?: unknown[];
  allowInsecureRegistries: boolean;
  /** Also delete the Kubesolo cluster and its data on delete. Ignored for existing clusters. */
  purgeOnDelete: boolean;
}

interface KubeInstanceState extends KubeInstanceInputs {
  kubeconfig: string;
  kubeconfigContent: string;
  context: string | null;
  namespace: string;
  endpoints: { http?: string; kubernetes?: string };
}

type KubeInstanceArgs = { [K in keyof KubeInstanceInputs]: pulumi.Input<KubeInstanceInputs[K]> };

/** Inputs whose change means a different instance rather than an upgrade of this one. */
const REPLACE_ON_CHANGE = ['name', 'stateDir', 'existingKubeconfig', 'existingContext'];
const INPUT_KEYS = [
  ...REPLACE_ON_CHANGE,
  'version',
  'binary',
  'httpPort',
  'platformPackage',
  'platformConfig',
  'values',
  'allowInsecureRegistries',
  'purgeOnDelete',
];

export class KubeInstance extends pulumi.dynamic.Resource {
  /** Admin kubeconfig path in kube's state directory. */
  declare readonly kubeconfig: pulumi.Output<string>;
  declare readonly kubeconfigContent: pulumi.Output<string>;
  /** Context kube selected, for existing clusters; null when the kubeconfig's current one applies. */
  declare readonly context: pulumi.Output<string | null>;
  declare readonly namespace: pulumi.Output<string>;
  declare readonly endpoints: pulumi.Output<{ http?: string; kubernetes?: string }>;

  constructor(name: string, args: KubeInstanceArgs, opts?: pulumi.CustomResourceOptions) {
    super(
      kubeProvider,
      name,
      {
        ...args,
        kubeconfig: undefined,
        kubeconfigContent: undefined,
        context: undefined,
        namespace: undefined,
        endpoints: undefined,
      },
      { ...opts, additionalSecretOutputs: ['kubeconfigContent'] },
    );
  }
}

/**
 * The newest published release tag, for stacks that track `latest`. Transient GitHub
 * failures are retried; if GitHub stays unreachable, the newest release already in the
 * local cache is used with a warning, so an outage does not block `pulumi up`.
 */
export async function latestKubeRelease(): Promise<string> {
  const token = process.env.GITHUB_TOKEN;
  let failure = '';
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(
        `https://api.github.com/repos/${KUBE_REPOSITORY}/releases/latest`,
        {
          headers: {
            accept: 'application/vnd.github+json',
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
        },
      );
      if (response.status === 404) {
        throw new Error(
          `${KUBE_REPOSITORY} has no published release; set kubeVersion to a tag or kubeBinary to a local build`,
        );
      }
      if (response.ok) {
        const release = (await response.json()) as { tag_name?: string };
        if (!release.tag_name) throw new Error(`latest ${KUBE_REPOSITORY} release has no tag`);
        return release.tag_name;
      }
      failure = `HTTP ${response.status}`;
      // Client errors other than rate limiting will not improve on retry.
      if (response.status < 500 && response.status !== 403 && response.status !== 429) break;
    } catch (error) {
      if (error instanceof Error && error.message.includes('no published release')) throw error;
      failure = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, attempt * 2000));
  }
  const cached = newestCachedRelease();
  if (cached === undefined) {
    throw new Error(`looking up the latest ${KUBE_REPOSITORY} release: ${failure}`);
  }
  pulumi.log.warn(
    `looking up the latest ${KUBE_REPOSITORY} release failed (${failure}); using cached ${cached}`,
  );
  return cached;
}

/** Highest `v<major>.<minor>.<patch>` directory in the download cache, if any. */
function newestCachedRelease(): string | undefined {
  const fs = require('node:fs') as typeof import('node:fs');
  const os = require('node:os') as typeof import('node:os');
  const path = require('node:path') as typeof import('node:path');
  const cacheRoot = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  const directory = path.join(cacheRoot, 'di-framework-kube');
  if (!fs.existsSync(directory)) return undefined;
  const parts = (tag: string) => tag.slice(1).split('.').map(Number);
  return fs
    .readdirSync(directory)
    .filter((name) => /^v\d+\.\d+\.\d+$/.test(name))
    .sort((a, b) => {
      const [x, y] = [parts(a), parts(b)];
      return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
    })
    .pop();
}

const kubeProvider: pulumi.dynamic.ResourceProvider = {
  async diff(_id: string, olds: KubeInstanceState, news: KubeInstanceInputs) {
    const differs = (key: string) =>
      JSON.stringify((olds as unknown as Record<string, unknown>)[key]) !==
      JSON.stringify((news as unknown as Record<string, unknown>)[key]);
    const replaces = REPLACE_ON_CHANGE.filter(differs);
    return { changes: INPUT_KEYS.some(differs), replaces, deleteBeforeReplace: true };
  },
  async create(inputs: KubeInstanceInputs) {
    return { id: inputs.name, outs: await kubeUp(inputs) };
  },
  async update(_id: string, _olds: KubeInstanceState, news: KubeInstanceInputs) {
    return { outs: await kubeUp(news) };
  },
  async delete(_id: string, state: KubeInstanceState) {
    const purge = state.purgeOnDelete && !state.existingKubeconfig;
    await runKube(state, ['down', '--name', state.name, ...(purge ? ['--purge-cluster'] : [])]);
  },
};

async function kubeUp(inputs: KubeInstanceInputs): Promise<KubeInstanceState> {
  const fs = require('node:fs') as typeof import('node:fs');
  const os = require('node:os') as typeof import('node:os');
  const path = require('node:path') as typeof import('node:path');
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'di-framework-kube-'));
  try {
    const platformConfig = path.join(scratch, 'platform.json');
    fs.writeFileSync(platformConfig, JSON.stringify(inputs.platformConfig));
    // JSON is YAML, so each values document can go to Helm as-is.
    const values = (inputs.values ?? []).map((document, index) => {
      const file = path.join(scratch, `values-${index}.yaml`);
      fs.writeFileSync(file, JSON.stringify(document));
      return file;
    });
    await runKube(inputs, [
      'up',
      '--name',
      inputs.name,
      '--platform-package',
      inputs.platformPackage,
      '--platform-config',
      platformConfig,
      ...(inputs.httpPort === undefined ? [] : ['--http-port', String(inputs.httpPort)]),
      ...(inputs.allowInsecureRegistries ? ['--allow-insecure-registries'] : []),
      ...(inputs.existingKubeconfig ? ['--kubeconfig', inputs.existingKubeconfig] : []),
      ...(inputs.existingContext ? ['--context', inputs.existingContext] : []),
      ...values.flatMap((file) => ['--values', file]),
    ]);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
  const outputs = JSON.parse(await runKube(inputs, ['outputs', '--name', inputs.name], true)) as {
    kubeconfig?: string;
    context?: string;
    namespace?: string;
    endpoints?: { http?: string; kubernetes?: string };
  };
  if (!outputs.kubeconfig || !outputs.namespace) {
    throw new Error(`di-framework-kube outputs for ${inputs.name} has no kubeconfig or namespace`);
  }
  return {
    ...inputs,
    kubeconfig: outputs.kubeconfig,
    kubeconfigContent: fs.readFileSync(outputs.kubeconfig, 'utf8'),
    context: outputs.context || null,
    namespace: outputs.namespace,
    endpoints: outputs.endpoints ?? {},
  };
}

/** Runs kube for this instance; see runLogged for logging and failure output. */
async function runKube(
  inputs: KubeInstanceInputs,
  args: string[],
  capture = false,
): Promise<string> {
  const argv = [...(inputs.stateDir ? ['--state-dir', inputs.stateDir] : []), ...args];
  return runLogged(await kubeBinary(inputs), argv, {
    log: `di-framework-kube-${inputs.name}-${args[0]}.log`,
    capture,
  });
}

/** The binary for this machine: a local build, or the verified release asset from the cache. */
export async function kubeBinary(inputs: KubeInstanceInputs): Promise<string> {
  if (inputs.binary) return inputs.binary;
  if (!inputs.version) throw new Error('KubeInstance needs a release version or a local binary');
  const childProcess = require('node:child_process') as typeof import('node:child_process');
  const crypto = require('node:crypto') as typeof import('node:crypto');
  const fs = require('node:fs') as typeof import('node:fs');
  const os = require('node:os') as typeof import('node:os');
  const path = require('node:path') as typeof import('node:path');

  const goos = ({ darwin: 'darwin', linux: 'linux' } as Record<string, string>)[process.platform];
  const goarch = ({ arm64: 'arm64', x64: 'amd64' } as Record<string, string>)[process.arch];
  if (!goos || !goarch) {
    throw new Error(`di-framework-kube publishes no build for ${process.platform}/${process.arch}`);
  }
  const cacheRoot = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  const directory = path.join(cacheRoot, 'di-framework-kube', inputs.version, `${goos}-${goarch}`);
  const binary = path.join(directory, 'di-framework-kube');
  if (fs.existsSync(binary)) return binary;

  const download = async (url: string): Promise<Buffer> => {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`downloading ${url}: HTTP ${response.status}`);
    return Buffer.from(await response.arrayBuffer());
  };
  // GoReleaser names: di-framework-kube_<version without v>_<os>_<arch>.tar.gz plus checksums.txt.
  const asset = `di-framework-kube_${inputs.version.replace(/^v/, '')}_${goos}_${goarch}.tar.gz`;
  const base = `https://github.com/${KUBE_REPOSITORY}/releases/download/${inputs.version}`;
  const checksums = (await download(`${base}/checksums.txt`)).toString('utf8');
  const expected = checksums
    .split('\n')
    .map((line) => line.trim().split(/\s+/))
    .find(([, file]) => file === asset)?.[0];
  if (!expected) throw new Error(`${inputs.version} checksums.txt does not list ${asset}`);
  const archive = await download(`${base}/${asset}`);
  const actual = crypto.createHash('sha256').update(archive).digest('hex');
  if (actual !== expected) {
    throw new Error(`${asset} sha256 is ${actual}; checksums.txt says ${expected}`);
  }

  fs.mkdirSync(directory, { recursive: true });
  const staging = fs.mkdtempSync(path.join(directory, '.download-'));
  try {
    const archivePath = path.join(staging, asset);
    fs.writeFileSync(archivePath, archive);
    childProcess.execFileSync('tar', ['-xzf', archivePath, '-C', staging, 'di-framework-kube']);
    const extracted = path.join(staging, 'di-framework-kube');
    fs.chmodSync(extracted, 0o755);
    fs.renameSync(extracted, binary);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
  return binary;
}
