/**
 * Baremetal wasmCloud platform: provision k0s over SSH with Pulumi Command,
 * then install `@di-framework/platform` 6.0.5 via `createPlatform`.
 *
 * This program is the managed `local` target. Application WorkloadDeployments
 * stay owned by `di-framework platform deploy`.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { homedir } from 'node:os';
import * as path from 'node:path';
import { createPlatform } from '@di-framework/platform';
import * as command from '@pulumi/command';
import * as k8s from '@pulumi/kubernetes';
import * as pulumi from '@pulumi/pulumi';
import { dnsCommands, k0sCommands, shellQuote } from './remote';

const REGISTRY_NODE_PORT = 30500;
const HTTP_NODE_PORT = 30180;
const namespaceName = 'wasmcloud';
const tenantName = 'identity';

const config = new pulumi.Config();
const host = config.require('sshHost');
const user = config.require('sshUser');
const sshPort = config.getNumber('sshPort') ?? 22;
const apiPort = hostPort(config, 'apiPort', 6443);
const registryPort = hostPort(config, 'registryPort', REGISTRY_NODE_PORT);
const httpPort = hostPort(config, 'httpPort', HTTP_NODE_PORT);
if (new Set([apiPort, registryPort, httpPort]).size !== 3) {
  throw new Error('apiPort, registryPort, and httpPort must be distinct');
}

const privateKeyPath = expandHome(config.require('sshPrivateKeyPath'));
const privateKey = pulumi.secret(fs.readFileSync(privateKeyPath, 'utf8'));

const stack = sanitize(pulumi.getStack());
const projectHash = createHash('sha256').update(pulumi.getProject()).digest('hex').slice(0, 10);
const scope = `di-framework-${stack}-${projectHash}`;
const markerDir = '/var/lib/di-framework-platform';
const markerPath = `${markerDir}/${scope}`;
const kubeconfigFile = path.resolve(`.kubeconfig-${stack}`);
const tenantKubeconfigFile = path.resolve(`.kubeconfig-${stack}-${tenantName}`);

const connection: command.types.input.remote.ConnectionArgs = {
  host,
  user,
  port: sshPort,
  privateKey,
};

const k0s = new command.remote.Command(
  'k0s',
  {
    connection,
    ...k0sCommands({ scope, markerPath, host, apiPort }),
  },
  { deleteBeforeReplace: true },
);

const kubeconfigCommand = new command.remote.Command(
  'kubeconfig',
  {
    connection,
    create: [
      'set -eu',
      `HOST=${shellQuote(host)}`,
      `API_PORT=${shellQuote(String(apiPort))}`,
      'sudo k0s kubeconfig admin | sed -E "s#server: https://[^:]+:[0-9]+#server: https://$HOST:$API_PORT#"',
    ].join('\n'),
    logging: command.types.enums.remote.Logging.None,
  },
  { dependsOn: [k0s], additionalSecretOutputs: ['stdout'] },
);

const originalCorefilePath = config.get('corednsOriginalCorefilePath');
const dnsSinkZone = config.get('dnsSinkZone');
const corednsSink =
  dnsSinkZone === undefined
    ? undefined
    : new command.remote.Command(
        'coredns-lan-sink',
        {
          connection,
          ...dnsCommands({
            stateDirectory: `${markerPath}.dns`,
            zone: dnsSinkZone,
            originalCorefile: originalCorefilePath
              ? fs.readFileSync(expandHome(originalCorefilePath), 'utf8')
              : undefined,
          }),
        },
        { dependsOn: [kubeconfigCommand] },
      );

const kubeconfigContents = pulumi.secret(kubeconfigCommand.stdout);
const kubeconfigFileCommand = writeKubeconfigFile(
  'kubeconfig-file',
  kubeconfigFile,
  kubeconfigContents,
  [kubeconfigCommand],
);

const provider = new k8s.Provider(
  'k0s',
  {
    kubeconfig: kubeconfigContents,
    enableServerSideApply: true,
    // The host already has platform CRDs from a removed install. Upsert adopts
    // them into this stack instead of failing create with AlreadyExists.
    upsertExistingObjects: true,
  },
  { dependsOn: corednsSink ? [kubeconfigCommand, corednsSink] : [kubeconfigCommand] },
);

const apiServer = `https://${host}:${apiPort}`;
const platform = createPlatform({
  provider,
  installation: scope,
  config,
  registry: true,
  insecureRegistry: true,
  registryNodePort: registryPort,
  httpNodePort: httpPort,
  storageRoot: '/var/lib/k0s',
  networkPolicyEngine: 'existing',
  apiServer,
  // Absolute NATS FQDNs (trailing dot). Pod search can include a LAN zone that
  // still answers stale service names, so cluster names stay absolute.
  values: {
    global: {
      nats: {
        schedulerUrl: 'nats://nats.wasmcloud.svc.cluster.local.:4222',
        dataUrl: 'nats://nats.wasmcloud.svc.cluster.local.:4222',
      },
    },
  },
  beforeTenancy: (wasmcloud) =>
    new command.remote.Command(
      'runtime-shutdown',
      {
        connection,
        create: 'true',
        delete: [
          'set -eu',
          `NAMESPACE=${shellQuote(namespaceName)}`,
          'sudo k0s kubectl --namespace "$NAMESPACE" delete deployment/hostgroup-default --ignore-not-found=true --wait=true --timeout=180s || true',
          'sudo k0s kubectl --namespace "$NAMESPACE" delete hosts.runtime.wasmcloud.dev --all --ignore-not-found=true --wait=true --timeout=180s || true',
        ].join('\n'),
      },
      { dependsOn: [wasmcloud, kubeconfigFileCommand] },
    ),
});

if (platform.kubeconfigs === undefined) {
  throw new Error('createPlatform must export tenant kubeconfigs when apiServer is set');
}
const developerName = developerFor(config, tenantName);
const tenantKubeconfig = pulumi.secret(
  platform.kubeconfigs.apply((all) => {
    const yaml = all[tenantName]?.[developerName];
    if (!yaml) {
      throw new Error(`missing kubeconfig for user ${developerName} on tenant ${tenantName}`);
    }
    return yaml;
  }),
);
const tenantKubeconfigFileCommand = writeKubeconfigFile(
  'tenant-kubeconfig-file',
  tenantKubeconfigFile,
  tenantKubeconfig,
  [platform.release],
);

export const tenants = platform.tenants;
export const users = platform.users;
export const schemaVersion = 2;
export const kubeconfig = kubeconfigFileCommand.id.apply(() => kubeconfigFile);
export const tenantKubeconfigPath = tenantKubeconfigFileCommand.id.apply(
  () => tenantKubeconfigFile,
);
export const namespace = platform.namespace;
export const registry = {
  push: `http://${host}:${registryPort}`,
  pull: `di-framework-registry.${namespaceName}.svc.cluster.local:5000`,
  insecure: true,
};
export const endpoints = {
  http: `http://${host}:${httpPort}`,
  kubernetes: apiServer,
  registry: `http://${host}:${registryPort}`,
};

function writeKubeconfigFile(
  name: string,
  file: string,
  contents: pulumi.Input<string>,
  dependsOn: pulumi.Resource[],
): command.local.Command {
  const script = [
    'bun -e',
    shellQuote(
      [
        "import { chmodSync, writeFileSync } from 'node:fs';",
        'const file = process.env.KUBECONFIG_FILE;',
        "const content = process.env.KUBECONFIG_CONTENT ?? '';",
        "if (!file) throw new Error('KUBECONFIG_FILE is required');",
        "writeFileSync(file, content.endsWith('\\n') ? content : content + '\\n', { mode: 0o600 });",
        'chmodSync(file, 0o600);',
      ].join(''),
    ),
  ].join(' ');
  return new command.local.Command(
    name,
    {
      create: script,
      update: script,
      delete: 'if [ -n "$KUBECONFIG_FILE" ]; then rm -f -- "$KUBECONFIG_FILE"; fi',
      environment: {
        KUBECONFIG_CONTENT: contents,
        KUBECONFIG_FILE: file,
      },
      logging: command.types.enums.local.Logging.None,
    },
    { dependsOn, additionalSecretOutputs: ['environment'] },
  );
}

function developerFor(configuration: pulumi.Config, tenant: string): string {
  const users =
    configuration.requireObject<
      { name?: string; memberships?: { tenant?: string; role?: string }[] }[]
    >('users');
  const developer = users.find((user) =>
    user.memberships?.some(
      (membership) => membership.tenant === tenant && membership.role === 'developer',
    ),
  );
  if (!developer?.name) {
    throw new Error(`stack users must include a developer of tenant ${tenant}`);
  }
  return developer.name;
}

function hostPort(configuration: pulumi.Config, name: string, fallback: number): number {
  const value = configuration.getNumber(name) ?? fallback;
  if (!Number.isInteger(value) || value < 1024 || value > 65535) {
    throw new Error(`${name} must be an integer from 1024 through 65535; received ${value}`);
  }
  return value;
}

function sanitize(value: string): string {
  const sanitized = value
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return sanitized || 'stack';
}

function expandHome(value: string): string {
  return value.startsWith('~/') ? path.join(homedir(), value.slice(2)) : value;
}
