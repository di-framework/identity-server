/**
 * Identity on wasmCloud, end to end, as one Pulumi program:
 *
 *   KubeInstance      di-framework-kube release, verified and cached; `up` on create and
 *                     update, `down` on delete. kube creates Kubesolo (or uses an existing
 *                     cluster) and installs @di-framework/platform with platform.json.
 *   InClusterRegistry component registry in the platform namespace, unless `registry`
 *                     names an external one.
 *   PublishedImage    the tenant host image (wash with wasi:tls, which the component
 *                     imports), pushed from the local engine to the registry; the node
 *                     pulls it through the registry's NodePort.
 *   DeploymentPatch   rolls the tenant host onto that image whenever its digest changes.
 *   BackingService    `directory`, the tenant's Postgres, which the platform controller
 *                     provisions; the workload binds to it by name.
 *   CliWorkload       the identity component: `di-framework platform deploy` when its
 *                     sources change, `di-framework platform destroy` on delete.
 *   Mailpit           the tenant's SMTP relay in di-tenant-identity, with a platform egress
 *                     grant that lets the guest dial it; skipped when `smtpHost` is set.
 *   RuntimeSecrets    the guest's `identity_runtime_secret` rows: issuer, origin, RS256
 *                     signing key (@pulumi/tls), and passwords and client secrets
 *                     (@pulumi/random). A change rolls the tenant host so the guest reloads.
 *
 * `pulumi up` builds the environment; `pulumi destroy` removes it in reverse order.
 *
 * Stack config, all optional:
 *   kubeVersion            kube release tag, or `latest` (default: latest)
 *   kubeBinary             local di-framework-kube build instead of a release
 *   kubeInstance           kube instance name (default: identity)
 *   kubeStateDir           kube --state-dir (default: kube's per-user directory)
 *   kubeconfig, context    install onto this existing cluster instead of Kubesolo
 *   httpPort               loopback gateway port of a new Kubesolo container (default: 28180)
 *   platformPackage        exact @di-framework/platform package (default: @di-framework/platform@6.0.5)
 *   values                 list of administrator Helm values documents
 *   purgeClusterOnDestroy  delete the Kubesolo cluster and its data on destroy (default: false)
 *   registry               { push, pull } of an external registry; skips the in-cluster one
 *   registryForwardPort    loopback port for pushes to the in-cluster registry (default: 25180)
 *   registryStorageClass   StorageClass for the in-cluster registry (default: cluster default)
 *   databaseDeletionPolicy `Retain` keeps the directory database's data when the stack is
 *                          destroyed; `Delete` removes it (default: Retain)
 *   tenantHostImage        node-pullable tenant host image; skips publishing a local one
 *   tenantHostLocalImage   local engine image published as the tenant host
 *                          (default: localhost/di-framework/wash:2.8.0-wasi-tls)
 *   registryNodePort       NodePort the node pulls the published host image through (default: 30500)
 *   containerEngine        podman or docker (default: whichever answers first)
 *   platformNamespace      namespace kube installs the platform into (default: wasmcloud)
 *   publicOrigin           identity's public origin (default: the gateway URL)
 *   issuerUrl              OIDC issuer (default: publicOrigin)
 *   accessRedirectUris     access client redirect URIs (default: http://localhost:3000/callback)
 *   smtpHost               external mail relay host; skips the in-cluster Mailpit
 *   mailpitClusterIP       Mailpit's fixed ClusterIP, granted as tenant egress (default: 10.43.250.25)
 *   workloadForwardPort    loopback port for reaching the workload through di-http (default: 25181)
 */
import { createHash, createPrivateKey } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as k8s from '@pulumi/kubernetes';
import * as pulumi from '@pulumi/pulumi';
import * as random from '@pulumi/random';
import * as tls from '@pulumi/tls';
import { parse } from 'yaml';
import { containerEngine, localImageId, PublishedImage } from './components/image';
import { KubeInstance, latestKubeRelease } from './components/kube';
import { Mailpit, mailpitDestination } from './components/mailpit';
import { InClusterRegistry } from './components/registry';
import { RuntimeSecrets } from './components/secrets';
import { CliWorkload, sourceDigest } from './components/workload';

/** Project name in apps/guest/di-framework.config.json. */
const APPLICATION = 'identity';
/** Target in di-framework.deploy.toml, and the tenant declared in platform.json. */
const TARGET = 'identity';
const TENANT = 'identity';
/** Postgres BackingService the guest binds to (`serviceName` in apps/guest/src/bindings.ts). */
const DATABASE = 'directory';

interface ExternalRegistry {
  push: string;
  pull: string;
}

const config = new pulumi.Config();
const workspaceRoot = resolve(__dirname, '../..');

const externalRegistry = config.getObject<ExternalRegistry>('registry');
if (externalRegistry !== undefined && (!externalRegistry.push || !externalRegistry.pull)) {
  throw new Error('registry must set both push and pull');
}
const registryForwardPort =
  config.getNumber('registryForwardPort', { min: 1024, max: 65535 }) ?? 25180;

/**
 * The tenant host must provide wasi:tls, which the stock wash image does not. Unless the
 * stack names a pullable image, the local build is published to the in-cluster registry
 * and pulled by the node from 127.0.0.1:<registryNodePort>; see the platform repo's
 * platform/tenant-host/README.md for building it.
 */
const configuredHostImage = config.get('tenantHostImage');
const publishHostImage = configuredHostImage === undefined;
if (publishHostImage && externalRegistry !== undefined) {
  throw new Error('with an external registry, set tenantHostImage to an image the nodes can pull');
}
const localHostImage =
  config.get('tenantHostLocalImage') ?? 'localhost/di-framework/wash:2.8.0-wasi-tls';
const registryNodePort = config.getNumber('registryNodePort', { min: 30000, max: 32767 }) ?? 30500;
/** `localhost/di-framework/wash:tag` without its registry host: `di-framework/wash:tag`. */
const hostRepository = localHostImage.replace(/^(localhost|[^/]*[.:][^/]*)\//, '');
const tenantHostImage = configuredHostImage ?? `127.0.0.1:${registryNodePort}/${hostRepository}`;

const instanceName = config.get('kubeInstance') ?? 'identity';
/** Known up front so previews of kube updates don't mark the registry's namespace unknown. */
const platformNamespace = config.get('platformNamespace') ?? 'wasmcloud';
const kubeBinary = config.get('kubeBinary');
const configuredSmtpHost = config.get('smtpHost');
/**
 * Mailpit's fixed ClusterIP, inside Kubesolo's 10.43.0.0/16 Service range. kube lists it in
 * the platform's egress class before Mailpit exists, which a pinned address allows.
 */
const mailpitClusterIP = configuredSmtpHost
  ? undefined
  : (config.get('mailpitClusterIP') ?? '10.43.250.25');
const kubeVersion = config.get('kubeVersion') ?? 'latest';

const kube = new KubeInstance('kube', {
  name: instanceName,
  version: kubeBinary ? undefined : kubeVersion === 'latest' ? latestKubeRelease() : kubeVersion,
  binary: kubeBinary,
  stateDir: config.get('kubeStateDir'),
  existingKubeconfig: config.get('kubeconfig'),
  existingContext: config.get('context'),
  httpPort: config.getNumber('httpPort', { min: 1024, max: 65535 }) ?? 28180,
  platformPackage: config.get('platformPackage') ?? '@di-framework/platform@6.0.5',
  platformConfig: {
    ...JSON.parse(readFileSync(join(__dirname, 'platform.json'), 'utf8')),
    tenantHostImage,
    // A published tag is mutable: pull on every host start so a rebuild takes effect.
    tenantHostImagePullPolicy: publishHostImage ? 'Always' : 'IfNotPresent',
    ...(mailpitClusterIP
      ? { egressAllowedDestinations: [mailpitDestination(mailpitClusterIP)] }
      : {}),
  },
  values: config.getObject<unknown[]>('values'),
  allowInsecureRegistries: externalRegistry === undefined,
  purgeOnDelete: config.getBoolean('purgeClusterOnDestroy') ?? false,
});

/** kube's selected context, else the kubeconfig's current context. */
const context = pulumi
  .all([kube.context, kube.kubeconfigContent])
  .apply(([selected, kubeconfig]) => {
    const current = (parse(kubeconfig) as { 'current-context'?: string } | null)?.[
      'current-context'
    ];
    const resolved = selected ?? current;
    if (!resolved) throw new Error('the kube instance kubeconfig selects no context');
    return resolved;
  });

const provider = new k8s.Provider('cluster', {
  kubeconfig: kube.kubeconfigContent,
  context,
  enableServerSideApply: true,
  // Same instance, same cluster: a new API port (Kubesolo picks one on each container
  // start) or rotated credentials update the provider instead of replacing everything.
  clusterIdentifier: `di-framework-kube/${instanceName}`,
});

const inCluster = externalRegistry
  ? undefined
  : new InClusterRegistry(
      'registry',
      {
        namespace: platformNamespace,
        storageClass: config.get('registryStorageClass'),
        nodePort: publishHostImage ? registryNodePort : undefined,
      },
      { providers: { kubernetes: provider } },
    );

const registryPush = externalRegistry?.push ?? `http://127.0.0.1:${registryForwardPort}`;
const registryPull: pulumi.Input<string> =
  externalRegistry?.pull ?? (inCluster as InClusterRegistry).pull;

const registryForward = inCluster && {
  kubeconfig: kube.kubeconfig,
  context,
  namespace: inCluster.namespace,
  service: inCluster.service,
  localPort: registryForwardPort,
  remotePort: 5000,
};

let hostImage: PublishedImage | undefined;
if (publishHostImage && inCluster && registryForward) {
  const engine = containerEngine(config.get('containerEngine'));
  hostImage = new PublishedImage(
    'tenant-host-image',
    {
      localImage: localHostImage,
      engine,
      imageId: localImageId(
        engine,
        localHostImage,
        'Build it from the platform repo: podman build -t localhost/di-framework/wash:2.8.0-wasi-tls platform/tenant-host, or set tenantHostImage.',
      ),
      repository: hostRepository,
      registryForward,
    },
    { dependsOn: [inCluster] },
  );
}

/**
 * Rolls the tenant host (a Deployment the platform controller owns) onto the published image
 * whenever its digest changes, through a server-side-apply patch of two fields the controller
 * leaves alone. Tenant host pods run under a ResourceQuota with no room for a second host, so
 * the default start-then-stop rolling update would never finish; this one stops first.
 */
const hostRollout =
  hostImage &&
  new k8s.apps.v1.DeploymentPatch(
    'tenant-host-rollout',
    {
      metadata: { name: `hostgroup-tenant-${TENANT}`, namespace: `di-runtime-${TENANT}` },
      spec: {
        strategy: { type: 'RollingUpdate', rollingUpdate: { maxSurge: 0, maxUnavailable: 1 } },
        template: {
          metadata: { annotations: { 'identity.di-framework.dev/host-image': hostImage.digest } },
        },
      },
    },
    { provider, dependsOn: [hostImage] },
  );

const databaseDeletionPolicy = config.get('databaseDeletionPolicy') ?? 'Retain';
if (databaseDeletionPolicy !== 'Retain' && databaseDeletionPolicy !== 'Delete') {
  throw new Error('databaseDeletionPolicy must be Retain or Delete');
}

const database = new k8s.apiextensions.CustomResource(
  DATABASE,
  {
    apiVersion: 'platform.di-framework.dev/v1alpha1',
    kind: 'BackingService',
    metadata: {
      name: DATABASE,
      namespace: `di-tenant-${TENANT}`,
      annotations: {
        // Wait for the platform controller to provision Postgres before deploying.
        'pulumi.com/waitFor': 'condition=Ready',
        'pulumi.com/timeoutSeconds': '600',
      },
    },
    spec: {
      type: 'postgres',
      className: 'postgres-dedicated',
      deletionPolicy: databaseDeletionPolicy,
    },
  },
  { provider },
);

const localCli = join(workspaceRoot, 'node_modules', '.bin', 'di-framework');

const identity = new CliWorkload(
  APPLICATION,
  {
    application: APPLICATION,
    target: TARGET,
    workspaceRoot,
    cli: existsSync(localCli) ? localCli : 'di-framework',
    // The variables di-framework.deploy.toml interpolates for target `identity`.
    environment: {
      IDENTITY_KUBECONFIG: kube.kubeconfig,
      IDENTITY_KUBE_CONTEXT: context,
      IDENTITY_REGISTRY_PUSH: registryPush,
      IDENTITY_REGISTRY_PULL: registryPull,
    },
    registryForward,
    // Everything the guest component bundles: the guest, the API, the server, core,
    // the client assets, and the dependency and deploy manifests.
    sourceDigest: sourceDigest(workspaceRoot, [
      'apps',
      'packages',
      'package.json',
      'bun.lock',
      'tsconfig.json',
      'di-framework.deploy.toml',
    ]),
  },
  {
    dependsOn: [database, ...(inCluster ? [inCluster] : []), ...(hostRollout ? [hostRollout] : [])],
  },
);

/** Tenant route through the platform HTTP gateway, when the instance publishes one. */
const url = kube.endpoints.apply((endpoints) => {
  if (!endpoints.http) return null;
  const gateway = new URL(endpoints.http);
  gateway.hostname = `${APPLICATION}.${TENANT}.localhost`;
  return gateway.origin;
});

const generated = (name: string, length: number) =>
  new random.RandomPassword(name, { length, special: false }).result;
const ownerPassword = generated('bootstrap-owner-password', 32);
const viewerPassword = generated('bootstrap-viewer-password', 32);
const clientSecrets = {
  access: generated('access-client-secret', 48),
  directory: generated('directory-client-secret', 48),
  provisioner: generated('provisioner-client-secret', 48),
};

/** RS256 signing key as the private JWK the guest expects, `kid` = RFC 7638 thumbprint. */
const signingKey = new tls.PrivateKey('signing-key', { algorithm: 'RSA', rsaBits: 2048 });
const activePrivateJwk = signingKey.privateKeyPem.apply((pem) => {
  const jwk = createPrivateKey(pem).export({ format: 'jwk' }) as Record<string, string>;
  const kid = createHash('sha256')
    .update(JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n }))
    .digest('base64url');
  return JSON.stringify({ ...jwk, kid, alg: 'RS256', use: 'sig' });
});
export const signingKeyId = pulumi.unsecret(
  activePrivateJwk.apply((jwk) => (JSON.parse(jwk) as { kid: string }).kid),
);

const publicOrigin = pulumi.output(config.get('publicOrigin') ?? url).apply((origin) => {
  if (!origin) throw new Error('set publicOrigin; this kube instance publishes no gateway URL');
  return origin;
});
const mailpit = mailpitClusterIP
  ? new Mailpit(
      'mailpit',
      { tenant: TENANT, workload: APPLICATION, clusterIP: mailpitClusterIP },
      { providers: { kubernetes: provider } },
    )
  : undefined;
const smtpHost: pulumi.Output<string> = mailpit
  ? mailpit.host
  : pulumi.output(configuredSmtpHost as string);

const runtimeValues = pulumi
  .all([
    publicOrigin,
    activePrivateJwk,
    ownerPassword,
    viewerPassword,
    clientSecrets.access,
    clientSecrets.directory,
    clientSecrets.provisioner,
    generated('smtp-password', 32),
    smtpHost,
  ])
  .apply(([origin, jwk, owner, viewer, access, directory, provisioner, smtpPassword, smtp]) => ({
    ISSUER_URL: config.get('issuerUrl') ?? origin,
    AUTH_PUBLIC_ORIGIN: origin,
    AUTH_ACTIVE_PRIVATE_JWK: jwk,
    AUTH_ACCESS_REDIRECT_URIS: config.get('accessRedirectUris') ?? 'http://localhost:3000/callback',
    AUTH_BOOTSTRAP_OWNER_PASSWORD: owner,
    AUTH_BOOTSTRAP_VIEWER_PASSWORD: viewer,
    AUTH_ACCESS_CLIENT_SECRET: access,
    AUTH_DIRECTORY_CLIENT_SECRET: directory,
    AUTH_PROVISIONER_CLIENT_SECRET: provisioner,
    SMTP_PASSWORD: smtpPassword,
    SMTP_HOST: smtp,
  }));

const runtimeSecrets = new RuntimeSecrets(
  'runtime-secrets',
  {
    kubeconfig: kube.kubeconfig,
    context,
    runtimeNamespace: `di-runtime-${TENANT}`,
    service: DATABASE,
    workloadHost: APPLICATION,
    localPort: config.getNumber('workloadForwardPort', { min: 1024, max: 65535 }) ?? 25181,
    values: runtimeValues,
  },
  { dependsOn: [identity] },
);

/**
 * A running guest keeps the settings it booted with, so a changed value rolls the tenant host
 * and the guest boots again. The annotation is a digest, never the values.
 */
new k8s.apps.v1.DeploymentPatch(
  'tenant-host-secrets',
  {
    metadata: { name: `hostgroup-tenant-${TENANT}`, namespace: `di-runtime-${TENANT}` },
    spec: {
      template: {
        metadata: {
          annotations: {
            'identity.di-framework.dev/runtime-secrets': pulumi.unsecret(
              runtimeValues.apply((values) =>
                createHash('sha256').update(JSON.stringify(values)).digest('hex'),
              ),
            ),
          },
        },
      },
    },
  },
  { provider, dependsOn: [runtimeSecrets] },
);

export const kubeconfig = kube.kubeconfig;
export { context };
export const namespace = kube.namespace.apply((actual) => {
  if (actual !== platformNamespace) {
    throw new Error(`kube installed the platform in ${actual}; set platformNamespace to match`);
  }
  return actual;
});
export const registry = { push: registryPush, pull: registryPull };
export const image = identity.image;
export { url };
export const bootstrapOwnerPassword = ownerPassword;
export const bootstrapViewerPassword = viewerPassword;
export const accessClientSecret = clientSecrets.access;
export const directoryClientSecret = clientSecrets.directory;
export const provisionerClientSecret = clientSecrets.provisioner;
export { smtpHost, tenantHostImage };
