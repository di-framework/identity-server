import * as k8s from '@pulumi/kubernetes';
import * as pulumi from '@pulumi/pulumi';

export const MAILPIT_NAME = 'mailpit';
const MAILPIT_IMAGE = 'docker.io/axllent/mailpit:v1.21';
const SMTP_PORT = 1025;
const UI_PORT = 8025;

const PLATFORM_API = 'platform.di-framework.dev/v1alpha1';
/** The platform's default egress class; admission refuses tenant classes it did not seed. */
const EGRESS_CLASS = 'egress-public';

export interface MailpitArgs {
  /** Platform tenant; Mailpit runs in its workload namespace, `di-tenant-<tenant>`. */
  tenant: string;
  /** WorkloadDeployment granted SMTP egress to Mailpit. */
  workload: string;
  /** Fixed ClusterIP, so the platform's egress class can list it before Mailpit exists. */
  clusterIP: string;
}

/** The `egressAllowedDestinations` entry the platform must approve for Mailpit. */
export function mailpitDestination(clusterIP: string): string {
  return `${clusterIP}:${SMTP_PORT}`;
}

/**
 * Mailpit as the tenant's SMTP relay, the in-cluster counterpart of the `compose.yml`
 * service. It accepts any credentials over plain SMTP on 1025 and keeps mail in memory.
 * The web UI on 8025 is reached with `kubectl port-forward`.
 *
 * Tenant hosts run wash with `--socket-egress=enforce`, so the guest may resolve and dial
 * only what a platform egress grant approves. A name grant reaches only public addresses,
 * and a TCP connect matches only a literal `ip:port`, so the grant names the Service's
 * fixed ClusterIP, which `host` is as well. The platform's `egress-public` class must list
 * `mailpitDestination(clusterIP)` (kube's `egressAllowedDestinations`). This component adds
 * the tenant's egress BackingService and a ServiceBinding to the workload; the platform
 * controller then patches `allowedHosts` and `allowedIpNameLookups` onto the
 * WorkloadDeployment.
 */
export class Mailpit extends pulumi.ComponentResource {
  /** SMTP host for the guest: the Service's ClusterIP, which the egress grant approves. */
  readonly host: pulumi.Output<string>;
  readonly service: pulumi.Output<string>;
  readonly namespace: pulumi.Output<string>;

  constructor(name: string, args: MailpitArgs, opts?: pulumi.ComponentResourceOptions) {
    super('identity:platform:Mailpit', name, {}, opts);
    const namespace = `di-tenant-${args.tenant}`;
    const labels = { app: MAILPIT_NAME, 'app.kubernetes.io/part-of': 'identity-server' };
    const metadata = { name: MAILPIT_NAME, namespace, labels };

    new k8s.apps.v1.Deployment(
      name,
      {
        metadata,
        spec: {
          replicas: 1,
          selector: { matchLabels: { app: MAILPIT_NAME } },
          template: {
            metadata: { labels },
            spec: {
              containers: [
                {
                  name: 'mailpit',
                  image: MAILPIT_IMAGE,
                  env: [
                    { name: 'MP_SMTP_AUTH_ACCEPT_ANY', value: '1' },
                    { name: 'MP_SMTP_AUTH_ALLOW_INSECURE', value: '1' },
                  ],
                  ports: [
                    { name: 'smtp', containerPort: SMTP_PORT },
                    { name: 'http', containerPort: UI_PORT },
                  ],
                  resources: {
                    requests: { cpu: '10m', memory: '32Mi' },
                    limits: { memory: '128Mi' },
                  },
                  readinessProbe: { httpGet: { path: '/livez', port: UI_PORT } },
                },
              ],
            },
          },
        },
      },
      { parent: this },
    );

    const service = new k8s.core.v1.Service(
      name,
      {
        metadata,
        spec: {
          clusterIP: args.clusterIP,
          selector: { app: MAILPIT_NAME },
          ports: [
            { name: 'smtp', port: SMTP_PORT, targetPort: SMTP_PORT },
            { name: 'http', port: UI_PORT, targetPort: UI_PORT },
          ],
        },
      },
      // A Service's ClusterIP is immutable, and the address is taken until the old one goes.
      { parent: this, replaceOnChanges: ['spec.clusterIP'], deleteBeforeReplace: true },
    );

    const destination = mailpitDestination(args.clusterIP);
    const egressName = `${args.tenant}-${MAILPIT_NAME}`;
    const egress = new k8s.apiextensions.CustomResource(
      `${name}-egress`,
      {
        apiVersion: PLATFORM_API,
        kind: 'BackingService',
        metadata: {
          name: egressName,
          namespace,
          labels,
          annotations: { 'pulumi.com/waitFor': 'condition=Ready' },
        },
        spec: { type: 'egress', className: EGRESS_CLASS, destinations: [destination] },
      },
      { parent: this, dependsOn: [service] },
    );
    new k8s.apiextensions.CustomResource(
      `${name}-egress-binding`,
      {
        apiVersion: PLATFORM_API,
        kind: 'ServiceBinding',
        metadata: { name: egressName, namespace, labels },
        spec: {
          bindingName: egressName,
          capability: 'egress',
          serviceName: egressName,
          workloadName: args.workload,
        },
      },
      { parent: this, dependsOn: [egress] },
    );

    this.service = service.metadata.name;
    this.namespace = service.metadata.namespace;
    this.host = service.spec.clusterIP;
    this.registerOutputs({ host: this.host, service: this.service, namespace: this.namespace });
  }
}
