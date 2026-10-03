import * as k8s from '@pulumi/kubernetes';
import * as pulumi from '@pulumi/pulumi';

export const REGISTRY_NAME = 'di-framework-registry';
const REGISTRY_IMAGE = 'registry:3.1.1';
const REGISTRY_PORT = 5000;

export interface InClusterRegistryArgs {
  namespace: pulumi.Input<string>;
  storageClass?: string;
  size?: string;
  /**
   * Also expose the registry on this NodePort. On a single-node cluster the node's
   * containerd can pull `127.0.0.1:<nodePort>/...` over plain HTTP (it allows HTTP only
   * for loopback registries), which is how node-level images such as the tenant host
   * image are served from this registry.
   */
  nodePort?: number;
}

/**
 * Plain-HTTP OCI registry in the platform namespace. wasmCloud hosts pull components from
 * its Service DNS name; the node pulls container images through the optional NodePort.
 * It has no ingress, so pushes go through a loopback port-forward.
 */
export class InClusterRegistry extends pulumi.ComponentResource {
  /** Pull reference for wasmCloud hosts: `<service>.<namespace>.svc.cluster.local:5000`. */
  readonly pull: pulumi.Output<string>;
  readonly service: pulumi.Output<string>;
  readonly namespace: pulumi.Output<string>;
  /** Node-local reference prefix, `127.0.0.1:<nodePort>`, when a NodePort is set. */
  readonly nodeHost?: string;

  constructor(name: string, args: InClusterRegistryArgs, opts?: pulumi.ComponentResourceOptions) {
    super('identity:platform:InClusterRegistry', name, {}, opts);
    const labels = { app: REGISTRY_NAME, 'app.kubernetes.io/part-of': 'identity-server' };
    const metadata = { name: REGISTRY_NAME, namespace: args.namespace, labels };

    const claim = new k8s.core.v1.PersistentVolumeClaim(
      `${name}-data`,
      {
        // Local-path style classes bind only once the pod is scheduled; the Deployment
        // rollout below is the readiness signal instead.
        metadata: { ...metadata, annotations: { 'pulumi.com/skipAwait': 'true' } },
        spec: {
          accessModes: ['ReadWriteOnce'],
          resources: { requests: { storage: args.size ?? '2Gi' } },
          ...(args.storageClass ? { storageClassName: args.storageClass } : {}),
        },
      },
      { parent: this },
    );

    new k8s.apps.v1.Deployment(
      name,
      {
        metadata,
        spec: {
          replicas: 1,
          strategy: { type: 'Recreate' },
          selector: { matchLabels: { app: REGISTRY_NAME } },
          template: {
            metadata: { labels },
            spec: {
              containers: [
                {
                  name: 'registry',
                  image: REGISTRY_IMAGE,
                  ports: [{ containerPort: REGISTRY_PORT }],
                  resources: {
                    requests: { cpu: '50m', memory: '64Mi' },
                    limits: { memory: '256Mi' },
                  },
                  readinessProbe: { httpGet: { path: '/v2/', port: REGISTRY_PORT } },
                  volumeMounts: [{ name: 'data', mountPath: '/var/lib/registry' }],
                },
              ],
              volumes: [
                { name: 'data', persistentVolumeClaim: { claimName: claim.metadata.name } },
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
          selector: { app: REGISTRY_NAME },
          ports: [{ name: 'registry', port: REGISTRY_PORT, targetPort: REGISTRY_PORT }],
        },
      },
      { parent: this },
    );

    if (args.nodePort !== undefined) {
      new k8s.core.v1.Service(
        `${name}-node`,
        {
          metadata: { ...metadata, name: `${REGISTRY_NAME}-node` },
          spec: {
            type: 'NodePort',
            selector: { app: REGISTRY_NAME },
            ports: [
              {
                name: 'registry',
                port: REGISTRY_PORT,
                targetPort: REGISTRY_PORT,
                nodePort: args.nodePort,
              },
            ],
          },
        },
        { parent: this },
      );
      this.nodeHost = `127.0.0.1:${args.nodePort}`;
    }

    this.service = service.metadata.name;
    this.namespace = service.metadata.namespace;
    this.pull = pulumi.interpolate`${service.metadata.name}.${service.metadata.namespace}.svc.cluster.local:${REGISTRY_PORT}`;
    this.registerOutputs({ pull: this.pull, service: this.service, namespace: this.namespace });
  }
}
