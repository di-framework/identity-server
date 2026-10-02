import * as pulumi from '@pulumi/pulumi';
import { type AuditItem, gasProviders } from './resources.ts';
import type { Connection } from './types.ts';

/**
 * `gas` resources for Pulumi programs (Node language host). The only module that imports
 * `@pulumi/pulumi`; tests exercise `resources.ts` directly.
 *
 * Configuration (`pulumi config set gas:...`): `issuer`, optional `apiUrl`,
 * `provisionerClientId`, and secret `provisionerClientSecret`.
 */
const providers = gasProviders();
const MODULE = 'gas';

function connection(): pulumi.Output<Connection> {
  const config = new pulumi.Config(MODULE);
  return pulumi.secret(
    pulumi
      .all([
        config.require('issuer'),
        config.get('apiUrl') ?? '',
        config.require('provisionerClientId'),
        config.requireSecret('provisionerClientSecret'),
      ])
      .apply(([issuer, apiUrl, provisionerClientId, provisionerClientSecret]) => ({
        issuer,
        apiUrl: apiUrl || undefined,
        provisionerClientId,
        provisionerClientSecret,
      })),
  );
}

type Args<T> = { [K in keyof T]: pulumi.Input<T[K]> };

/**
 * A dynamic resource whose inputs include the connection and its own URN, which the provider
 * sends as the `Idempotency-Key`, as the Go provider does with the engine-supplied URN.
 */
function resource<Outputs>(type: string, provider: object) {
  return class extends pulumi.dynamic.Resource {
    constructor(
      name: string,
      args: Record<string, unknown>,
      opts: pulumi.CustomResourceOptions = {},
    ) {
      const urn = pulumi.createUrn(name, `pulumi-nodejs:dynamic/${MODULE}:${type}`, opts.parent);
      super(
        provider as pulumi.dynamic.ResourceProvider,
        name,
        { ...args, connection: connection(), urn },
        {
          ...opts,
          additionalSecretOutputs: [
            ...(opts.additionalSecretOutputs ?? []),
            'connection',
            'clientSecret',
          ],
        },
        MODULE,
        type,
      );
    }
  } as unknown as new (
    name: string,
    args: Args<Record<string, unknown>>,
    opts?: pulumi.CustomResourceOptions,
  ) => pulumi.dynamic.Resource & { [K in keyof Outputs]: pulumi.Output<Outputs[K]> };
}

export const Organization = resource<{ slug: string; name: string; organizationId: string }>(
  'Organization',
  providers.organization,
);
export const User = resource<{
  login: string;
  email: string;
  displayName: string;
  userId: string;
  status: string;
}>('User', providers.user);
export const Membership = resource<{ organizationSlug: string; userId: string; role: string }>(
  'Membership',
  providers.membership,
);
export const OAuthClient = resource<{
  clientId: string;
  organizationSlug: string;
  redirectUris: string[];
  scopes: string[];
  browser: boolean;
  secretRotationVersion: string;
  clientSecret: string;
}>('OAuthClient', providers.oauthClient);
export const Bootstrap = resource<Record<string, string>>('Bootstrap', providers.bootstrap);

/** `gas:index:audit`. */
export function audit(): pulumi.Output<{ items: AuditItem[] }> {
  return connection().apply((value) => providers.audit(value));
}
