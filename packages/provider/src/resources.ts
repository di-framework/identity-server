import {
  type AdminApi,
  adminClient,
  deleted,
  type HttpFetch,
  ProviderError,
  type RetryOptions,
  unexpectedStatus,
} from './client.ts';
import type { Connection, DiffResult, ResourceInputs, ResourceProvider } from './types.ts';

export interface OrganizationInputs extends ResourceInputs {
  slug: string;
  name: string;
}
export interface OrganizationOutputs extends OrganizationInputs {
  organizationId: string;
}

export interface UserInputs extends ResourceInputs {
  login: string;
  email: string;
  displayName: string;
}
export interface UserOutputs extends UserInputs {
  userId: string;
  status: string;
}

export interface MembershipInputs extends ResourceInputs {
  organizationSlug: string;
  userId: string;
  role: string;
}
export type MembershipOutputs = MembershipInputs;

export interface OAuthClientInputs extends ResourceInputs {
  clientId: string;
  organizationSlug?: string;
  redirectUris?: string[];
  scopes?: string[];
  browser?: boolean;
  /** Changing this value rotates the client secret. */
  secretRotationVersion?: string;
}
export interface OAuthClientOutputs extends OAuthClientInputs {
  /** Write-only on the server: an imported client has none until it is rotated. */
  clientSecret?: string;
}

export interface BootstrapInputs extends ResourceInputs {
  name: string;
  activePrivateJwk: string;
  previousPublicJwkSet?: string;
  databasePassword: string;
  smtpUsername: string;
  smtpPassword: string;
  bootstrapOwnerEmail: string;
  bootstrapOwnerLogin: string;
  bootstrapOwnerPassword: string;
  bootstrapOrganizationSlug: string;
  bootstrapOrganizationName: string;
  accessClientId: string;
  accessClientSecret: string;
  directoryClientId: string;
  directoryClientSecret: string;
  provisionerClientId: string;
  provisionerClientSecret: string;
}
export type BootstrapOutputs = BootstrapInputs;

export interface AuditItem {
  id: string;
  action: string;
  actor_client_id: string | null;
  target: string | null;
  correlation_id: string | null;
  before_metadata: string;
  after_metadata: string;
  created_at: string;
}

/** `mutationKey`: the resource URN, required for every mutation. */
function key(inputs: ResourceInputs): string {
  if (!inputs.urn) throw new ProviderError('Pulumi resource URN is required for mutations');
  return inputs.urn;
}

function diff(changes: Array<[changed: boolean, property: string, replace: boolean]>): DiffResult {
  const changed = changes.filter(([value]) => value);
  return {
    changes: changed.length > 0,
    replaces: changed.filter(([, , replace]) => replace).map(([, property]) => property),
  };
}

function sameSet(left: string[] = [], right: string[] = []): boolean {
  const a = [...left].sort();
  const b = [...right].sort();
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/**
 * `gas` resources as `pulumi.dynamic` providers. Each talks only to `/api/admin` through
 * `adminClient`; none handles an end-user password.
 */
export function gasProviders(transport?: HttpFetch, retry?: RetryOptions) {
  const api = (connection: Connection): AdminApi => adminClient(connection, transport, retry);

  const organization: ResourceProvider<OrganizationInputs, OrganizationOutputs> = {
    async diff(_id, olds, news) {
      return diff([
        [olds.slug !== news.slug, 'slug', true],
        [olds.name !== news.name, 'name', false],
      ]);
    },
    async create(inputs) {
      const { response, data } = await api(inputs.connection).POST('/api/admin/organizations', {
        params: { header: { 'Idempotency-Key': key(inputs) } },
        body: { slug: inputs.slug, name: inputs.name },
      });
      if (response.status !== 201) throw unexpectedStatus('create organization', response);
      if (!data?.id)
        throw new ProviderError('create organization: response omitted organization ID');
      return { id: inputs.slug, outs: { ...inputs, organizationId: data.id } };
    },
    async read(id, props) {
      const { response, data } = await api(props.connection).GET(
        '/api/admin/organizations/{slug}',
        {
          params: { path: { slug: props.slug || id } },
        },
      );
      if (response.status === 404) return {};
      if (response.status !== 200 || !data) throw unexpectedStatus('read organization', response);
      return {
        id: data.slug ?? id,
        props: {
          ...props,
          slug: data.slug ?? '',
          name: data.name ?? '',
          organizationId: data.id ?? '',
        },
      };
    },
    async update(id, olds, news) {
      const { response, data } = await api(news.connection).PATCH(
        '/api/admin/organizations/{slug}',
        {
          params: { path: { slug: id }, header: { 'Idempotency-Key': key(news) } },
          body: { name: news.name },
        },
      );
      if (response.status !== 200 || !data) {
        throw unexpectedStatus('update organization display name', response);
      }
      return { outs: { ...news, organizationId: data.id ?? olds.organizationId } };
    },
    async delete(_id, props) {
      const { response } = await api(props.connection).DELETE('/api/admin/organizations/{slug}', {
        params: { path: { slug: props.slug }, header: { 'Idempotency-Key': key(props) } },
      });
      if (!deleted(response)) throw unexpectedStatus('delete organization', response);
    },
  };

  const user: ResourceProvider<UserInputs, UserOutputs> = {
    async diff(_id, olds, news) {
      return diff([
        [olds.login !== news.login, 'login', true],
        [olds.email !== news.email, 'email', true],
        [olds.displayName !== news.displayName, 'displayName', false],
      ]);
    },
    async create(inputs) {
      const { response, data } = await api(inputs.connection).POST('/api/admin/users', {
        params: { header: { 'Idempotency-Key': key(inputs) } },
        body: { login: inputs.login, email: inputs.email, displayName: inputs.displayName },
      });
      if (response.status !== 201) throw unexpectedStatus('create user', response);
      if (!data?.id) throw new ProviderError('create user: response omitted user ID');
      return {
        id: data.id,
        outs: { ...inputs, userId: data.id, status: data.status ?? 'pending' },
      };
    },
    async read(id, props) {
      const { response, data } = await api(props.connection).GET('/api/admin/users/{userId}', {
        params: { path: { userId: id } },
      });
      if (response.status === 404) return {};
      if (response.status !== 200 || !data) throw unexpectedStatus('read user', response);
      if (data.status === 'archived') return {};
      return {
        id: data.id ?? id,
        props: {
          ...props,
          login: data.login ?? '',
          email: data.email ?? '',
          displayName: data.display_name ?? '',
          userId: data.id ?? id,
          status: data.status ?? '',
        },
      };
    },
    async update(id, olds, news) {
      const { response, data } = await api(news.connection).PATCH('/api/admin/users/{userId}', {
        params: { path: { userId: id }, header: { 'Idempotency-Key': key(news) } },
        body: { displayName: news.displayName },
      });
      if (response.status !== 200 || !data)
        throw unexpectedStatus('update user display name', response);
      return {
        outs: { ...news, userId: data.id ?? olds.userId, status: data.status ?? olds.status },
      };
    },
    async delete(id, props) {
      const { response } = await api(props.connection).DELETE('/api/admin/users/{userId}', {
        params: { path: { userId: id }, header: { 'Idempotency-Key': key(props) } },
      });
      if (!deleted(response)) throw unexpectedStatus('archive user', response);
    },
  };

  const putMembership = async (inputs: MembershipInputs, action: string) => {
    const { response } = await api(inputs.connection).PUT(
      '/api/admin/organizations/{slug}/members/{userId}',
      {
        params: {
          path: { slug: inputs.organizationSlug, userId: inputs.userId },
          header: { 'Idempotency-Key': key(inputs) },
        },
        body: { userId: inputs.userId, role: inputs.role },
      },
    );
    if (response.status !== 204) throw unexpectedStatus(action, response);
  };

  const membership: ResourceProvider<MembershipInputs, MembershipOutputs> = {
    async diff(_id, olds, news) {
      return diff([
        [olds.organizationSlug !== news.organizationSlug, 'organizationSlug', true],
        [olds.userId !== news.userId, 'userId', true],
        [olds.role !== news.role, 'role', false],
      ]);
    },
    async create(inputs) {
      await putMembership(inputs, 'create membership');
      return { id: `${inputs.organizationSlug}:${inputs.userId}`, outs: inputs };
    },
    async read(id, props) {
      const separator = id.indexOf(':');
      const slug = props.organizationSlug || id.slice(0, Math.max(separator, 0));
      const userId = props.userId || id.slice(separator + 1);
      if (!slug || !userId || (separator < 0 && !props.organizationSlug)) {
        throw new ProviderError('import membership: ID must be <organization-slug>:<user-id>');
      }
      const { response, data } = await api(props.connection).GET(
        '/api/admin/organizations/{slug}/members/{userId}',
        {
          params: { path: { slug, userId } },
        },
      );
      if (response.status === 404) return {};
      if (response.status !== 200 || !data) throw unexpectedStatus('read membership', response);
      const organizationSlug = data.organization_slug ?? slug;
      const memberId = data.user_id ?? userId;
      return {
        id: `${organizationSlug}:${memberId}`,
        props: { ...props, organizationSlug, userId: memberId, role: data.role ?? '' },
      };
    },
    async update(_id, _olds, news) {
      await putMembership(news, 'update membership role');
      return { outs: news };
    },
    async delete(_id, props) {
      const { response } = await api(props.connection).DELETE(
        '/api/admin/organizations/{slug}/members/{userId}',
        {
          params: {
            path: { slug: props.organizationSlug, userId: props.userId },
            header: { 'Idempotency-Key': key(props) },
          },
        },
      );
      if (!deleted(response)) throw unexpectedStatus('delete membership', response);
    },
  };

  const oauthClient: ResourceProvider<OAuthClientInputs, OAuthClientOutputs> = {
    async diff(_id, olds, news) {
      return diff([
        [olds.clientId !== news.clientId, 'clientId', true],
        [
          (olds.organizationSlug ?? '') !== (news.organizationSlug ?? ''),
          'organizationSlug',
          false,
        ],
        [!sameSet(olds.redirectUris, news.redirectUris), 'redirectUris', false],
        [!sameSet(olds.scopes, news.scopes), 'scopes', false],
        [Boolean(olds.browser) !== Boolean(news.browser), 'browser', false],
        [
          (olds.secretRotationVersion ?? '') !== (news.secretRotationVersion ?? ''),
          'secretRotationVersion',
          false,
        ],
      ]);
    },
    async create(inputs) {
      const { response, data } = await api(inputs.connection).POST('/api/admin/oauth-clients', {
        params: { header: { 'Idempotency-Key': key(inputs) } },
        body: {
          clientId: inputs.clientId,
          ...(inputs.organizationSlug ? { organizationSlug: inputs.organizationSlug } : {}),
          redirectUris: inputs.redirectUris ?? [],
          scopes: inputs.scopes ?? [],
          browser: inputs.browser ?? false,
        },
      });
      if (response.status !== 201) throw unexpectedStatus('create OAuth client', response);
      if (!data?.client_id || !data.client_secret) {
        throw new ProviderError('create OAuth client: response omitted client ID or secret');
      }
      return { id: data.client_id, outs: { ...inputs, clientSecret: data.client_secret } };
    },
    async read(id, props) {
      const { response, data } = await api(props.connection).GET(
        '/api/admin/oauth-clients/{clientId}',
        {
          params: { path: { clientId: id } },
        },
      );
      if (response.status === 404) return {};
      if (response.status !== 200 || !data) throw unexpectedStatus('read OAuth client', response);
      if (data.revoked_at) return {};
      return {
        id: data.client_id ?? id,
        props: {
          ...props,
          clientId: data.client_id ?? id,
          organizationSlug: data.organization_slug ?? '',
          redirectUris: data.redirect_uris ?? [],
          scopes: data.scopes ?? [],
          browser: data.browser ?? false,
        },
      };
    },
    async update(id, olds, news) {
      const outs: OAuthClientOutputs = { ...news, clientSecret: olds.clientSecret };
      const metadataChanged =
        (olds.organizationSlug ?? '') !== (news.organizationSlug ?? '') ||
        !sameSet(olds.redirectUris, news.redirectUris) ||
        !sameSet(olds.scopes, news.scopes) ||
        Boolean(olds.browser) !== Boolean(news.browser);
      const client = api(news.connection);
      if (metadataChanged) {
        const { response } = await client.PUT('/api/admin/oauth-clients/{clientId}', {
          params: { path: { clientId: id }, header: { 'Idempotency-Key': key(news) } },
          body: {
            ...(news.organizationSlug ? { organizationSlug: news.organizationSlug } : {}),
            redirectUris: news.redirectUris ?? [],
            scopes: news.scopes ?? [],
            browser: news.browser ?? false,
          },
        });
        if (response.status !== 200)
          throw unexpectedStatus('update OAuth client metadata', response);
      }
      if ((olds.secretRotationVersion ?? '') !== (news.secretRotationVersion ?? '')) {
        const { response, data } = await client.POST(
          '/api/admin/oauth-clients/{clientId}/rotate-secret',
          {
            params: { path: { clientId: id }, header: { 'Idempotency-Key': key(news) } },
            body: { version: news.secretRotationVersion ?? '' },
          },
        );
        if (response.status !== 200 || !data?.client_secret) {
          throw unexpectedStatus('rotate OAuth client secret', response);
        }
        outs.clientSecret = data.client_secret;
      }
      return { outs };
    },
    async delete(id, props) {
      const { response } = await api(props.connection).DELETE(
        '/api/admin/oauth-clients/{clientId}',
        {
          params: { path: { clientId: id }, header: { 'Idempotency-Key': key(props) } },
        },
      );
      if (!deleted(response)) throw unexpectedStatus('revoke OAuth client', response);
    },
  };

  /** Secret-only bridge from encrypted configuration to deployment inputs. No API call. */
  const bootstrap: ResourceProvider<BootstrapInputs, BootstrapOutputs> = {
    async diff(_id, olds, news) {
      const changed = Object.keys(news).filter(
        (field) =>
          JSON.stringify(olds[field as keyof BootstrapInputs]) !==
          JSON.stringify(news[field as keyof BootstrapInputs]),
      );
      return { changes: changed.length > 0, replaces: [] };
    },
    async create(inputs) {
      if (
        !inputs.activePrivateJwk ||
        !inputs.databasePassword ||
        !inputs.provisionerClientId ||
        !inputs.provisionerClientSecret
      ) {
        throw new ProviderError('required GSIO auth bootstrap secret is empty');
      }
      return { id: inputs.name, outs: inputs };
    },
    async read(id, props) {
      return { id, props };
    },
    async update(_id, _olds, news) {
      return { outs: news };
    },
    async delete() {},
  };

  /** `gas:index:audit`: the newest audit records, metadata as stored. */
  async function audit(connection: Connection): Promise<{ items: AuditItem[] }> {
    const { response, data } = await api(connection).GET('/api/admin/audit');
    if (response.status !== 200 || !data) {
      throw new ProviderError(`get audit: ${response.status} ${response.statusText}`.trim());
    }
    return {
      items: data.map((item) => ({
        id: item.id ?? '',
        action: item.action ?? '',
        actor_client_id: item.actor_client_id ?? null,
        target: item.target ?? null,
        correlation_id: item.correlation_id ?? null,
        before_metadata: item.before_metadata ?? '{}',
        after_metadata: item.after_metadata ?? '{}',
        created_at: item.created_at ?? '',
      })),
    };
  }

  return { organization, user, membership, oauthClient, bootstrap, audit };
}
