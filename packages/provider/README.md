# `@di-framework/identity-provider`

A TypeScript port of the auth server's `gas` Pulumi provider. It manages organizations, users,
memberships, and OAuth clients, and reads audit records, through this server's protected
`/api/admin` API. It never handles an end-user password.

```ts
import { Membership, OAuthClient, Organization, User } from '@di-framework/identity-provider';

const org = new Organization('acme', { slug: 'acme', name: 'Acme' });
const ada = new User('ada', { login: 'ada', email: 'ada@example.com', displayName: 'Ada' });
new Membership('ada-acme', { organizationSlug: org.slug, userId: ada.userId, role: 'owner' });
new OAuthClient('portal', { clientId: 'portal', organizationSlug: 'acme', scopes: ['openid'] });
```

Configuration:

```sh
pulumi config set gas:issuer https://auth.example
pulumi config set gas:provisionerClientId provisioner
pulumi config set --secret gas:provisionerClientSecret ...
pulumi config set gas:apiUrl http://identity:4180   # optional; defaults to the issuer
```

Behavior matches `pulumi-provider-gas`:

- Every request runs OIDC discovery against the issuer, checks that the advertised issuer matches,
  and obtains a `client_credentials` token with `admin:read admin:write directory:read`.
- Every mutation sends `Idempotency-Key` set to the resource URN, so retries and re-runs do not
  duplicate resources.
- GET requests and requests with an `Idempotency-Key` retry three times on transport errors and
  408, 429, 500, 502, 503, and 504.
- Deleting a user archives it; deleting a client revokes it; delete treats 404 and 410 as done.
- Client secrets are write-only on the server: an imported client has no `clientSecret` until
  `secretRotationVersion` changes.

Dynamic providers run in Pulumi's Node language host. The resource logic in `src/resources.ts`
is tested under `bun test` against the in-process server; `src/pulumi.ts` needs the Pulumi
engine and is not loaded by the tests.
