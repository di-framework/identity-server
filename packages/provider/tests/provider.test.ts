import { beforeAll, describe, expect, test } from 'bun:test';
import type { SqlDatabase } from '@di-framework/repo';
import { controlPlane } from '../../../apps/api/src/control-plane.ts';
import { registerClient } from '../../core/tests/support/clients.ts';
import { useTestDatabase } from '../../core/tests/support/database.ts';
import { adminClient, deleted, ProviderError, retrying, unexpectedStatus } from '../src/client.ts';
import { type BootstrapInputs, gasProviders } from '../src/resources.ts';
import type { Connection } from '../src/types.ts';

let database: SqlDatabase;
let connection: Connection;
const transport = (request: Request) => controlPlane.fetch(request);
const gas = gasProviders(transport);
const tag = () => crypto.randomUUID().slice(0, 8);

beforeAll(async () => {
  database = await useTestDatabase();
  const provisioner = await registerClient({
    scopes: ['admin:read', 'admin:write', 'directory:read'],
  });
  connection = {
    issuer: 'https://identity.test/',
    provisionerClientId: provisioner.clientId,
    provisionerClientSecret: provisioner.secret,
  };
});

async function audits(urn: string): Promise<string[]> {
  const rows = await database.query<{ action: string }>(
    `SELECT action FROM auth_audit_records WHERE correlation_id = ? ORDER BY created_at`,
    [urn],
  );
  return rows.map((row) => row.action);
}

describe('resources against the admin API', () => {
  test('organization lifecycle with URN idempotency', async () => {
    const slug = `gas-${tag()}`;
    const urn = `urn:pulumi:dev::proj::pulumi-nodejs:dynamic/gas:Organization::${slug}`;
    const inputs = { connection, idempotencyKey: urn, slug, name: 'Gas Org' };
    const created = await gas.organization.create(inputs);
    const organizationId = created.outs.organizationId;
    expect(created).toMatchObject({
      id: slug,
      outs: { slug, name: 'Gas Org', organizationId: expect.any(String) },
    });
    const replay = await gas.organization.create(inputs);
    expect(replay.outs.organizationId).toBe(organizationId);
    expect(await audits(urn)).toEqual(['admin.organization_created']);
    expect(await gas.organization.read(slug, created.outs)).toMatchObject({
      id: slug,
      props: { name: 'Gas Org' },
    });
    expect(await gas.organization.read(slug, { ...created.outs, slug: '' })).toMatchObject({
      id: slug,
    });
    expect(await gas.organization.diff(slug, created.outs, { ...inputs, name: 'Renamed' })).toEqual(
      {
        changes: true,
        replaces: [],
      },
    );
    expect(await gas.organization.diff(slug, created.outs, { ...inputs, slug: 'other' })).toEqual({
      changes: true,
      replaces: ['slug'],
    });
    expect(await gas.organization.diff(slug, created.outs, inputs)).toEqual({
      changes: false,
      replaces: [],
    });
    const updated = await gas.organization.update(slug, created.outs, {
      ...inputs,
      name: 'Renamed',
    });
    expect(updated.outs).toMatchObject({
      name: 'Renamed',
      organizationId,
    });
    await expect(
      gas.organization.create({ ...inputs, idempotencyKey: `${urn}-other`, name: 'Clash' }),
    ).rejects.toThrow('create organization: invalid state transition (Conflict)');
    await gas.organization.delete(slug, updated.outs);
    await gas.organization.delete(slug, updated.outs);
    expect(await gas.organization.read(slug, updated.outs)).toEqual({});
    await expect(gas.organization.create({ ...inputs, idempotencyKey: undefined })).rejects.toThrow(
      'Pulumi resource URN is required for mutations',
    );
  });

  test('user, membership, OAuth client, bootstrap, and audit', async () => {
    const t = tag();
    const userInputs = {
      connection,
      idempotencyKey: `urn:user:${t}`,
      login: `gas-${t}`,
      email: `gas-${t}@example.com`,
      displayName: 'Gas User',
    };
    const user = await gas.user.create(userInputs);
    expect(user.outs).toMatchObject({ status: 'pending', userId: user.id });
    expect(await gas.user.read(user.id, user.outs)).toMatchObject({
      props: { login: `gas-${t}`, displayName: 'Gas User' },
    });
    expect(
      await gas.user.diff(user.id, user.outs, { ...userInputs, email: 'new@example.com' }),
    ).toEqual({
      changes: true,
      replaces: ['email'],
    });
    expect(
      await gas.user.diff(user.id, user.outs, { ...userInputs, login: 'x', displayName: 'y' }),
    ).toEqual({
      changes: true,
      replaces: ['login'],
    });
    const renamed = await gas.user.update(user.id, user.outs, {
      ...userInputs,
      displayName: 'Renamed',
    });
    expect(renamed.outs.displayName).toBe('Renamed');

    const slug = `gas-m-${t}`;
    await gas.organization.create({ connection, idempotencyKey: `urn:org:${t}`, slug, name: 'M' });
    const memberInputs = {
      connection,
      idempotencyKey: `urn:member:${t}`,
      organizationSlug: slug,
      userId: user.id,
      role: 'member',
    };
    const member = await gas.membership.create(memberInputs);
    expect(member.id).toBe(`${slug}:${user.id}`);
    expect(await gas.membership.read(member.id, member.outs)).toMatchObject({
      props: { role: 'member' },
    });
    const imported = await gas.membership.read(member.id, {
      ...member.outs,
      organizationSlug: '',
      userId: '',
    });
    expect(imported).toMatchObject({
      id: member.id,
      props: { organizationSlug: slug, userId: user.id },
    });
    await expect(
      gas.membership.read('no-separator', { ...member.outs, organizationSlug: '', userId: '' }),
    ).rejects.toThrow('import membership: ID must be <organization-slug>:<user-id>');
    await expect(
      gas.membership.read(':', { ...member.outs, organizationSlug: '', userId: '' }),
    ).rejects.toThrow('import membership');
    expect(
      await gas.membership.diff(member.id, member.outs, { ...memberInputs, role: 'owner' }),
    ).toEqual({ changes: true, replaces: [] });
    expect(
      await gas.membership.diff(member.id, member.outs, {
        ...memberInputs,
        userId: 'u',
        organizationSlug: 'o',
      }),
    ).toEqual({
      changes: true,
      replaces: ['organizationSlug', 'userId'],
    });
    await gas.membership.update(member.id, member.outs, { ...memberInputs, role: 'owner' });
    expect(await gas.membership.read(member.id, member.outs)).toMatchObject({
      props: { role: 'owner' },
    });
    await expect(gas.user.delete(user.id, renamed.outs)).rejects.toThrow(
      'archive user: invalid state transition (Conflict)',
    );
    await gas.membership.delete(member.id, member.outs);
    expect(await gas.membership.read(member.id, member.outs)).toEqual({});
    await gas.user.delete(user.id, renamed.outs);
    expect(await gas.user.read(user.id, renamed.outs)).toEqual({});
    expect(await gas.user.read(crypto.randomUUID(), renamed.outs)).toEqual({});

    const clientInputs = {
      connection,
      idempotencyKey: `urn:client:${t}`,
      clientId: `gas-client-${t}`,
      organizationSlug: slug,
      scopes: ['openid'],
    };
    const client = await gas.oauthClient.create(clientInputs);
    expect(client.outs.clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const replayed = await gas.oauthClient.create(clientInputs);
    expect(replayed.outs.clientSecret).toBe(client.outs.clientSecret);
    const read = await gas.oauthClient.read(client.id, client.outs);
    expect(read.props).toMatchObject({
      clientSecret: client.outs.clientSecret,
      organizationSlug: slug,
      scopes: ['openid'],
      browser: false,
    });
    expect(
      await gas.oauthClient.diff(client.id, client.outs, { ...clientInputs, scopes: ['openid'] }),
    ).toEqual({ changes: false, replaces: [] });
    expect(
      await gas.oauthClient.diff(client.id, client.outs, {
        ...clientInputs,
        clientId: 'x',
        secretRotationVersion: '2',
      }),
    ).toEqual({
      changes: true,
      replaces: ['clientId'],
    });
    const metadata = await gas.oauthClient.update(client.id, client.outs, {
      ...clientInputs,
      browser: true,
      redirectUris: ['https://gas.example/cb'],
      organizationSlug: undefined,
    });
    expect(metadata.outs.clientSecret).toBe(client.outs.clientSecret);
    expect(await gas.oauthClient.read(client.id, metadata.outs)).toMatchObject({
      props: { browser: true, organizationSlug: '' },
    });
    const rotated = await gas.oauthClient.update(client.id, metadata.outs, {
      ...metadata.outs,
      secretRotationVersion: 'v2',
    });
    expect(rotated.outs.clientSecret).not.toBe(client.outs.clientSecret);
    const unchanged = await gas.oauthClient.update(client.id, rotated.outs, rotated.outs);
    expect(unchanged.outs.clientSecret).toBe(rotated.outs.clientSecret);
    // Clearing the version is not a rotation: no diff, and an update keeps the secret.
    const cleared = { ...rotated.outs, secretRotationVersion: undefined };
    expect(await gas.oauthClient.diff(client.id, rotated.outs, cleared)).toEqual({
      changes: false,
      replaces: [],
    });
    expect((await gas.oauthClient.update(client.id, rotated.outs, cleared)).outs.clientSecret).toBe(
      rotated.outs.clientSecret,
    );
    await gas.oauthClient.delete(client.id, rotated.outs);
    expect(await gas.oauthClient.read(client.id, rotated.outs)).toEqual({});
    expect(await gas.oauthClient.read('missing', rotated.outs)).toEqual({});
    const minimal = await gas.oauthClient.create({
      connection,
      idempotencyKey: `urn:min:${t}`,
      clientId: `gas-min-${t}`,
    });
    expect(minimal.id).toBe(`gas-min-${t}`);

    const secrets = {
      connection,
      name: 'bootstrap',
      activePrivateJwk: '{}',
      databasePassword: 'db',
      smtpUsername: 'u',
      smtpPassword: 'p',
      bootstrapOwnerEmail: 'o@example.com',
      bootstrapOwnerLogin: 'o',
      bootstrapOwnerPassword: 'pw',
      bootstrapOrganizationSlug: 'acme',
      bootstrapOrganizationName: 'Acme',
      accessClientId: 'a',
      accessClientSecret: 'as',
      directoryClientId: 'd',
      directoryClientSecret: 'ds',
      provisionerClientId: 'p',
      provisionerClientSecret: 'ps',
    } satisfies BootstrapInputs;
    expect(await gas.bootstrap.create(secrets)).toEqual({ id: 'bootstrap', outs: secrets });
    await expect(gas.bootstrap.create({ ...secrets, databasePassword: '' })).rejects.toThrow(
      'required GSIO auth bootstrap secret is empty',
    );
    expect(
      await gas.bootstrap.diff('bootstrap', secrets, { ...secrets, smtpPassword: 'new' }),
    ).toEqual({ changes: true, replaces: [] });
    expect(await gas.bootstrap.diff('bootstrap', secrets, secrets)).toEqual({
      changes: false,
      replaces: [],
    });
    expect(await gas.bootstrap.read('bootstrap', secrets)).toEqual({
      id: 'bootstrap',
      props: secrets,
    });
    expect(await gas.bootstrap.update('bootstrap', secrets, secrets)).toEqual({ outs: secrets });
    await gas.bootstrap.delete('bootstrap', secrets);

    const { items } = await gas.audit(connection);
    expect(
      items.find(
        (item) =>
          item.correlation_id === `urn:client:${t}` && item.action === 'admin.oauth_client_created',
      ),
    ).toMatchObject({
      action: 'admin.oauth_client_created',
      before_metadata: expect.any(String),
    });
  });
});

describe('client behavior', () => {
  function scripted(
    api: (request: Request) => Response | Promise<Response>,
    discovery?: Partial<Record<string, unknown>>,
  ) {
    return async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      if (url.pathname === '/.well-known/openid-configuration') {
        return Response.json({
          issuer: 'https://stub.example',
          token_endpoint: 'https://stub.example/oauth2/token',
          ...discovery,
        });
      }
      if (url.pathname === '/oauth2/token') return Response.json({ access_token: 'tok' });
      return api(request);
    };
  }
  const fast = (transport: (request: Request) => Promise<Response>) =>
    gasProviders(transport, { sleep: async () => {} });
  const stubConnection: Connection = {
    issuer: 'https://stub.example',
    apiUrl: 'https://api.stub.example/',
    provisionerClientId: 'p',
    provisionerClientSecret: 's',
  };
  const outs = { connection: stubConnection, idempotencyKey: 'urn:x' };

  test('every unexpected status surfaces with the operation name', async () => {
    const failing = fast(
      scripted(() => new Response(null, { status: 500, statusText: 'Server Error' })),
    );
    const org = { ...outs, slug: 's', name: 'n', organizationId: 'i' };
    const user = {
      ...outs,
      login: 'l',
      email: 'e',
      displayName: 'd',
      userId: 'u',
      status: 'active',
    };
    const member = { ...outs, organizationSlug: 'o', userId: 'u', role: 'member' };
    const client = { ...outs, clientId: 'c', secretRotationVersion: '1' };
    const cases: Array<[() => Promise<unknown>, string]> = [
      [() => failing.organization.create(org), 'create organization'],
      [() => failing.organization.read('s', org), 'read organization'],
      [() => failing.organization.update('s', org, org), 'update organization display name'],
      [() => failing.organization.delete('s', org), 'delete organization'],
      [() => failing.user.create(user), 'create user'],
      [() => failing.user.read('u', user), 'read user'],
      [() => failing.user.update('u', user, user), 'update user display name'],
      [() => failing.user.delete('u', user), 'archive user'],
      [() => failing.membership.create(member), 'create membership'],
      [() => failing.membership.read('o:u', member), 'read membership'],
      [() => failing.membership.update('o:u', member, member), 'update membership role'],
      [() => failing.membership.delete('o:u', member), 'delete membership'],
      [() => failing.oauthClient.create(client), 'create OAuth client'],
      [() => failing.oauthClient.read('c', client), 'read OAuth client'],
      [
        () => failing.oauthClient.update('c', client, { ...client, browser: true }),
        'update OAuth client metadata',
      ],
      [
        () => failing.oauthClient.update('c', client, { ...client, secretRotationVersion: '2' }),
        'rotate OAuth client secret',
      ],
      [() => failing.oauthClient.delete('c', client), 'revoke OAuth client'],
      [() => failing.audit(stubConnection), 'get audit: 500 Server Error'],
    ];
    for (const [run, action] of cases) {
      await expect(run()).rejects.toThrow(action);
    }
    const empty = fast(scripted(() => Response.json({}, { status: 201 })));
    await expect(empty.organization.create(org)).rejects.toThrow(
      'response omitted organization ID',
    );
    await expect(empty.user.create(user)).rejects.toThrow('response omitted user ID');
    await expect(empty.oauthClient.create(client)).rejects.toThrow(
      'response omitted client ID or secret',
    );
    const sparse = fast(
      scripted((request) => {
        if (request.method === 'GET' && new URL(request.url).pathname.endsWith('/audit'))
          return Response.json([{}]);
        if (request.method === 'GET') return Response.json({});
        return Response.json({}, { status: request.method === 'PATCH' ? 200 : 201 });
      }),
    );
    expect(await sparse.organization.read('s', org)).toEqual({
      id: 's',
      props: { ...org, slug: '', name: '', organizationId: '' },
    });
    expect(await sparse.organization.update('s', org, org)).toEqual({ outs: org });
    expect(await sparse.user.read('u', user)).toMatchObject({
      id: 'u',
      props: { login: '', status: '' },
    });
    expect(await sparse.user.update('u', user, user)).toEqual({ outs: user });
    expect(await sparse.membership.read('o:u', member)).toMatchObject({
      id: 'o:u',
      props: { role: '' },
    });
    expect(await sparse.oauthClient.read('c', client)).toMatchObject({
      id: 'c',
      props: { redirectUris: [], scopes: [], browser: false },
    });
    expect((await sparse.audit(stubConnection)).items).toEqual([
      {
        id: '',
        action: '',
        actor_client_id: null,
        target: null,
        correlation_id: null,
        before_metadata: '{}',
        after_metadata: '{}',
        created_at: '',
      },
    ]);
    const statusOnly = fast(scripted(() => new Response(null, { status: 201 })));
    await expect(statusOnly.user.create(user)).rejects.toThrow('response omitted user ID');
    const pendingDefault = fast(scripted(() => Response.json({ id: 'u1' }, { status: 201 })));
    expect((await pendingDefault.user.create(user)).outs.status).toBe('pending');
  });

  test('discovery and token failures, error mapping, and retries', async () => {
    const statuses = [
      [400, 'server rejected the requested state (Bad Request)'],
      [404, 'remote resource does not exist (Not Found)'],
      [409, 'invalid state transition (Conflict)'],
      [418, 'auth API returned 418'],
    ] as const;
    for (const [status, message] of statuses) {
      expect(unexpectedStatus('op', new Response(null, { status })).message).toContain(message);
    }
    expect([204, 404, 410, 500].map((status) => deleted(new Response(null, { status })))).toEqual([
      true,
      true,
      true,
      false,
    ]);

    const read = (http: (request: Request) => Promise<Response>) =>
      adminClient(stubConnection, http).GET('/api/admin/audit');
    await expect(
      read(scripted(() => Response.json([]), { issuer: 'https://evil.example' })),
    ).rejects.toThrow('OIDC discovery issuer/token endpoint validation failed');
    await expect(read(scripted(() => Response.json([]), { token_endpoint: '' }))).rejects.toThrow(
      'validation failed',
    );
    await expect(read(async () => new Response('x', { status: 503 }))).rejects.toThrow(
      'OIDC discovery returned 503',
    );
    await expect(
      read(async (request) =>
        request.url.endsWith('openid-configuration') ? new Response('not json') : new Response(),
      ),
    ).rejects.toThrow('validation failed');
    const tokenFails = async (request: Request) =>
      request.url.endsWith('openid-configuration')
        ? Response.json({
            issuer: 'https://stub.example',
            token_endpoint: 'https://stub.example/oauth2/token',
          })
        : new Response(null, { status: 401 });
    await expect(read(tokenFails)).rejects.toThrow('provisioner token request returned 401');
    const tokenEmpty = async (request: Request) =>
      request.url.endsWith('openid-configuration')
        ? Response.json({
            issuer: 'https://stub.example',
            token_endpoint: 'https://stub.example/oauth2/token',
          })
        : new Response('{', { status: 200 });
    await expect(read(tokenEmpty)).rejects.toThrow('invalid provisioner token response');

    let seen: Request | undefined;
    const ok = await read(
      scripted((request) => {
        seen = request;
        return Response.json([]);
      }),
    );
    expect(ok.response.status).toBe(200);
    expect(seen?.url).toBe('https://api.stub.example/api/admin/audit');
    expect(seen?.headers.get('authorization')).toBe('Bearer tok');

    const delays: number[] = [];
    const sleep = async (ms: number) => {
      delays.push(ms);
    };
    let calls = 0;
    const flaky = retrying(
      async () => {
        calls += 1;
        return new Response(null, { status: calls < 3 ? 503 : 200 });
      },
      { sleep },
    );
    expect((await flaky(new Request('https://x.example/'))).status).toBe(200);
    expect(delays).toEqual([200, 400]);
    calls = 0;
    const post = retrying(
      async () => {
        calls += 1;
        return new Response(null, { status: 503 });
      },
      { sleep },
    );
    expect(
      (await post(new Request('https://x.example/', { method: 'POST', body: '{}' }))).status,
    ).toBe(503);
    expect(calls).toBe(1);
    calls = 0;
    const keyed = retrying(
      async () => {
        calls += 1;
        return new Response(null, { status: 502 });
      },
      { sleep },
    );
    expect(
      (
        await keyed(
          new Request('https://x.example/', {
            method: 'POST',
            headers: { 'idempotency-key': 'urn' },
          }),
        )
      ).status,
    ).toBe(502);
    expect(calls).toBe(3);
    const broken = retrying(
      async () => {
        throw new Error('ECONNRESET');
      },
      { sleep },
    );
    await expect(broken(new Request('https://x.example/'))).rejects.toThrow(
      'auth API request failed: ECONNRESET',
    );
    const brokenPost = retrying(
      async () => {
        throw 'odd';
      },
      { sleep },
    );
    await expect(brokenPost(new Request('https://x.example/', { method: 'POST' }))).rejects.toThrow(
      'auth API request failed: transport error',
    );
    expect(new ProviderError('x').name).toBe('ProviderError');
    const real = retrying(async () => new Response('ok'), { attempts: 1 });
    expect(await (await real(new Request('https://x.example/'))).text()).toBe('ok');
    const defaults = retrying(async () => new Response('ok'));
    expect((await defaults(new Request('https://x.example/'))).status).toBe(200);
  });
});
