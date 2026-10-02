import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import type { SqlDatabase } from '@di-framework/repo';
import {
  AdminAccessDenied,
  AdminPolicy,
  commaList,
  formEncode,
  invalidId,
} from '../src/admin/application/admin-policy.ts';
import {
  AuditAdminService,
  auditOrganization,
  redact,
} from '../src/admin/application/audit-admin.ts';
import { ClientAdminService } from '../src/admin/application/client-admin.ts';
import { MembershipAdminService } from '../src/admin/application/membership-admin.ts';
import { OrganizationAdminService } from '../src/admin/application/organization-admin.ts';
import { UserAdminService } from '../src/admin/application/user-admin.ts';
import { AuditEntry, type AuditRepository } from '../src/audit/domain/audit-entry.ts';
import type { RegisteredClientRepository } from '../src/authorization/domain/models.ts';
import type { DirectoryRepository } from '../src/directory/domain/directory-repository.ts';
import { AUDIT, DIRECTORY, REGISTERED_CLIENTS } from '../src/shared/domain/tokens.ts';
import { PasswordHasher } from '../src/shared/infrastructure/crypto/passwords.ts';
import { useIsolatedDatabase } from './support/database.ts';
import { type RecordingMailSender, useRecordingMail } from './support/mail.ts';

let isolated: Awaited<ReturnType<typeof useIsolatedDatabase>>;
let database: SqlDatabase;
let mail: RecordingMailSender;
const directory = () => useContainer().resolve<DirectoryRepository>(DIRECTORY);
const policy = () => useContainer().resolve(AdminPolicy);
const users = () => useContainer().resolve(UserAdminService);
const organizations = () => useContainer().resolve(OrganizationAdminService);
const memberships = () => useContainer().resolve(MembershipAdminService);
const clients = () => useContainer().resolve(ClientAdminService);
const audits = () => useContainer().resolve(AuditAdminService);

const world = {
  admin: '',
  owner: '',
  member: '',
  otherOwner: '',
  inactive: '',
  archivedOwner: '',
  loner: '',
  acme: { id: '', slug: 'acme' },
  beta: { id: '', slug: 'beta' },
  old: { id: '', slug: 'old' },
};

async function account(
  login: string,
  options: { status?: string; role?: string; email?: string | null } = {},
) {
  const id = crypto.randomUUID();
  await directory().insertAccount({
    id,
    login,
    email: options.email === undefined ? `${login}@example.com` : options.email,
    displayName: `${login} name`,
    passwordHash: null,
    emailVerified: true,
    systemRole: options.role ?? 'user',
    status: options.status ?? 'active',
  });
  return id;
}

async function organization(slug: string) {
  const id = crypto.randomUUID();
  await directory().insertOrganization({ id, slug, name: `${slug} name` });
  return id;
}

beforeAll(async () => {
  isolated = await useIsolatedDatabase('identity_admin_test');
  database = isolated.database;
  mail = useRecordingMail();
  world.admin = await account('admin', { role: 'platform_admin' });
  world.owner = await account('owner');
  world.member = await account('member');
  world.otherOwner = await account('other');
  world.inactive = await account('inactive', { status: 'pending' });
  world.archivedOwner = await account('archived-owner');
  world.loner = await account('loner', { email: null });
  world.acme.id = await organization('acme');
  world.beta.id = await organization('beta');
  world.old.id = await organization('old');
  await directory().upsertMembership(world.acme.id, world.owner, 'owner');
  await directory().upsertMembership(world.acme.id, world.member, 'member');
  await directory().upsertMembership(world.beta.id, world.otherOwner, 'owner');
  await directory().upsertMembership(world.acme.id, world.inactive, 'owner');
  await directory().upsertMembership(world.old.id, world.archivedOwner, 'owner');
  await directory().archiveOrganization('old', Date.now());
});

afterAll(async () => {
  await isolated.release();
});

async function denied(promise: Promise<unknown>) {
  await expect(promise).rejects.toBeInstanceOf(AdminAccessDenied);
}

describe('admin policy (authz)', () => {
  test('evaluates the auth server matrix', async () => {
    const p = policy();
    expect(await p.authorized(world.admin, 'ORG_CREATE')).toBe(true);
    expect(await p.authorized(world.admin, 'PLATFORM_ADMIN_MANAGE')).toBe(true);
    expect(await p.authorized(world.owner, 'ORG_CREATE')).toBe(false);
    expect(await p.authorized(world.owner, 'ORG_ARCHIVE', { orgSlug: 'acme' })).toBe(false);
    expect(await p.authorized(world.owner, 'ORG_VIEW')).toBe(true);
    expect(await p.authorized(world.owner, 'USER_ARCHIVE')).toBe(false);
    expect(await p.authorized(world.owner, 'ORG_EDIT_SETTINGS', { orgSlug: 'acme' })).toBe(true);
    expect(await p.authorized(world.owner, 'ORG_EDIT_SETTINGS', { orgSlug: 'beta' })).toBe(false);
    expect(await p.authorized(world.owner, 'USER_ARCHIVE', { userId: world.member })).toBe(true);
    expect(await p.authorized(world.owner, 'USER_ARCHIVE', { userId: world.otherOwner })).toBe(
      false,
    );
    expect(await p.authorized(world.owner, 'USER_VIEW', { userId: world.owner })).toBe(true);
    expect(await p.authorized(world.member, 'USER_VIEW')).toBe(false);
    expect(await p.authorized(world.member, 'USER_VIEW', { userId: world.member })).toBe(false);
    expect(await p.authorized(world.archivedOwner, 'ORG_VIEW')).toBe(false);
    expect(await p.authorized(world.inactive, 'ORG_VIEW', { orgSlug: 'acme' })).toBe(false);
    expect(await p.authorized(crypto.randomUUID(), 'ORG_VIEW')).toBe(false);
    const ctx = await p.context(crypto.randomUUID());
    expect(ctx.isPlatformAdmin).toBe(false);
    expect((await p.context(world.owner)).memberOrgSlugs).toEqual(new Set(['acme']));
  });

  test('last platform admin and last owner checks', async () => {
    const p = policy();
    expect(await p.canDemoteOrArchivePlatformAdmin(world.owner)).toBe(true);
    expect(await p.canDemoteOrArchivePlatformAdmin(world.admin)).toBe(false);
    expect(await p.canRemoveOrDemoteOrgOwner('missing', world.owner)).toBe(false);
    expect(await p.canRemoveOrDemoteOrgOwner('beta', world.owner)).toBe(true);
    expect(await p.canRemoveOrDemoteOrgOwner('beta', world.otherOwner)).toBe(false);
    expect(await p.canRemoveOrDemoteOrgOwner('acme', world.owner)).toBe(true);
    expect(commaList(' a, ,b ')).toEqual(['a', 'b']);
    expect(commaList(null)).toEqual([]);
    expect(invalidId()).toMatchObject({ kind: 'error', status: 400 });
  });
});

describe('users', () => {
  test('lists with filters and owner scoping', async () => {
    const all = await users().list(world.admin);
    expect(all.length).toBe(7);
    expect((await users().list(world.admin, { q: 'MEMB' })).map((u) => u.login)).toEqual([
      'member',
    ]);
    expect((await users().list(world.admin, { q: 'other name' })).map((u) => u.login)).toEqual([
      'other',
    ]);
    expect((await users().list(world.admin, { q: 'loner@' })).map((u) => u.login)).toEqual([]);
    expect((await users().list(world.admin, { status: 'PENDING' })).map((u) => u.login)).toEqual([
      'inactive',
    ]);
    const scoped = (await users().list(world.owner)).map((u) => u.login).sort();
    expect(scoped).toEqual(['inactive', 'member', 'owner']);
    await denied(users().list(world.member));
    expect((await users().inviteOrganizations(world.owner)).map((o) => o.slug)).toEqual(['acme']);
    expect((await users().inviteOrganizations(world.admin)).map((o) => o.slug)).toEqual([
      'acme',
      'beta',
    ]);
  });

  test('invites with validation, membership, mail, and audit', async () => {
    expect(
      await users().invite(world.admin, { login: ' ', email: 'x@example.com', displayName: '' }),
    ).toMatchObject({ kind: 'error', status: 400, title: 'Invalid Input' });
    expect(
      await users().invite(world.admin, {
        login: 'MEMBER',
        email: 'new@example.com',
        displayName: '',
      }),
    ).toMatchObject({ kind: 'error', status: 409, title: 'Conflict' });
    await denied(
      users().invite(world.owner, { login: 'x', email: 'x@x.x', displayName: '', orgSlug: 'beta' }),
    );
    const invited = await users().invite(world.owner, {
      login: ' Newbie ',
      email: 'newbie@example.com',
      displayName: ' ',
      orgSlug: 'acme',
      role: 'owner',
    });
    expect(invited.kind).toBe('redirect');
    const id =
      /\/admin\/users\/([0-9a-f-]+)\?invited=1$/.exec(
        (invited as { location: string }).location,
      )?.[1] ?? '';
    const created = await directory().findUser(id);
    expect(created).toMatchObject({
      login: 'Newbie',
      displayName: 'Newbie',
      status: 'pending',
      systemRole: 'user',
    });
    expect((await directory().findMembership('acme', id))?.role).toBe('owner');
    expect(mail.to('newbie@example.com')).toHaveLength(1);
    expect(
      (
        await database.first<{ purpose: string }>(
          `SELECT purpose FROM email_challenges WHERE email = 'newbie@example.com'`,
        )
      )?.purpose,
    ).toBe('activation');
    const audit = await database.first<{
      actor_client_id: string;
      after_metadata: Record<string, string>;
    }>(
      `SELECT actor_client_id, after_metadata FROM auth_audit_records WHERE action = 'admin.user.invite' AND target = ?`,
      [id],
    );
    expect(audit).toMatchObject({
      actor_client_id: world.owner,
      after_metadata: { login: 'Newbie', orgSlug: 'acme' },
    });

    const toArchived = await users().invite(world.admin, {
      login: 'to-old',
      email: 'to-old@example.com',
      displayName: 'Old',
      orgSlug: 'old',
    });
    const oldId =
      /users\/([0-9a-f-]+)/.exec((toArchived as { location: string }).location)?.[1] ?? '';
    expect(await directory().findMembership('old', oldId)).toBeUndefined();
    const member = await users().invite(world.admin, {
      login: 'plain',
      email: 'plain@example.com',
      displayName: 'P',
      orgSlug: 'beta',
      role: 'boss',
    });
    const plainId =
      /users\/([0-9a-f-]+)/.exec((member as { location: string }).location)?.[1] ?? '';
    expect((await directory().findMembership('beta', plainId))?.role).toBe('member');
  });

  test('detail, archive safeguards, restore, and password reset', async () => {
    expect((await users().detail(world.admin, 'nope')).kind).toBe('error');
    expect(await users().detail(world.admin, crypto.randomUUID())).toMatchObject({
      status: 404,
      title: 'User Not Found',
    });
    const detail = await users().detail(world.owner, world.member);
    expect(detail).toMatchObject({
      kind: 'ok',
      value: { user: { login: 'member' }, memberships: [{ organizationSlug: 'acme' }] },
    });
    await denied(users().detail(world.owner, world.otherOwner));

    expect(await users().archive(world.admin, world.admin)).toEqual({
      kind: 'redirect',
      location: `/admin/users/${world.admin}?error=${formEncode('Cannot archive the last active platform administrator')}`,
    });
    expect(await users().archive(world.admin, world.otherOwner)).toEqual({
      kind: 'redirect',
      location: `/admin/users/${world.otherOwner}?error=${formEncode('Cannot archive user who is the sole owner of active organization beta')}`,
    });
    expect((await users().archive(world.admin, 'nope')).kind).toBe('error');
    expect(await users().archive(world.admin, crypto.randomUUID())).toMatchObject({ status: 404 });
    expect(await users().archive(world.owner, world.member)).toEqual({
      kind: 'redirect',
      location: `/admin/users/${world.member}?archived=1`,
    });
    expect((await directory().findUser(world.member))?.status).toBe('archived');
    expect(await users().archive(world.admin, world.archivedOwner)).toMatchObject({
      location: expect.stringContaining('archived=1'),
    });

    expect(await users().restore(world.owner, world.member)).toEqual({
      kind: 'redirect',
      location: `/admin/users/${world.member}?restored=1`,
    });
    expect((await directory().findUser(world.member))?.status).toBe('active');
    expect((await users().restore(world.admin, 'x')).kind).toBe('error');
    expect(await users().restore(world.admin, crypto.randomUUID())).toMatchObject({ status: 404 });

    const before = mail.to('member@example.com').length;
    expect(await users().passwordReset(world.owner, world.member)).toEqual({
      kind: 'redirect',
      location: `/admin/users/${world.member}?reset=1`,
    });
    expect(mail.to('member@example.com')).toHaveLength(before + 1);
    expect(await users().passwordReset(world.admin, world.loner)).toMatchObject({
      kind: 'redirect',
    });
    expect((await users().passwordReset(world.admin, 'x')).kind).toBe('error');
    expect(await users().passwordReset(world.admin, crypto.randomUUID())).toMatchObject({
      status: 404,
    });
    const reset = await database.first<{ after_metadata: Record<string, unknown> }>(
      `SELECT after_metadata FROM auth_audit_records WHERE action = 'admin.user.password_reset' AND target = ?`,
      [world.loner],
    );
    expect(reset?.after_metadata).toEqual({ resetRequested: true });
  });
});

describe('organizations', () => {
  test('lists, creates, shows, renames, and archives', async () => {
    const all = await organizations().list(world.admin);
    expect(all.canCreate).toBe(true);
    const acme = all.rows.find((row) => row.organization.slug === 'acme');
    expect(acme?.memberCount).toBeGreaterThanOrEqual(3);
    expect(
      (await organizations().list(world.admin, 'archived')).rows.map((r) => r.organization.slug),
    ).toEqual(['old']);
    expect(
      (await organizations().list(world.admin, 'ACTIVE')).rows.map((r) => r.organization.slug),
    ).not.toContain('old');
    const owned = await organizations().list(world.owner);
    expect(owned).toMatchObject({ canCreate: false, rows: [{ organization: { slug: 'acme' } }] });

    await denied(organizations().checkCreate(world.owner));
    await organizations().checkCreate(world.admin);
    expect(await organizations().create(world.admin, { slug: 'Bad Slug', name: '' })).toMatchObject(
      {
        status: 400,
        title: 'Invalid Organization Slug',
      },
    );
    expect(await organizations().create(world.admin, { slug: '', name: '' })).toMatchObject({
      status: 400,
    });
    expect(await organizations().create(world.admin, { slug: ' ACME ', name: '' })).toMatchObject({
      status: 409,
      message: "Organization with slug 'acme' already exists.",
    });
    const created = await organizations().create(world.admin, { slug: ' New-Org ', name: '  ' });
    const id =
      /organizations\/([0-9a-f-]+)\?created=1/.exec(
        (created as { location: string }).location,
      )?.[1] ?? '';
    expect((await directory().findOrganizationById(id))?.name).toBe('new-org');

    expect((await organizations().detail(world.admin, 'x')).kind).toBe('error');
    expect(await organizations().detail(world.admin, crypto.randomUUID())).toMatchObject({
      status: 404,
    });
    expect(await organizations().detail(world.admin, id)).toMatchObject({
      kind: 'ok',
      value: { canArchive: true, clientCount: 0 },
    });
    expect(await organizations().detail(world.owner, world.acme.id)).toMatchObject({
      value: { canArchive: false },
    });
    await denied(organizations().detail(world.owner, id));

    expect(await organizations().updateSettings(world.owner, world.acme.id, ' ')).toEqual({
      kind: 'redirect',
      location: `/admin/organizations/${world.acme.id}?updated=1`,
    });
    expect((await directory().findOrganization('acme'))?.name).toBe('acme');
    await organizations().updateSettings(world.owner, world.acme.id, 'Acme Corp');
    expect((await organizations().updateSettings(world.owner, 'x', 'n')).kind).toBe('error');
    expect(
      await organizations().updateSettings(world.owner, crypto.randomUUID(), 'n'),
    ).toMatchObject({ status: 404 });

    await denied(organizations().archive(world.owner, world.acme.id));
    expect(await organizations().archive(world.admin, id)).toEqual({
      kind: 'redirect',
      location: `/admin/organizations/${id}?archived=1`,
    });
    expect((await directory().findOrganizationById(id))?.archivedAt).not.toBeNull();
    expect((await organizations().archive(world.admin, 'x')).kind).toBe('error');
    expect(await organizations().archive(world.admin, crypto.randomUUID())).toMatchObject({
      status: 404,
    });
  });
});

describe('memberships', () => {
  test('lists, adds, changes roles, and removes with last-owner blocks', async () => {
    expect(
      (await memberships().list(world.admin, 'beta')).memberships.map((m) => m.userLogin),
    ).toContain('other');
    expect((await memberships().list(world.admin)).memberships.length).toBeGreaterThan(4);
    const own = await memberships().list(world.owner);
    expect(new Set(own.memberships.map((m) => m.organizationSlug))).toEqual(new Set(['acme']));
    expect(own.organizations.map((o) => o.slug)).toEqual(['acme']);
    await denied(memberships().list(world.owner, 'beta'));

    const add = (form: { orgSlug: string; userLoginOrEmail: string; role: string }) =>
      memberships().add(world.admin, form);
    expect(await add({ orgSlug: 'old', userLoginOrEmail: 'loner', role: 'member' })).toMatchObject({
      location: `/admin/memberships?orgSlug=old&error=${formEncode('Invalid or archived organization')}`,
    });
    expect(
      await add({ orgSlug: 'missing', userLoginOrEmail: 'loner', role: 'member' }),
    ).toMatchObject({
      location: expect.stringContaining(formEncode('Invalid or archived organization')),
    });
    expect(
      await add({ orgSlug: 'beta', userLoginOrEmail: 'nobody', role: 'member' }),
    ).toMatchObject({
      location: expect.stringContaining(formEncode('User not found')),
    });
    const gone = await account('gone', { status: 'archived' });
    expect(gone).toBeDefined();
    expect(
      await add({ orgSlug: 'beta', userLoginOrEmail: 'GONE@example.com', role: 'member' }),
    ).toMatchObject({
      location: expect.stringContaining(formEncode('Cannot add archived user to organization')),
    });
    expect(await add({ orgSlug: 'beta', userLoginOrEmail: 'other', role: 'member' })).toMatchObject(
      {
        location: expect.stringContaining(formEncode('User is already a member')),
      },
    );
    expect(await add({ orgSlug: 'beta', userLoginOrEmail: ' loner ', role: 'owner' })).toEqual({
      kind: 'redirect',
      location: '/admin/memberships?orgSlug=beta&added=1',
    });
    expect((await directory().findMembership('beta', world.loner))?.role).toBe('owner');

    const change = (userId: string, newRole: string, orgSlug = 'beta') =>
      memberships().changeRole(world.admin, { orgSlug, userId, newRole });
    expect((await change('x', 'member')).kind).toBe('error');
    expect(await change(crypto.randomUUID(), 'member')).toMatchObject({ status: 404 });
    expect(await change(world.loner, 'member', 'missing')).toMatchObject({ status: 404 });
    expect(await change(world.loner, 'member')).toMatchObject({
      location: '/admin/memberships?orgSlug=beta&changed=1',
    });
    expect(await change(world.otherOwner, 'member')).toMatchObject({
      location: `/admin/memberships?orgSlug=beta&error=${formEncode('Cannot demote last owner')}`,
    });
    expect(await change(world.loner, 'owner')).toMatchObject({
      location: expect.stringContaining('changed=1'),
    });

    const remove = (userId: string, orgSlug = 'beta') =>
      memberships().remove(world.admin, { orgSlug, userId });
    expect((await remove('x')).kind).toBe('error');
    expect(await remove(crypto.randomUUID())).toMatchObject({ status: 404 });
    expect(await remove(world.loner, 'missing')).toMatchObject({ status: 404 });
    expect(await remove(world.loner)).toMatchObject({
      location: '/admin/memberships?orgSlug=beta&removed=1',
    });
    expect(await remove(world.otherOwner)).toMatchObject({
      location: `/admin/memberships?orgSlug=beta&error=${formEncode('Cannot remove last owner')}`,
    });
    await directory().upsertMembership(world.beta.id, world.member, 'member');
    expect(await remove(world.member)).toMatchObject({
      location: expect.stringContaining('removed=1'),
    });
  });

  test('concurrent demotions and removals never leave an organization ownerless', async () => {
    const gammaId = await organization('gamma');
    const first = await account('gamma-first');
    const second = await account('gamma-second');
    const owners = async () => {
      await directory().upsertMembership(gammaId, first, 'owner');
      await directory().upsertMembership(gammaId, second, 'owner');
    };
    await owners();
    await Promise.all([
      memberships().changeRole(world.admin, { orgSlug: 'gamma', userId: first, newRole: 'member' }),
      memberships().changeRole(world.admin, {
        orgSlug: 'gamma',
        userId: second,
        newRole: 'member',
      }),
    ]);
    expect(await directory().countOwners('gamma')).toBe(1);
    await owners();
    await Promise.all([
      memberships().remove(world.admin, { orgSlug: 'gamma', userId: first }),
      memberships().remove(world.admin, { orgSlug: 'gamma', userId: second }),
    ]);
    expect(await directory().countOwners('gamma')).toBe(1);
  });

  test('concurrent archives never leave the platform without an active administrator', async () => {
    const deputy = await account('deputy', { role: 'platform_admin' });
    const archived = await Promise.all([
      users().archive(world.admin, world.admin),
      users().archive(world.admin, deputy),
    ]);
    expect(
      archived.filter((result) => 'location' in result && result.location.includes('archived=1')),
    ).toHaveLength(1);
    expect(await directory().countActivePlatformAdmins()).toBe(1);
    await directory().updateAccount(world.admin, { status: 'active' });
    await directory().updateAccount(deputy, { status: 'archived' });
  });
});

describe('oauth clients', () => {
  test('registers cli_ clients, lists, edits, rotates, and revokes', async () => {
    expect((await clients().registerOrganizations(world.owner)).map((o) => o.slug)).toEqual([
      'acme',
    ]);
    expect(
      await clients().register(world.admin, { orgSlug: 'old', clientName: 'x' }),
    ).toMatchObject({
      status: 400,
      title: 'Invalid Organization',
    });
    expect(
      await clients().register(world.admin, { orgSlug: 'missing', clientName: 'x' }),
    ).toMatchObject({ status: 400 });
    await denied(clients().register(world.owner, { orgSlug: 'beta', clientName: 'x' }));
    const registered = await clients().register(world.owner, {
      orgSlug: 'acme',
      clientName: ' Portal ',
    });
    expect(registered.kind).toBe('ok');
    const { clientId, secret } = (registered as { value: { clientId: string; secret: string } })
      .value;
    expect(clientId).toMatch(/^cli_[0-9a-f]{16}$/);
    const stored = await useContainer()
      .resolve<RegisteredClientRepository>(REGISTERED_CLIENTS)
      .find(clientId);
    expect(stored).toMatchObject({
      clientName: 'Portal',
      authenticationMethods: ['client_secret_basic'],
      grantTypes: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile', 'email'],
      redirectUris: [],
      organizationSlug: 'acme',
      settings: { requireProofKey: false, requireAuthorizationConsent: false },
    });
    expect(await new PasswordHasher().verify(secret, stored?.secretHash)).toBe(true);
    const named = await clients().register(world.admin, {
      orgSlug: 'beta',
      clientName: '',
      redirectUris: 'https://b.example/cb, https://b.example/cb2',
      grantTypes: 'client_credentials',
      scopes: 'admin:read',
    });
    const betaId = (named as { value: { clientId: string } }).value.clientId;
    expect(await clients().detail(world.admin, betaId)).toMatchObject({
      value: {
        clientName: betaId,
        grantTypes: ['client_credentials'],
        redirectUris: ['https://b.example/cb', 'https://b.example/cb2'],
      },
    });

    expect((await clients().list(world.owner)).clients.map((c) => c.clientId)).toEqual([clientId]);
    expect(
      (await clients().list(world.admin, { orgSlug: 'beta' })).clients.map((c) => c.clientId),
    ).toEqual([betaId]);
    expect((await clients().list(world.admin)).clients.length).toBe(2);

    expect(await clients().detail(world.admin, 'missing')).toMatchObject({
      status: 404,
      title: 'Client Not Found',
    });
    await denied(clients().detail(world.owner, betaId));
    expect(
      await clients().edit(world.owner, clientId, {
        clientName: 'Portal 2',
        redirectUris: 'https://a.example/cb',
        grantTypes: 'authorization_code',
        scopes: 'openid',
      }),
    ).toMatchObject({ kind: 'ok' });
    expect(await clients().detail(world.owner, clientId)).toMatchObject({
      value: {
        clientName: 'Portal 2',
        redirectUris: ['https://a.example/cb'],
        grantTypes: ['authorization_code'],
        scopes: ['openid'],
      },
    });
    expect(await clients().edit(world.owner, 'missing', { clientName: 'x' })).toMatchObject({
      status: 404,
    });
    const renamed = await clients().edit(world.owner, clientId, { clientName: 'Portal 3' });
    expect(renamed).toMatchObject({
      kind: 'ok',
      value: {
        clientName: 'Portal 3',
        redirectUris: ['https://a.example/cb'],
        grantTypes: ['authorization_code'],
        scopes: ['openid'],
      },
    });

    for (const scopes of ['openid,admin:write', 'admin:read', 'directory:read']) {
      expect(
        await clients().register(world.owner, { orgSlug: 'acme', clientName: 'x', scopes }),
      ).toMatchObject({ status: 400, title: 'Scope Not Allowed' });
      expect(
        await clients().edit(world.owner, clientId, { clientName: 'x', scopes }),
      ).toMatchObject({ status: 400, title: 'Scope Not Allowed' });
    }
    const granted = await clients().register(world.admin, {
      orgSlug: 'acme',
      clientName: 'Provisioner',
      grantTypes: 'client_credentials',
      scopes: 'admin:read',
    });
    const grantedId = (granted as { value: { clientId: string } }).value.clientId;
    expect(
      await clients().edit(world.owner, grantedId, {
        clientName: 'Provisioner 2',
        scopes: 'admin:read,openid',
      }),
    ).toMatchObject({ kind: 'ok', value: { scopes: ['admin:read', 'openid'] } });
    expect(
      await clients().edit(world.owner, grantedId, {
        clientName: 'Provisioner 3',
        scopes: 'admin:read,admin:write',
      }),
    ).toMatchObject({
      status: 400,
      message: 'Only platform administrators can grant admin:write.',
    });
    await clients().revoke(world.admin, grantedId);

    const rotated = await clients().rotateSecret(world.owner, clientId);
    const fresh = (rotated as { value: { secret: string } }).value.secret;
    expect(fresh).not.toBe(secret);
    expect(
      await new PasswordHasher().verify(
        fresh,
        ((await clients().detail(world.owner, clientId)) as { value: { secretHash: string } }).value
          .secretHash,
      ),
    ).toBe(true);
    expect(await clients().rotateSecret(world.owner, 'missing')).toMatchObject({ status: 404 });

    expect(await clients().revoke(world.owner, clientId)).toEqual({
      kind: 'redirect',
      location: `/admin/oauth-clients/${clientId}?revoked=1`,
    });
    expect(await clients().revoke(world.owner, 'missing')).toMatchObject({ status: 404 });
    expect(
      (await clients().list(world.owner, { status: 'revoked' })).clients
        .map((c) => c.clientId)
        .sort(),
    ).toEqual([clientId, grantedId].sort());
    expect((await clients().list(world.owner, { status: 'active' })).clients).toEqual([]);
    const orgs = await organizations().detail(world.admin, world.beta.id);
    expect(orgs).toMatchObject({ value: { clientCount: 1 } });

    const audit = await database.first<{ target: string }>(
      `SELECT target FROM auth_audit_records WHERE action = 'admin.oauth_client.create' AND after_metadata->>'clientId' = ?`,
      [clientId],
    );
    expect(audit?.target).toBe(`acme:${clientId}`);
  });
});

describe('audit', () => {
  test('filters, scopes to owned slugs, and redacts detail', async () => {
    const repository = useContainer().resolve<AuditRepository>(AUDIT);
    await repository.append({
      action: 'test.secret_event',
      actor: 'robot',
      target: 'beta:thing',
      correlationId: null,
      before: { clientSecret: 'shh', note: 'beta' },
      after: { token: 'abc', count: 1 },
    });
    await repository.append({
      action: 'test.metadata_only',
      actor: 'robot',
      target: 'elsewhere',
      correlationId: null,
      after: { orgSlug: 'acme' },
    });
    const scoped = [
      { action: 'test.org.scoped', target: 'acme' },
      { action: 'admin.org.edit_settings', target: 'acme' },
      { action: 'admin.organization_updated', target: 'acme' },
      { action: 'admin.membership.add', target: 'acme:someone' },
      { action: 'admin.oauth_client.revoke', target: 'acme:cli_x' },
      { action: 'admin.membership_upserted', target: 'acme/someone' },
      { action: 'admin.membership.remove', target: 'acme-two:someone' },
      { action: 'admin.membership_deleted', target: '/someone' },
      { action: 'admin.org.archive', target: null },
      { action: 'admin.user.archive', target: crypto.randomUUID() },
    ];
    for (const record of scoped) {
      await repository.append({
        ...record,
        actor: 'scope-test',
        correlationId: null,
        after: { status: 'archived', note: 'acme' },
      });
    }
    for (const after of [{ orgSlug: 'acme' }, { orgSlug: '' }, {}]) {
      await repository.append({
        action: 'admin.user.invite',
        actor: 'scope-test',
        target: crypto.randomUUID(),
        correlationId: null,
        after,
      });
    }
    expect(
      (await audits().list(world.owner, { actor: 'scope-test' })).map((r) => r.action).sort(),
    ).toEqual(
      [
        'admin.membership.add',
        'admin.membership_upserted',
        'admin.oauth_client.revoke',
        'admin.org.edit_settings',
        'admin.organization_updated',
        'admin.user.invite',
      ].sort(),
    );
    const all = await audits().list(world.admin, { action: 'TEST.', actor: 'ROB' });
    expect(all.map((r) => r.action).sort()).toEqual(['test.metadata_only', 'test.secret_event']);
    expect((await audits().list(world.admin, { target: 'beta:' })).map((r) => r.action)).toContain(
      'test.secret_event',
    );
    const future = new Date(Date.now() + 60_000).toISOString();
    expect(await audits().list(world.admin, { from: future })).toEqual([]);
    expect(
      (await audits().list(world.admin, { to: future, from: 'yesterday' })).length,
    ).toBeGreaterThan(2);
    expect(await audits().list(world.admin, { to: '2000-01-01T00:00:00Z' })).toEqual([]);
    expect(await audits().list(world.admin, { actor: 'nobody-at-all' })).toEqual([]);
    // Slugs in a target or metadata of an unrelated action are not a tenant association.
    expect(await audits().list(world.owner, { action: 'test.' })).toEqual([]);
    await denied(audits().list(world.member));

    const secretRecord = all.find((r) => r.action === 'test.secret_event');
    const detail = await audits().detail(world.admin, secretRecord?.id ?? '');
    const value = (detail as { value: { beforeMetadata: string; afterMetadata: string } }).value;
    expect(value.beforeMetadata).toContain('"clientSecret": "[REDACTED]"');
    expect(value.beforeMetadata).toContain('"note": "beta"');
    expect(value.afterMetadata).toContain('"token": "[REDACTED]"');
    expect(value.afterMetadata).toContain('"count": 1');
    await denied(audits().detail(world.owner, secretRecord?.id ?? ''));
    expect((await audits().detail(world.admin, 'x')).kind).toBe('error');
    expect(await audits().detail(world.admin, crypto.randomUUID())).toMatchObject({ status: 404 });

    const invite = (after: string) =>
      auditOrganization(
        new AuditEntry('i', 'admin.user.invite', null, null, null, '{}', after, ''),
      );
    expect(invite('{"orgSlug":"acme"}')).toBe('acme');
    expect(invite('not json')).toBeUndefined();
    expect(invite('"acme"')).toBeUndefined();
    expect(invite('null')).toBeUndefined();

    expect(redact('')).toBe('{}');
    expect(redact('{"password":"a","apiKey":"b","Authorization":"c","n":"d"}')).toBe(
      '{"password":"[REDACTED]","apiKey":"[REDACTED]","Authorization":"[REDACTED]","n":"d"}',
    );
  });
});
