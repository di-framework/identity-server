import { ActionGroup, Button, Title, ToolbarItem } from '@patternfly/react-core';
import { useState } from 'react';
import type { PageModel } from '../domain/model.ts';
import { formatTimestamp, t } from '../i18n/messages.ts';
import {
  AppPage,
  DataTable,
  ErrorAlert,
  FilterToolbar,
  PageTitle,
  PostForm,
  recordPath,
  SelectField,
  StatusBanner,
  TextField,
} from './chrome.tsx';
import { Details } from './details.tsx';

type PageOf<Name extends PageModel['page']> = Extract<PageModel, { page: Name }>;

const userStatuses = [
  { value: 'all', label: t('all') },
  { value: 'active', label: t('active') },
  { value: 'pending', label: t('pending') },
  { value: 'archived', label: t('archived') },
];

const orgStatuses = [
  { value: 'all', label: t('all') },
  { value: 'active', label: t('active') },
  { value: 'archived', label: t('archived') },
];

const roles = [
  { value: 'member', label: t('member') },
  { value: 'owner', label: t('owner') },
];

export function UsersScreen({ page }: { page: PageOf<'users'> }) {
  const [query, setQuery] = useState(page.query);
  const [status, setStatus] = useState(page.status);
  const columns = [t('id'), t('login'), t('displayName'), t('email'), t('status'), t('systemRole')];
  return (
    <AppPage page={page}>
      <PageTitle>{t('users')}</PageTitle>
      <form method="get" action="/admin/users">
        <FilterToolbar>
          <ToolbarItem>
            <TextField
              id="user-search"
              label={t('searchUsers')}
              name="q"
              value={query}
              onChange={setQuery}
            />
          </ToolbarItem>
          <ToolbarItem>
            <SelectField
              id="user-status"
              label={t('status')}
              name="status"
              value={status}
              onChange={setStatus}
              options={userStatuses}
            />
          </ToolbarItem>
          <ToolbarItem>
            <Button type="submit" variant="secondary">
              {t('apply')}
            </Button>
          </ToolbarItem>
          <ToolbarItem align={{ default: 'alignEnd' }}>
            <Button component="a" variant="primary" href="/admin/users/invite">
              {t('inviteUser')}
            </Button>
          </ToolbarItem>
        </FilterToolbar>
      </form>
      <DataTable
        label={t('users')}
        columns={columns}
        emptyTitle={t('noUsers')}
        emptyBody={t('noUsersBody')}
        rows={page.users.map((user) => ({
          key: user.id,
          cells: [
            user.id,
            <Button
              key="login"
              component="a"
              variant="link"
              isInline
              href={recordPath('/admin/users', user.id)}
            >
              {user.login}
            </Button>,
            user.displayName,
            user.email,
            user.status,
            user.systemRole,
          ],
        }))}
      />
    </AppPage>
  );
}

export function InviteScreen({ page }: { page: PageOf<'invite'> }) {
  const [login, setLogin] = useState('');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [organization, setOrganization] = useState('');
  const [role, setRole] = useState('member');
  const organizations = [{ value: '', label: t('none') }, ...page.organizations.map(orgOption)];
  return (
    <AppPage page={page} layout="form">
      <PageTitle>{t('inviteTitle')}</PageTitle>
      <PostForm action="/admin/users/invite" csrf={page.csrf}>
        <ErrorAlert error={page.error} />
        <TextField
          id="invite-login"
          label={t('login')}
          name="login"
          value={login}
          onChange={setLogin}
          required
        />
        <TextField
          id="invite-email"
          label={t('email')}
          name="email"
          type="email"
          value={email}
          onChange={setEmail}
          required
        />
        <TextField
          id="invite-name"
          label={t('displayName')}
          name="displayName"
          value={displayName}
          onChange={setDisplayName}
        />
        <SelectField
          id="invite-organization"
          label={t('organization')}
          name="organization"
          value={organization}
          onChange={setOrganization}
          options={organizations}
        />
        <SelectField
          id="invite-role"
          label={t('role')}
          name="role"
          value={role}
          onChange={setRole}
          options={roles}
        />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('sendInvite')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AppPage>
  );
}

export function UserScreen({ page }: { page: PageOf<'user'> }) {
  const user = page.user;
  return (
    <AppPage page={page}>
      <StatusBanner name={page.banner} />
      <PageTitle>{user.displayName}</PageTitle>
      <Details
        label={t('user')}
        items={[
          { term: t('id'), value: user.id },
          { term: t('login'), value: user.login },
          { term: t('displayName'), value: user.displayName },
          { term: t('email'), value: user.email },
          { term: t('emailVerified'), value: user.emailVerified ? t('yes') : t('no') },
          { term: t('status'), value: user.status },
          { term: t('systemRole'), value: user.systemRole },
        ]}
      />
      <Title headingLevel="h2">{t('memberships')}</Title>
      <DataTable
        label={t('memberships')}
        columns={[t('organization'), t('slug'), t('role')]}
        emptyTitle={t('noMemberships')}
        emptyBody={t('noMembersBody')}
        rows={user.memberships.map((membership) => ({
          key: membership.organizationId,
          cells: [membership.name, membership.slug, membership.role],
        }))}
      />
      {page.showArchive ? (
        <PostForm action={`${recordPath('/admin/users', user.id)}/archive`} csrf={page.csrf}>
          <ActionGroup>
            <Button type="submit" variant="danger">
              {t('archive')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
      {page.showRestore ? (
        <PostForm action={`${recordPath('/admin/users', user.id)}/restore`} csrf={page.csrf}>
          <ActionGroup>
            <Button type="submit" variant="primary">
              {t('restore')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
      {page.showPasswordReset ? (
        <PostForm action={`${recordPath('/admin/users', user.id)}/password-reset`} csrf={page.csrf}>
          <ActionGroup>
            <Button type="submit" variant="secondary">
              {t('sendPasswordReset')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
    </AppPage>
  );
}

export function OrganizationsScreen({ page }: { page: PageOf<'organizations'> }) {
  const [status, setStatus] = useState(page.status);
  return (
    <AppPage page={page}>
      <PageTitle>{t('organizations')}</PageTitle>
      <form method="get" action="/admin/organizations">
        <FilterToolbar>
          <ToolbarItem>
            <SelectField
              id="org-status"
              label={t('status')}
              name="status"
              value={status}
              onChange={setStatus}
              options={orgStatuses}
            />
          </ToolbarItem>
          <ToolbarItem>
            <Button type="submit" variant="secondary">
              {t('apply')}
            </Button>
          </ToolbarItem>
          {page.canCreate ? (
            <ToolbarItem align={{ default: 'alignEnd' }}>
              <Button component="a" variant="primary" href="/admin/organizations/create">
                {t('createOrganization')}
              </Button>
            </ToolbarItem>
          ) : null}
        </FilterToolbar>
      </form>
      <DataTable
        label={t('organizations')}
        columns={[t('slug'), t('name'), t('status'), t('activeMembers'), t('activeClients')]}
        emptyTitle={t('noOrganizations')}
        emptyBody={t('noOrganizationsBody')}
        rows={page.organizations.map((organization) => ({
          key: organization.id,
          cells: [
            <Button
              key="slug"
              component="a"
              variant="link"
              isInline
              href={recordPath('/admin/organizations', organization.id)}
            >
              {organization.slug}
            </Button>,
            organization.name,
            organization.status,
            String(organization.activeMemberCount),
            String(organization.activeClientCount),
          ],
        }))}
      />
    </AppPage>
  );
}

export function CreateOrganizationScreen({ page }: { page: PageOf<'create-organization'> }) {
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  return (
    <AppPage page={page} layout="form">
      <PageTitle>{t('createOrganizationTitle')}</PageTitle>
      <PostForm action="/admin/organizations/create" csrf={page.csrf}>
        <ErrorAlert error={page.error} />
        <TextField
          id="org-slug"
          label={t('slug')}
          name="slug"
          value={slug}
          onChange={setSlug}
          required
          helper={t('slugRule')}
        />
        <TextField
          id="org-name"
          label={t('displayNameField')}
          name="name"
          value={name}
          onChange={setName}
        />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('create')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AppPage>
  );
}

export function OrganizationScreen({ page }: { page: PageOf<'organization'> }) {
  const organization = page.organization;
  const [name, setName] = useState(organization.name);
  return (
    <AppPage page={page}>
      <StatusBanner name={page.banner} />
      <PageTitle>{organization.name}</PageTitle>
      <Details
        label={t('organization')}
        items={[
          { term: t('id'), value: organization.id },
          { term: t('slug'), value: organization.slug },
          { term: t('name'), value: organization.name },
          { term: t('status'), value: organization.status },
          { term: t('created'), value: formatTimestamp(organization.createdAt) },
          { term: t('memberCount'), value: String(organization.memberCount) },
          { term: t('activeClients'), value: String(organization.activeClientCount) },
        ]}
      />
      {page.canEdit ? (
        <PostForm
          action={`${recordPath('/admin/organizations', organization.id)}/settings`}
          csrf={page.csrf}
        >
          <TextField
            id="settings-name"
            label={t('displayNameField')}
            name="name"
            value={name}
            onChange={setName}
          />
          <ActionGroup>
            <Button type="submit" variant="primary">
              {t('saveSettings')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
      {page.canArchive ? (
        <PostForm
          action={`${recordPath('/admin/organizations', organization.id)}/archive`}
          csrf={page.csrf}
        >
          <ActionGroup>
            <Button type="submit" variant="danger">
              {t('archiveOrganization')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
    </AppPage>
  );
}

export function MembershipsScreen({ page }: { page: PageOf<'memberships'> }) {
  const [organization, setOrganization] = useState(page.organizationId);
  const [user, setUser] = useState('');
  const [role, setRole] = useState('member');
  return (
    <AppPage page={page}>
      <StatusBanner
        name={page.banner}
        text={page.banner === 'blocked' ? t('membershipBlocked') : undefined}
      />
      <PageTitle>{t('membershipsTitle')}</PageTitle>
      <form method="get" action="/admin/memberships">
        <FilterToolbar>
          <ToolbarItem>
            <SelectField
              id="membership-organization"
              label={t('organization')}
              name="organization"
              value={organization}
              onChange={setOrganization}
              options={page.organizations.map(orgOption)}
            />
          </ToolbarItem>
          <ToolbarItem>
            <Button type="submit" variant="secondary">
              {t('apply')}
            </Button>
          </ToolbarItem>
        </FilterToolbar>
      </form>
      <PostForm action="/admin/memberships/add" csrf={page.csrf}>
        <ErrorAlert error={page.error} />
        <SelectField
          id="add-organization"
          label={t('organization')}
          name="organization"
          value={organization}
          onChange={setOrganization}
          options={page.organizations.map(orgOption)}
          required
        />
        <TextField
          id="add-user"
          label={t('userLoginOrEmail')}
          name="user"
          value={user}
          onChange={setUser}
          required
        />
        <SelectField
          id="add-role"
          label={t('role')}
          name="role"
          value={role}
          onChange={setRole}
          options={roles}
        />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('addMember')}
          </Button>
        </ActionGroup>
      </PostForm>
      <DataTable
        label={t('memberships')}
        columns={[t('login'), t('email'), t('role'), t('promote'), t('remove')]}
        emptyTitle={t('noMembers')}
        emptyBody={t('noMembersBody')}
        rows={page.members.map((member) => ({
          key: member.userId,
          cells: [
            member.login,
            member.email,
            member.role,
            <form key="role" method="post" action="/admin/memberships/role-change">
              <input type="hidden" name="_csrf" value={page.csrf} />
              <input type="hidden" name="organization" value={page.organizationId} />
              <input type="hidden" name="user" value={member.userId} />
              <input
                type="hidden"
                name="role"
                value={member.role === 'owner' ? 'member' : 'owner'}
              />
              <Button type="submit" variant="secondary">
                {member.role === 'owner' ? t('demote') : t('promote')}
              </Button>
            </form>,
            <form key="remove" method="post" action="/admin/memberships/remove">
              <input type="hidden" name="_csrf" value={page.csrf} />
              <input type="hidden" name="organization" value={page.organizationId} />
              <input type="hidden" name="user" value={member.userId} />
              <Button type="submit" variant="danger">
                {t('remove')}
              </Button>
            </form>,
          ],
        }))}
      />
    </AppPage>
  );
}

function orgOption(organization: { id: string; name: string }) {
  return { value: organization.id, label: organization.name };
}
