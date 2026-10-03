import {
  ActionGroup,
  Alert,
  Button,
  ClipboardCopy,
  Content,
  ToolbarItem,
} from '@patternfly/react-core';
import { useState } from 'react';
import type { PageModel } from '../domain/page-model.ts';
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

const clientStatuses = [
  { value: 'all', label: t('all') },
  { value: 'active', label: t('active') },
  { value: 'revoked', label: t('revoked') },
];

export function ClientsScreen({ page }: { page: PageOf<'clients'> }) {
  const [organization, setOrganization] = useState(page.organizationId);
  const [status, setStatus] = useState(page.status);
  const organizations = [{ value: '', label: t('all') }, ...page.organizations.map(orgOption)];
  return (
    <AppPage page={page}>
      <PageTitle>{t('oauthClients')}</PageTitle>
      <form method="get" action="/admin/oauth-clients">
        <FilterToolbar>
          <ToolbarItem>
            <SelectField
              id="client-organization"
              label={t('organization')}
              name="orgSlug"
              value={organization}
              onChange={setOrganization}
              options={organizations}
            />
          </ToolbarItem>
          <ToolbarItem>
            <SelectField
              id="client-status"
              label={t('status')}
              name="status"
              value={status}
              onChange={setStatus}
              options={clientStatuses}
            />
          </ToolbarItem>
          <ToolbarItem>
            <Button type="submit" variant="secondary">
              {t('apply')}
            </Button>
          </ToolbarItem>
          <ToolbarItem align={{ default: 'alignEnd' }}>
            <Button component="a" variant="primary" href="/admin/oauth-clients/register">
              {t('registerClient')}
            </Button>
          </ToolbarItem>
        </FilterToolbar>
      </form>
      <DataTable
        label={t('oauthClients')}
        columns={[t('clientId'), t('organization'), t('name'), t('status')]}
        emptyTitle={t('noClients')}
        emptyBody={t('noClientsBody')}
        rows={page.clients.map((client) => ({
          key: client.id,
          cells: [
            <Button
              key="id"
              component="a"
              variant="link"
              isInline
              href={recordPath('/admin/oauth-clients', client.id)}
            >
              {client.id}
            </Button>,
            client.organization,
            client.name,
            client.status,
          ],
        }))}
      />
    </AppPage>
  );
}

export function RegisterClientScreen({ page }: { page: PageOf<'register-client'> }) {
  const [organization, setOrganization] = useState(page.organizations[0]?.id ?? '');
  const [name, setName] = useState('');
  const [redirectUris, setRedirectUris] = useState('');
  const [grantTypes, setGrantTypes] = useState('authorization_code,refresh_token');
  const [scopes, setScopes] = useState('openid,profile,email');
  return (
    <AppPage page={page} layout="form">
      <PageTitle>{t('registerTitle')}</PageTitle>
      <PostForm action="/admin/oauth-clients/register" csrf={page.csrf}>
        <ErrorAlert error={page.error} />
        <SelectField
          id="register-organization"
          label={t('organization')}
          name="orgSlug"
          value={organization}
          onChange={setOrganization}
          options={page.organizations.map(orgOption)}
          required
        />
        <TextField
          id="client-name"
          label={t('clientName')}
          name="clientName"
          value={name}
          onChange={setName}
          required
        />
        <TextField
          id="redirect-uris"
          label={t('redirectUris')}
          name="redirectUris"
          value={redirectUris}
          onChange={setRedirectUris}
          helper={t('redirectHelp')}
        />
        <TextField
          id="grant-types"
          label={t('grantTypes')}
          name="grantTypes"
          value={grantTypes}
          onChange={setGrantTypes}
        />
        <TextField
          id="scopes"
          label={t('scopes')}
          name="scopes"
          value={scopes}
          onChange={setScopes}
        />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('register')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AppPage>
  );
}

export function ClientScreen({ page }: { page: PageOf<'client'> }) {
  const client = page.client;
  const [name, setName] = useState(client.name);
  const [redirectUris, setRedirectUris] = useState(client.redirectUris);
  const [grantTypes, setGrantTypes] = useState(client.grantTypes);
  const [scopes, setScopes] = useState(client.scopes);
  return (
    <AppPage page={page}>
      <StatusBanner name={page.banner} />
      {page.secret ? (
        <Alert variant="info" isInline isLiveRegion title={t('clientSecret')}>
          {t('secretOnce')}
          <ClipboardCopy
            isReadOnly
            hoverTip={t('copy')}
            clickTip={t('copied')}
            textAriaLabel={t('secretValue')}
          >
            {page.secret}
          </ClipboardCopy>
        </Alert>
      ) : null}
      <PageTitle>{client.name}</PageTitle>
      {!page.canModify ? <Content component="p">{t('cannotModify')}</Content> : null}
      <Details
        label={t('oauthClients')}
        items={[
          { term: t('clientId'), value: client.id },
          { term: t('organization'), value: client.organization },
          { term: t('name'), value: client.name },
          { term: t('status'), value: client.status },
          { term: t('redirectUris'), value: client.redirectUris },
          { term: t('grantTypes'), value: client.grantTypes },
          { term: t('scopes'), value: client.scopes },
        ]}
      />
      {page.canModify ? (
        <PostForm action={`${recordPath('/admin/oauth-clients', client.id)}/edit`} csrf={page.csrf}>
          <TextField
            id="edit-name"
            label={t('clientName')}
            name="clientName"
            value={name}
            onChange={setName}
            required
          />
          <TextField
            id="edit-redirects"
            label={t('redirectUris')}
            name="redirectUris"
            value={redirectUris}
            onChange={setRedirectUris}
          />
          <TextField
            id="edit-grants"
            label={t('grantTypes')}
            name="grantTypes"
            value={grantTypes}
            onChange={setGrantTypes}
          />
          <TextField
            id="edit-scopes"
            label={t('scopes')}
            name="scopes"
            value={scopes}
            onChange={setScopes}
          />
          <ActionGroup>
            <Button type="submit" variant="primary">
              {t('saveMetadata')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
      {page.canModify ? (
        <PostForm
          action={`${recordPath('/admin/oauth-clients', client.id)}/rotate-secret`}
          csrf={page.csrf}
        >
          <ActionGroup>
            <Button type="submit" variant="secondary">
              {t('rotateSecret')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
      {page.canModify ? (
        <PostForm
          action={`${recordPath('/admin/oauth-clients', client.id)}/revoke`}
          csrf={page.csrf}
        >
          <ActionGroup>
            <Button type="submit" variant="danger">
              {t('revoke')}
            </Button>
          </ActionGroup>
        </PostForm>
      ) : null}
    </AppPage>
  );
}

export function AuditScreen({ page }: { page: PageOf<'audit'> }) {
  const [action, setAction] = useState(page.filters.action);
  const [actor, setActor] = useState(page.filters.actor);
  const [target, setTarget] = useState(page.filters.target);
  const [from, setFrom] = useState(page.filters.from);
  const [to, setTo] = useState(page.filters.to);
  return (
    <AppPage page={page}>
      <PageTitle>{t('auditHeading', { count: page.count })}</PageTitle>
      <form method="get" action="/admin/audit">
        <FilterToolbar>
          <ToolbarItem>
            <TextField
              id="audit-action"
              label={t('action')}
              name="action"
              value={action}
              onChange={setAction}
            />
          </ToolbarItem>
          <ToolbarItem>
            <TextField
              id="audit-actor"
              label={t('actor')}
              name="actor"
              value={actor}
              onChange={setActor}
            />
          </ToolbarItem>
          <ToolbarItem>
            <TextField
              id="audit-target"
              label={t('target')}
              name="target"
              value={target}
              onChange={setTarget}
            />
          </ToolbarItem>
          <ToolbarItem>
            <TextField
              id="audit-from"
              label={t('from')}
              name="from"
              value={from}
              onChange={setFrom}
            />
          </ToolbarItem>
          <ToolbarItem>
            <TextField id="audit-to" label={t('to')} name="to" value={to} onChange={setTo} />
          </ToolbarItem>
          <ToolbarItem>
            <Button type="submit" variant="secondary">
              {t('apply')}
            </Button>
          </ToolbarItem>
        </FilterToolbar>
      </form>
      <DataTable
        label={t('auditHeading', { count: page.count })}
        columns={[t('id'), t('timestamp'), t('action'), t('actor'), t('target')]}
        emptyTitle={t('noAudit')}
        emptyBody={t('noAuditBody')}
        rows={page.records.map((record) => ({
          key: record.id,
          cells: [
            <Button
              key="id"
              component="a"
              variant="link"
              isInline
              href={recordPath('/admin/audit', record.id)}
            >
              {record.id}
            </Button>,
            formatTimestamp(record.timestamp),
            record.action,
            record.actor,
            record.target,
          ],
        }))}
      />
    </AppPage>
  );
}

export function AuditRecordScreen({ page }: { page: PageOf<'audit-record'> }) {
  const record = page.record;
  return (
    <AppPage page={page}>
      <PageTitle>{t('auditRecord')}</PageTitle>
      <Details
        label={t('auditRecord')}
        items={[
          { term: t('id'), value: record.id },
          { term: t('timestamp'), value: formatTimestamp(record.timestamp) },
          { term: t('action'), value: record.action },
          { term: t('actor'), value: record.actor },
          { term: t('target'), value: record.target },
          { term: t('correlationId'), value: record.correlationId },
          { term: t('stateBefore'), value: record.stateBefore },
          { term: t('stateAfter'), value: record.stateAfter },
        ]}
      />
    </AppPage>
  );
}

function orgOption(organization: { id: string; name: string }) {
  return { value: organization.id, label: organization.name };
}
