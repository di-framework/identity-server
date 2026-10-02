import {
  Alert,
  Banner,
  Button,
  Card,
  CardBody,
  EmptyState,
  EmptyStateBody,
  Flex,
  FlexItem,
  Form,
  FormAlert,
  FormGroup,
  FormHelperText,
  FormSelect,
  FormSelectOption,
  HelperText,
  HelperTextItem,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadLogo,
  MastheadMain,
  Page,
  PageSection,
  Skeleton,
  Stack,
  TextInput,
  Title,
  Toolbar,
  ToolbarContent,
  ToolbarItem,
} from '@patternfly/react-core';
import ExclamationCircleIcon from '@patternfly/react-icons/dist/dynamic/icons/exclamation-circle-icon';
import LockIcon from '@patternfly/react-icons/dist/dynamic/icons/lock-icon';
import CheckCircleIcon from '@patternfly/react-icons/dist/dynamic/icons/rh-ui-check-circle-fill-icon';
import ErrorIcon from '@patternfly/react-icons/dist/dynamic/icons/rh-ui-error-fill-icon';
import InfoIcon from '@patternfly/react-icons/dist/dynamic/icons/rh-ui-information-fill-icon';
import WarningIcon from '@patternfly/react-icons/dist/dynamic/icons/rh-ui-warning-fill-icon';
import SearchIcon from '@patternfly/react-icons/dist/dynamic/icons/search-icon';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import type { ReactNode } from 'react';
import type { ActorFields, BannerName, FormErrorName } from '../domain/page-model.ts';
import { type MessageKey, t } from '../i18n/messages.ts';

const bannerText: Record<BannerName, MessageKey> = {
  invited: 'invited',
  archived: 'userArchived',
  restored: 'userRestored',
  'password-reset': 'passwordResetSent',
  blocked: 'blocked',
  created: 'organizationCreated',
  saved: 'settingsSaved',
  added: 'memberAdded',
  'role-changed': 'roleChanged',
  removed: 'memberRemoved',
  registered: 'clientRegistered',
  'secret-rotated': 'secretRotated',
  'metadata-updated': 'metadataUpdated',
  revoked: 'clientRevoked',
  linked: 'linked',
  unlinked: 'unlinked',
  canceled: 'canceled',
};

const errorText: Record<FormErrorName, MessageKey> = {
  conflict: 'conflict',
  slug: 'slugRule',
  'duplicate-slug': 'duplicateSlug',
  required: 'required',
  short: 'passwordShort',
  'invalid-org': 'invalidOrg',
  'user-not-found': 'userNotFound',
  'archived-user': 'archivedUser',
  'already-member': 'alreadyMember',
  'recent-auth': 'recentAuth',
  'last-method': 'lastMethod',
  'inactive-unlink': 'activeOnly',
  name: 'nameRequired',
};

const warningBanners = new Set<BannerName>(['blocked', 'archived', 'revoked']);

export function safePath(path: string): string {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('..')) return '/login';
  return path;
}

export function recordPath(base: string, id: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(id)) return '/login';
  return `${base}/${id}`;
}

export function Csrf({ csrf }: { csrf: string }) {
  return <input type="hidden" name="_csrf" value={csrf} />;
}

export function AuthPage({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <Flex
      direction={{ default: 'column' }}
      justifyContent={{ default: 'justifyContentCenter' }}
      alignItems={{ default: 'alignItemsCenter' }}
      flexWrap={{ default: 'nowrap' }}
      style={{
        minHeight: '100vh',
        background: 'var(--pf-t--global--background--color--secondary--default)',
      }}
    >
      <FlexItem style={{ width: '100%', maxWidth: '34rem' }}>
        <Card>
          <CardBody>
            <Stack hasGutter>
              <Title headingLevel="h1" size="3xl">
                {title}
              </Title>
              {children}
            </Stack>
          </CardBody>
        </Card>
      </FlexItem>
    </Flex>
  );
}

export function AppPage({
  page,
  children,
  layout = 'wide',
}: {
  page: ActorFields;
  children: ReactNode;
  layout?: 'wide' | 'form';
}) {
  const form = layout === 'form';
  const masthead = (
    <Masthead>
      <MastheadMain>
        <MastheadBrand>
          <MastheadLogo component="a" href={page.signedIn ? '/account/identity-links' : '/login'}>
            {t('productName')}
          </MastheadLogo>
        </MastheadBrand>
      </MastheadMain>
      {page.signedIn ? (
        <MastheadContent>
          <Toolbar>
            <ToolbarContent>
              <ToolbarItem align={{ default: 'alignEnd' }}>
                <form method="post" action="/admin/logout">
                  <Csrf csrf={page.csrf} />
                  <Button type="submit" variant="link">
                    {t('logOut')}
                  </Button>
                </form>
              </ToolbarItem>
            </ToolbarContent>
          </Toolbar>
        </MastheadContent>
      ) : null}
    </Masthead>
  );
  return (
    <Page masthead={masthead} isContentFilled>
      <PageSection isFilled variant={form ? 'default' : 'secondary'} hasBodyWrapper={false}>
        <Card
          isFullHeight={!form}
          style={
            form
              ? { maxWidth: '34rem', marginInline: 'auto' }
              : { minHeight: '100%', margin: 'var(--pf-t--global--spacer--md)' }
          }
        >
          <CardBody>
            <Stack hasGutter>{children}</Stack>
          </CardBody>
        </Card>
      </PageSection>
    </Page>
  );
}

export function StatusBanner({ name, text }: { name: BannerName | null; text?: string }) {
  if (!name) return null;
  const message = text ?? t(bannerText[name]);
  const status = warningBanners.has(name) ? 'warning' : 'success';
  const Icon = status === 'warning' ? WarningIcon : CheckCircleIcon;
  return (
    <Banner status={status} screenReaderText={message}>
      <Flex spaceItems={{ default: 'spaceItemsSm' }}>
        <FlexItem>
          <Icon />
        </FlexItem>
        <FlexItem>{message}</FlexItem>
      </Flex>
    </Banner>
  );
}

export function ErrorAlert({ error }: { error: FormErrorName | null }) {
  if (!error) return null;
  return (
    <FormAlert>
      <Alert variant="danger" isInline isLiveRegion title={t(errorText[error])} />
    </FormAlert>
  );
}

export function Notice({ title }: { title: string }) {
  return <Alert variant="info" isInline isLiveRegion title={title} customIcon={<InfoIcon />} />;
}

export function Loading() {
  return (
    <Page>
      <PageSection>
        <Stack hasGutter>
          <Skeleton height="2rem" width="40%" screenreaderText={t('loading')} />
          <Skeleton height="8rem" width="100%" />
        </Stack>
      </PageSection>
    </Page>
  );
}

export function LoadError({ onRetry }: { onRetry: () => void }) {
  return (
    <Page>
      <PageSection>
        <EmptyState titleText={t('loadError')} headingLevel="h1" icon={ErrorIcon}>
          <EmptyStateBody>{t('loadErrorBody')}</EmptyStateBody>
          <Button variant="primary" onClick={onRetry}>
            {t('retry')}
          </Button>
        </EmptyState>
      </PageSection>
    </Page>
  );
}

export function NotFound({ page }: { page: ActorFields }) {
  return (
    <AppPage page={page} layout="form">
      <EmptyState titleText={t('notFound')} headingLevel="h1" icon={ExclamationCircleIcon}>
        <EmptyStateBody>{t('notFoundBody')}</EmptyStateBody>
      </EmptyState>
    </AppPage>
  );
}

export function LinkUnavailable({ page, message }: { page: ActorFields; message: string | null }) {
  return (
    <AppPage page={page} layout="form">
      <EmptyState
        titleText={t('linkUnavailableTitle')}
        headingLevel="h1"
        icon={ExclamationCircleIcon}
      >
        {message ? <EmptyStateBody>{message}</EmptyStateBody> : null}
      </EmptyState>
    </AppPage>
  );
}

/** Auth-server error page: a title such as "Conflict" and its message. */
export function ErrorPage({
  page,
  title,
  message,
}: {
  page: ActorFields;
  title: string;
  message: string;
}) {
  return (
    <AppPage page={page} layout="form">
      <EmptyState titleText={title} headingLevel="h1" icon={ExclamationCircleIcon}>
        {message ? <EmptyStateBody>{message}</EmptyStateBody> : null}
      </EmptyState>
    </AppPage>
  );
}

export function Denied({
  page,
  reason,
}: {
  page: ActorFields;
  reason: 'inactive' | 'member' | 'platform';
}) {
  const body =
    reason === 'inactive'
      ? t('inactiveDenied')
      : reason === 'member'
        ? t('memberDenied')
        : t('platformDenied');
  return (
    <AppPage page={page} layout="form">
      <EmptyState titleText={t('accessNeeded')} headingLevel="h1" icon={LockIcon}>
        <EmptyStateBody>{body}</EmptyStateBody>
      </EmptyState>
    </AppPage>
  );
}

export function PageTitle({ children }: { children: ReactNode }) {
  return <Title headingLevel="h1">{children}</Title>;
}

export function PostForm({
  action,
  csrf,
  children,
}: {
  action: string;
  csrf: string;
  children: ReactNode;
}) {
  return (
    <Form method="post" action={safePath(action)} isWidthLimited>
      <Csrf csrf={csrf} />
      {children}
    </Form>
  );
}

export function TextField({
  id,
  label,
  name,
  value,
  onChange,
  type = 'text',
  required = false,
  validated = 'default',
  helper,
  autoComplete,
}: {
  id: string;
  label: string;
  name: string;
  value: string;
  onChange: (value: string) => void;
  type?: 'text' | 'email' | 'password';
  required?: boolean;
  validated?: 'default' | 'error';
  helper?: string;
  autoComplete?: string;
}) {
  return (
    <FormGroup label={label} isRequired={required} fieldId={id}>
      <TextInput
        id={id}
        name={name}
        type={type}
        value={value}
        isRequired={required}
        validated={validated}
        autoComplete={autoComplete}
        onChange={(_event, next) => onChange(next)}
      />
      {helper ? (
        <FormHelperText>
          <HelperText>
            <HelperTextItem variant={validated === 'error' ? 'error' : 'default'}>
              {helper}
            </HelperTextItem>
          </HelperText>
        </FormHelperText>
      ) : null}
    </FormGroup>
  );
}

export function SelectField({
  id,
  label,
  name,
  value,
  onChange,
  options,
  required = false,
}: {
  id: string;
  label: string;
  name: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
  required?: boolean;
}) {
  return (
    <FormGroup label={label} fieldId={id} isRequired={required}>
      <FormSelect
        id={id}
        name={name}
        value={value}
        aria-label={label}
        isRequired={required}
        onChange={(_event, next) => onChange(next)}
      >
        {options.map((option) => (
          <FormSelectOption
            key={option.value || 'empty'}
            value={option.value}
            label={option.label}
          />
        ))}
      </FormSelect>
    </FormGroup>
  );
}

export function DataTable({
  label,
  columns,
  rows,
  emptyTitle,
  emptyBody,
}: {
  label: string;
  columns: string[];
  rows: Array<{ key: string; cells: ReactNode[] }>;
  emptyTitle: string;
  emptyBody: string;
}) {
  const span = columns.length;
  return (
    <Table aria-label={label}>
      <Thead>
        <Tr>
          {columns.map((column) => (
            <Th key={column}>{column}</Th>
          ))}
        </Tr>
      </Thead>
      <Tbody>
        {rows.length === 0 ? (
          <Tr>
            <Td colSpan={span} dataLabel={columns[0] ?? label}>
              <EmptyState titleText={emptyTitle} headingLevel="h2" icon={SearchIcon}>
                <EmptyStateBody>{emptyBody}</EmptyStateBody>
              </EmptyState>
            </Td>
          </Tr>
        ) : (
          rows.map((row) => (
            <Tr key={row.key}>
              {row.cells.map((cell, index) => (
                <Td key={columns[index] ?? String(index)} dataLabel={columns[index] ?? label}>
                  {cell}
                </Td>
              ))}
            </Tr>
          ))
        )}
      </Tbody>
    </Table>
  );
}

export function FilterToolbar({ children }: { children: ReactNode }) {
  return (
    <Toolbar>
      <ToolbarContent alignItems="baseline">{children}</ToolbarContent>
    </Toolbar>
  );
}
