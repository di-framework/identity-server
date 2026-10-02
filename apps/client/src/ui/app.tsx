import { useEffect, useState } from 'react';
import type { PageModel } from '../domain/model.ts';
import { LinkConfirmScreen, LinksScreen, UnlinkConfirmScreen } from './account-screens.tsx';
import { Denied, LinkUnavailable, LoadError, Loading, NotFound } from './chrome.tsx';
import {
  AuditRecordScreen,
  AuditScreen,
  ClientScreen,
  ClientsScreen,
  RegisterClientScreen,
} from './client-screens.tsx';
import {
  CreateOrganizationScreen,
  InviteScreen,
  MembershipsScreen,
  OrganizationScreen,
  OrganizationsScreen,
  UserScreen,
  UsersScreen,
} from './directory-screens.tsx';
import {
  ConfirmEmailScreen,
  ConsentScreen,
  LoginScreen,
  PasswordlessScreen,
  PasswordScreen,
} from './public-screens.tsx';

export function useResource(path: string, search: string, load: typeof globalThis.fetch) {
  const [phase, setPhase] = useState<'loading' | 'error' | 'ready'>('loading');
  const [page, setPage] = useState<PageModel | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    setPhase('loading');
    load(`${path}${search}`, {
      headers: { Accept: 'application/json', 'x-attempt': String(attempt) },
      credentials: 'same-origin',
    })
      .then(async (response) => {
        const body = (await response.json()) as PageModel;
        if (!active) return;
        if (body.page === 'unauthenticated') {
          window.location.assign('/login');
          return;
        }
        setPage(body);
        setPhase('ready');
      })
      .catch(() => {
        if (active) setPhase('error');
      });
    return () => {
      active = false;
    };
  }, [path, search, load, attempt]);
  return { phase, page, retry: () => setAttempt((value) => value + 1) };
}

export function Screen({ page }: { page: PageModel }) {
  switch (page.page) {
    case 'login':
      return <LoginScreen page={page} />;
    case 'passwordless':
      return <PasswordlessScreen page={page} />;
    case 'passwordless-confirm':
      return <ConfirmEmailScreen page={page} />;
    case 'password':
      return <PasswordScreen page={page} />;
    case 'consent':
      return <ConsentScreen page={page} />;
    case 'unauthenticated':
      return <Loading />;
    case 'denied':
      return <Denied page={page} reason={page.reason} />;
    case 'not-found':
      return <NotFound page={page} />;
    case 'link-unavailable':
      return <LinkUnavailable page={page} />;
    case 'users':
      return <UsersScreen page={page} />;
    case 'invite':
      return <InviteScreen page={page} />;
    case 'user':
      return <UserScreen page={page} />;
    case 'organizations':
      return <OrganizationsScreen page={page} />;
    case 'create-organization':
      return <CreateOrganizationScreen page={page} />;
    case 'organization':
      return <OrganizationScreen page={page} />;
    case 'memberships':
      return <MembershipsScreen page={page} />;
    case 'clients':
      return <ClientsScreen page={page} />;
    case 'register-client':
      return <RegisterClientScreen page={page} />;
    case 'client':
      return <ClientScreen page={page} />;
    case 'audit':
      return <AuditScreen page={page} />;
    case 'audit-record':
      return <AuditRecordScreen page={page} />;
    case 'links':
      return <LinksScreen page={page} />;
    case 'link-confirm':
      return <LinkConfirmScreen page={page} />;
    case 'unlink-confirm':
      return <UnlinkConfirmScreen page={page} />;
  }
}

export function App({
  path,
  search,
  load,
}: {
  path?: string;
  search?: string;
  load?: typeof globalThis.fetch;
} = {}) {
  const resource = useResource(
    path ?? window.location.pathname,
    search ?? window.location.search,
    load ?? globalThis.fetch,
  );
  if (resource.phase === 'error') return <LoadError onRetry={resource.retry} />;
  if (resource.phase === 'loading' || !resource.page) return <Loading />;
  return <Screen page={resource.page} />;
}
