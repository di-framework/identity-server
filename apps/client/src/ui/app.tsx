import { useEffect, useState } from 'react';
import type { PageModel } from '../domain/page-model.ts';
import { LinkConfirmScreen, LinksScreen, UnlinkConfirmScreen } from './account-screens.tsx';
import { Denied, ErrorPage, LinkUnavailable, LoadError, Loading, NotFound } from './chrome.tsx';
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

declare global {
  interface Window {
    __IDENTITY_PAGE__?: PageModel;
  }
}

/** The page model the server embedded in the HTML shell, used once on first render. */
export function takeEmbeddedPage(): PageModel | null {
  const embedded = typeof window === 'undefined' ? undefined : window.__IDENTITY_PAGE__;
  if (!embedded) return null;
  window.__IDENTITY_PAGE__ = undefined;
  return embedded;
}

export function useResource(path: string, search: string, load: typeof globalThis.fetch) {
  const [embedded] = useState(takeEmbeddedPage);
  const [phase, setPhase] = useState<'loading' | 'error' | 'ready'>(embedded ? 'ready' : 'loading');
  const [page, setPage] = useState<PageModel | null>(embedded);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (embedded && attempt === 0) return;
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
  }, [path, search, load, attempt, embedded]);
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
      return <LinkUnavailable page={page} message={page.message} />;
    case 'error':
      return <ErrorPage page={page} title={page.title} message={page.message} />;
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
