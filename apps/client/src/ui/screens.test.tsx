import './dom.ts';
import { afterEach, describe, expect, test } from 'bun:test';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { PageModel } from '../domain/model.ts';
import { App, Screen } from './app.tsx';
import { recordPath, safePath } from './chrome.tsx';

afterEach(() => {
  cleanup();
});

const actor = { csrf: 'csrf-token', signedIn: true, displayName: 'Ada Admin' };
const guest = { csrf: 'csrf-token', signedIn: false, displayName: null };

function loginPage(): PageModel {
  return { page: 'login', ...guest };
}

describe('identity client screens', () => {
  test('builds safe paths', () => {
    expect(safePath('/admin/users')).toBe('/admin/users');
    expect(safePath('//evil')).toBe('/login');
    expect(safePath('https://evil.example')).toBe('/login');
    expect(safePath('/admin/../users')).toBe('/login');
    expect(recordPath('/admin/users', 'u_ada')).toBe('/admin/users/u_ada');
    expect(recordPath('/admin/users', 'bad id')).toBe('/login');
  });

  test('renders every page variant', async () => {
    const user = userEvent.setup();
    const pages: PageModel[] = [
      loginPage(),
      { page: 'passwordless', ...guest, notice: false },
      { page: 'passwordless', ...guest, notice: true },
      { page: 'passwordless-confirm', ...guest, unavailable: true },
      { page: 'passwordless-confirm', ...guest, unavailable: false },
      { page: 'password', ...actor, error: null },
      { page: 'password', ...actor, error: 'short' },
      {
        page: 'consent',
        ...actor,
        clientName: 'Acme web',
        clientId: 'cli_aaaaaaaaaaaaaaaa',
        scopes: ['profile'],
        redirectUri: 'https://acme.example/callback',
      },
      {
        page: 'consent',
        ...actor,
        clientName: 'Acme web',
        clientId: 'cli_aaaaaaaaaaaaaaaa',
        scopes: [],
        redirectUri: '',
      },
      { page: 'unauthenticated', ...guest },
      { page: 'denied', ...actor, reason: 'inactive' },
      { page: 'denied', ...actor, reason: 'member' },
      { page: 'denied', ...actor, reason: 'platform' },
      { page: 'not-found', ...actor },
      { page: 'link-unavailable', ...actor },
      {
        page: 'users',
        ...actor,
        query: 'ada',
        status: 'all',
        users: [
          {
            id: 'u_ada',
            login: 'ada',
            displayName: 'Ada Admin',
            email: 'ada@identity.example',
            status: 'active',
            systemRole: 'platform_admin',
          },
        ],
      },
      { page: 'users', ...actor, query: '', status: 'active', users: [] },
      {
        page: 'invite',
        ...actor,
        error: 'conflict',
        organizations: [{ id: 'o_acme', slug: 'acme', name: 'Acme' }],
      },
      { page: 'invite', ...actor, error: null, organizations: [] },
      {
        page: 'user',
        ...actor,
        banner: 'invited',
        showArchive: true,
        showRestore: false,
        showPasswordReset: true,
        user: {
          id: 'u_new',
          login: 'new',
          displayName: 'New User',
          email: 'new@identity.example',
          status: 'pending',
          systemRole: 'none',
          emailVerified: false,
          memberships: [{ organizationId: 'o_acme', slug: 'acme', name: 'Acme', role: 'member' }],
        },
      },
      {
        page: 'user',
        ...actor,
        banner: 'blocked',
        showArchive: false,
        showRestore: true,
        showPasswordReset: false,
        user: {
          id: 'u_archived',
          login: 'archived',
          displayName: 'Archived User',
          email: '',
          status: 'archived',
          systemRole: 'none',
          emailVerified: true,
          memberships: [],
        },
      },
      {
        page: 'organizations',
        ...actor,
        status: 'all',
        canCreate: true,
        organizations: [
          {
            id: 'o_acme',
            slug: 'acme',
            name: 'Acme',
            status: 'active',
            activeMemberCount: 2,
            activeClientCount: 1,
          },
        ],
      },
      { page: 'organizations', ...actor, status: 'archived', canCreate: false, organizations: [] },
      { page: 'create-organization', ...actor, error: 'slug' },
      {
        page: 'organization',
        ...actor,
        banner: 'created',
        canEdit: true,
        canArchive: true,
        organization: {
          id: 'o_acme',
          slug: 'acme',
          name: 'Acme',
          status: 'active',
          createdAt: '2026-01-01T00:00:00.000Z',
          memberCount: 2,
          activeMemberCount: 2,
          activeClientCount: 1,
        },
      },
      {
        page: 'organization',
        ...actor,
        banner: null,
        canEdit: false,
        canArchive: false,
        organization: {
          id: 'o_old',
          slug: 'oldco',
          name: 'Old Co',
          status: 'archived',
          createdAt: 'not-a-date',
          memberCount: 0,
          activeMemberCount: 0,
          activeClientCount: 0,
        },
      },
      {
        page: 'memberships',
        ...actor,
        organizationId: 'o_acme',
        banner: 'blocked',
        error: 'already-member',
        organizations: [{ id: 'o_acme', slug: 'acme', name: 'Acme' }],
        members: [
          {
            organizationId: 'o_acme',
            userId: 'u_olivia',
            login: 'olivia',
            email: 'olivia@acme.example',
            role: 'owner',
          },
          {
            organizationId: 'o_acme',
            userId: 'u_marco',
            login: 'marco',
            email: 'marco@acme.example',
            role: 'member',
          },
        ],
      },
      {
        page: 'memberships',
        ...actor,
        organizationId: '',
        banner: null,
        error: null,
        organizations: [],
        members: [],
      },
      {
        page: 'clients',
        ...actor,
        organizationId: '',
        status: 'all',
        organizations: [{ id: 'o_acme', slug: 'acme', name: 'Acme' }],
        clients: [
          { id: 'cli_aaaaaaaaaaaaaaaa', organization: 'Acme', name: 'Acme web', status: 'active' },
        ],
      },
      {
        page: 'clients',
        ...actor,
        organizationId: '',
        status: 'revoked',
        organizations: [],
        clients: [],
      },
      {
        page: 'register-client',
        ...actor,
        error: 'invalid-org',
        organizations: [{ id: 'o_acme', slug: 'acme', name: 'Acme' }],
      },
      { page: 'register-client', ...actor, error: null, organizations: [] },
      {
        page: 'client',
        ...actor,
        banner: 'registered',
        secret: 'secret-value',
        canModify: true,
        client: {
          id: 'cli_aaaaaaaaaaaaaaaa',
          organizationId: 'o_acme',
          organization: 'Acme',
          name: 'Acme web',
          status: 'active',
          redirectUris: 'https://acme.example/callback',
          grantTypes: 'authorization_code,refresh_token',
          scopes: 'openid,profile,email',
        },
      },
      {
        page: 'client',
        ...actor,
        banner: 'revoked',
        secret: null,
        canModify: false,
        client: {
          id: 'cli_bbbbbbbbbbbbbbbb',
          organizationId: 'o_acme',
          organization: 'Acme',
          name: 'Acme old',
          status: 'revoked',
          redirectUris: 'https://acme.example/old',
          grantTypes: 'authorization_code',
          scopes: 'openid',
        },
      },
      {
        page: 'audit',
        ...actor,
        count: 1,
        filters: {
          action: 'user.invite',
          actor: 'ada',
          target: 'user:u_pending',
          from: '',
          to: '',
        },
        records: [
          {
            id: 'aud_invite',
            timestamp: '2026-01-12T00:00:00.000Z',
            action: 'user.invite',
            actor: 'ada',
            target: 'user:u_pending',
          },
        ],
      },
      {
        page: 'audit',
        ...actor,
        count: 0,
        filters: { action: '', actor: '', target: '', from: '', to: '' },
        records: [],
      },
      {
        page: 'audit-record',
        ...actor,
        record: {
          id: 'aud_invite',
          timestamp: '2026-01-12T00:00:00.000Z',
          action: 'user.invite',
          actor: 'ada',
          target: 'user:u_pending',
          correlationId: 'cor_invite',
          stateBefore: '{}',
          stateAfter: '{"login":"pending"}',
        },
      },
      {
        page: 'links',
        ...actor,
        accountName: 'Nora North',
        banner: 'unlinked',
        error: 'last-method',
        links: [
          {
            issuer: 'https://accounts.google.example',
            subject: 'subject-nora-1',
            subjectHint: '••••ra-1',
            provider: 'google',
            linkedAt: '2026-01-02T00:00:00.000Z',
          },
        ],
      },
      { page: 'links', ...actor, accountName: 'Casey North', banner: null, error: null, links: [] },
      {
        page: 'link-confirm',
        ...actor,
        account: { displayName: 'Nora North', login: 'nora', email: 'nora@north.example' },
        external: {
          provider: 'google',
          issuer: 'https://idp.example',
          subjectHint: '••••0001',
          providerEmail: 'user@google.example',
        },
      },
      {
        page: 'unlink-confirm',
        ...actor,
        provider: 'google',
        issuer: 'https://accounts.google.example',
        subjectHint: '••••ra-1',
      },
    ];
    for (const page of pages) {
      const view = render(<Screen page={page} />);
      if (page.page === 'login') {
        await user.type(screen.getByRole('textbox', { name: /Email or login/ }), 'ada');
        expect(screen.queryByText('signed out')).toBeNull();
        expect(document.querySelector('input[name="_csrf"]')).toBeTruthy();
      }
      if (page.page === 'consent' && page.scopes.length > 0) {
        expect(screen.queryByRole('button', { name: 'Deny' })).toBeNull();
        await user.click(screen.getByRole('checkbox', { name: 'profile' }));
        expect(document.querySelector('input[name="scope"][value="openid"]')).toBeTruthy();
      }
      if (page.page === 'users' && page.users.length > 0) {
        await user.selectOptions(screen.getByRole('combobox', { name: /Status/ }), 'active');
      }
      if (page.page === 'password' && page.error === 'short') {
        expect(screen.getByText('Enter a password of at least 12 characters.')).toBeTruthy();
      }
      if (page.page === 'passwordless' && page.notice) {
        expect(screen.getByText('A link is on the way.')).toBeTruthy();
      }
      view.unmount();
    }
  });

  test('loads, retries, and redirects when the session is missing', async () => {
    const user = userEvent.setup();
    const pending = render(
      <App
        path="/login"
        search=""
        load={(() => new Promise(() => undefined)) as unknown as typeof fetch}
      />,
    );
    expect(screen.getByText('Loading')).toBeTruthy();
    pending.unmount();

    let calls = 0;
    render(
      <App
        path="/login"
        search="?logout=1"
        load={
          (() => {
            calls += 1;
            if (calls === 1) return Promise.reject(new Error('down'));
            return Promise.resolve(new Response(JSON.stringify(loginPage())));
          }) as unknown as typeof fetch
        }
      />,
    );
    await user.click(await screen.findByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeTruthy();
    cleanup();

    let assigned = '';
    const assign = window.location.assign.bind(window.location);
    window.location.assign = (url: string | URL) => {
      assigned = String(url);
    };
    render(
      <App
        path="/admin/users"
        search=""
        load={
          (() =>
            Promise.resolve(
              new Response(
                JSON.stringify({
                  page: 'unauthenticated',
                  csrf: 'csrf-token',
                  signedIn: false,
                  displayName: null,
                }),
              ),
            )) as unknown as typeof fetch
        }
      />,
    );
    await screen.findByText('Loading');
    expect(assigned).toBe('/login');
    window.location.assign = assign;
    cleanup();

    let finish: (value: Response) => void = () => undefined;
    const hanging = render(
      <App
        path="/login"
        search=""
        load={
          (() =>
            new Promise<Response>((resolve) => {
              finish = resolve;
            })) as unknown as typeof fetch
        }
      />,
    );
    hanging.unmount();
    finish(new Response(JSON.stringify(loginPage())));
    await Promise.resolve();

    const original = globalThis.fetch;
    let fetches = 0;
    globalThis.fetch = (async () => {
      fetches += 1;
      return new Response(JSON.stringify(loginPage()));
    }) as unknown as typeof fetch;
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeTruthy();
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(fetches).toBe(1);
    globalThis.fetch = original;
  });
});
