import './dom.ts';
import { afterEach, describe, expect, test } from 'bun:test';
import { cleanup, render, screen } from '@testing-library/react';
import type { PageModel } from '../domain/model.ts';
import { Screen } from './app.tsx';

afterEach(() => {
  cleanup();
});

const actor = { csrf: 'csrf-token', signedIn: true, displayName: 'Ada Admin' };

describe('identity client accessibility', () => {
  test('names sign-in fields and does not announce a signed-out message', () => {
    const page: PageModel = {
      page: 'login',
      csrf: 'csrf-token',
      signedIn: false,
      displayName: null,
    };
    render(<Screen page={{ ...page, page: 'login' }} />);
    expect(screen.getByRole('textbox', { name: /Email or login/ })).toBeTruthy();
    expect(screen.getByLabelText(/Password/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Email sign-in' })).toBeTruthy();
    expect(screen.queryByText(/signed out/i)).toBeNull();
    expect(document.querySelector('input[name="_csrf"]')).toBeTruthy();
  });

  test('consent uses a hidden openid field, checked scopes, and no deny button', () => {
    const page: PageModel = {
      page: 'consent',
      ...actor,
      clientName: 'Acme web',
      clientId: 'cli_aaaaaaaaaaaaaaaa',
      scopes: ['profile', 'email'],
      redirectUri: 'https://acme.example/callback',
    };
    render(<Screen page={page} />);
    expect(screen.getByRole('heading', { name: 'Review access' })).toBeTruthy();
    expect(screen.getByText('Acme web wants access to the identity.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Deny' })).toBeNull();
    expect(screen.getByRole('checkbox', { name: 'profile' })).toBeTruthy();
    expect(screen.getByRole('checkbox', { name: 'email' })).toBeTruthy();
    const hidden = document.querySelector('input[type="hidden"][name="scope"]');
    expect(hidden?.getAttribute('value')).toBe('openid');
    expect(screen.getByRole('button', { name: 'Allow' })).toBeTruthy();
  });

  test('tables and alerts expose accessible names', () => {
    const page: PageModel = {
      page: 'users',
      ...actor,
      query: '',
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
    };
    render(<Screen page={page} />);
    expect(screen.getByRole('grid', { name: 'Users' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'ada' })).toBeTruthy();
    cleanup();
    const empty: PageModel = { ...page, users: [] };
    render(<Screen page={empty} />);
    expect(screen.getByText('No users found')).toBeTruthy();
    cleanup();
    const unavailable: PageModel = { page: 'link-unavailable', ...actor };
    render(<Screen page={unavailable} />);
    expect(screen.getByRole('heading', { name: 'Link unavailable' })).toBeTruthy();
  });

  test('password rejection is announced and the updated flag is not shown', () => {
    const page: PageModel = { page: 'password', ...actor, error: 'short' };
    render(<Screen page={page} />);
    expect(screen.getByText('Enter a password of at least 12 characters.')).toBeTruthy();
    expect(screen.queryByText(/updated/i)).toBeNull();
  });
});
