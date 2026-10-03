import { ActionGroup, Button, Checkbox, Content, FormGroup } from '@patternfly/react-core';
import { useState } from 'react';
import type { PageModel } from '../domain/page-model.ts';
import { t } from '../i18n/messages.ts';
import { AppPage, AuthPage, Notice, PageTitle, PostForm, TextField } from './chrome.tsx';

type PageOf<Name extends PageModel['page']> = Extract<PageModel, { page: Name }>;

export function LoginScreen({ page }: { page: PageOf<'login'> }) {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  return (
    <AuthPage title={t('signInTitle')}>
      <PostForm action="/login" csrf={page.csrf}>
        <TextField
          id="identifier"
          label={t('identifier')}
          name="username"
          value={identifier}
          onChange={setIdentifier}
          required
          autoComplete="username"
        />
        <TextField
          id="password"
          label={t('password')}
          name="password"
          type="password"
          value={password}
          onChange={setPassword}
          required
          autoComplete="current-password"
        />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('signIn')}
          </Button>
          <Button component="a" variant="link" href="/passwordless">
            {t('emailSignIn')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AuthPage>
  );
}

export function PasswordlessScreen({ page }: { page: PageOf<'passwordless'> }) {
  const [email, setEmail] = useState('');
  return (
    <AuthPage title={t('emailSignInTitle')}>
      {page.notice ? <Notice title={t('linkOnTheWay')} /> : null}
      <PostForm action="/passwordless" csrf={page.csrf}>
        <TextField
          id="email"
          label={t('email')}
          name="email"
          type="email"
          value={email}
          onChange={setEmail}
          required
          autoComplete="email"
        />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('sendLink')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AuthPage>
  );
}

export function ConfirmEmailScreen({ page }: { page: PageOf<'passwordless-confirm'> }) {
  if (page.unavailable) {
    return <AuthPage title={t('linkUnavailable')} />;
  }
  return (
    <AuthPage title={t('emailSignInTitle')}>
      <Content component="p">{t('scannerProtection')}</Content>
      <PostForm action="/passwordless/confirm" csrf={page.csrf}>
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('continue')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AuthPage>
  );
}

export function PasswordScreen({ page }: { page: PageOf<'password'> }) {
  const [password, setPassword] = useState('');
  const invalid = page.error === 'short';
  return (
    <AppPage page={page} layout="form">
      <PageTitle>{t('setPassword')}</PageTitle>
      <PostForm action="/account/password" csrf={page.csrf}>
        <TextField
          id="new-password"
          label={t('newPassword')}
          name="password"
          type="password"
          value={password}
          onChange={setPassword}
          required
          validated={invalid ? 'error' : 'default'}
          helper={invalid ? t('passwordShort') : undefined}
          autoComplete="new-password"
        />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('savePassword')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AppPage>
  );
}

export function ConsentScreen({ page }: { page: PageOf<'consent'> }) {
  const [scopes, setScopes] = useState(page.scopes);
  return (
    <AppPage page={page} layout="form">
      <PageTitle>{t('reviewAccess')}</PageTitle>
      <Content component="p">{t('consentBody')}</Content>
      <PostForm action="/oauth2/authorize" csrf={page.csrf}>
        <input type="hidden" name="client_id" value={page.clientId} />
        {page.state !== null ? <input type="hidden" name="state" value={page.state} /> : null}
        {page.openid ? <input type="hidden" name="scope" value="openid" /> : null}
        {page.scopes.length > 0 ? (
          <FormGroup label={t('scopes')} fieldId="consent-scopes" role="group">
            {page.scopes.map((scope) => (
              <Checkbox
                key={scope}
                id={`scope-${scope}`}
                name="scope"
                value={scope}
                label={scope}
                isChecked={scopes.includes(scope)}
                onChange={(_event, checked) => {
                  setScopes((current) =>
                    checked ? [...current, scope] : current.filter((item) => item !== scope),
                  );
                }}
              />
            ))}
          </FormGroup>
        ) : null}
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('allow')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AppPage>
  );
}
