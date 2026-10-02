import { ActionGroup, Button, Content, Grid, GridItem, Title } from '@patternfly/react-core';
import type { PageModel } from '../domain/page-model.ts';
import { formatTimestamp, t } from '../i18n/messages.ts';
import { AppPage, DataTable, ErrorAlert, PageTitle, PostForm, StatusBanner } from './chrome.tsx';
import { Details } from './details.tsx';

type PageOf<Name extends PageModel['page']> = Extract<PageModel, { page: Name }>;

export function LinksScreen({ page }: { page: PageOf<'links'> }) {
  return (
    <AppPage page={page}>
      <StatusBanner name={page.banner} />
      <ErrorAlert error={page.error} />
      <PageTitle>{t('linkedIdentities')}</PageTitle>
      <Content component="p">{page.accountName}</Content>
      <DataTable
        label={t('linkedIdentities')}
        columns={[t('issuer'), t('subjectHint'), t('linkedAt'), t('unlink')]}
        emptyTitle={t('noLinks')}
        emptyBody={t('noLinks')}
        rows={page.links.map((link) => ({
          key: link.id,
          cells: [
            link.issuer,
            link.subjectHint,
            formatTimestamp(link.linkedAt),
            <form key="unlink" method="post" action="/account/identity-links/unlink/start">
              <input type="hidden" name="_csrf" value={page.csrf} />
              <input type="hidden" name="id" value={link.id} />
              <Button type="submit" variant="danger">
                {t('unlink')}
              </Button>
            </form>,
          ],
        }))}
      />
    </AppPage>
  );
}

export function LinkConfirmScreen({ page }: { page: PageOf<'link-confirm'> }) {
  return (
    <AppPage page={page} layout="form">
      <PageTitle>{t('confirmLinkTitle')}</PageTitle>
      <Grid hasGutter>
        <GridItem md={6}>
          <Title headingLevel="h2">{t('currentAccount')}</Title>
          <Details
            label={t('currentAccount')}
            items={[
              { term: t('displayName'), value: page.account.displayName },
              { term: t('login'), value: page.account.login },
              { term: t('email'), value: page.account.email },
            ]}
          />
        </GridItem>
        <GridItem md={6}>
          <Title headingLevel="h2">{t('externalIdentity')}</Title>
          <Details
            label={t('externalIdentity')}
            items={[
              { term: t('provider'), value: page.external.provider },
              { term: t('issuer'), value: page.external.issuer },
              { term: t('subjectHint'), value: page.external.subjectHint },
              { term: t('providerEmail'), value: page.external.providerEmail },
            ]}
          />
        </GridItem>
      </Grid>
      <Content component="p">{t('providerSignIn')}</Content>
      <PostForm action="/account/identity-links/confirm" csrf={page.csrf}>
        <input type="hidden" name="token" value={page.token} />
        <ActionGroup>
          <Button type="submit" variant="primary">
            {t('confirmLink')}
          </Button>
        </ActionGroup>
      </PostForm>
      <PostForm action="/account/identity-links/cancel" csrf={page.csrf}>
        <input type="hidden" name="token" value={page.token} />
        <ActionGroup>
          <Button type="submit" variant="link">
            {t('cancel')}
          </Button>
        </ActionGroup>
      </PostForm>
    </AppPage>
  );
}

export function UnlinkConfirmScreen({ page }: { page: PageOf<'unlink-confirm'> }) {
  return (
    <AppPage page={page} layout="form">
      <PageTitle>{t('confirmUnlinkTitle')}</PageTitle>
      <Details
        label={t('confirmUnlinkTitle')}
        items={[
          { term: t('provider'), value: page.provider },
          { term: t('issuer'), value: page.issuer },
          { term: t('subjectHint'), value: page.subjectHint },
        ]}
      />
      <Content component="p">{t('tokensRevoked')}</Content>
      <PostForm action="/account/identity-links/unlink/confirm" csrf={page.csrf}>
        <ActionGroup>
          <Button type="submit" variant="danger">
            {t('confirmUnlink')}
          </Button>
        </ActionGroup>
      </PostForm>
      <Button component="a" variant="link" href="/account/identity-links">
        {t('cancel')}
      </Button>
    </AppPage>
  );
}
