#!/usr/bin/env bun
/**
 * Runs the guest's database-backed flows against a deployed identity workload.
 *
 *   bun apps/guest/scripts/live-check.ts --values <file> --url <gateway> --host <workload host> \
 *     --slug <new organization slug> [--read-only]
 *
 * `--values` is the runtime secrets file deploy/guest/deploy.sh applied (mode 0600, checked) (bootstrap owner password
 * and client secrets come from it). Requests go to `--url` with `Host: <--host>`, for example
 * `--url http://127.0.0.1:28380 --host identity.pgprove.localhost`. Without `--read-only` it
 * creates the organization `--slug` and runs the authorization-code checks (tests/support/flows.ts:
 * the HTTP-only assertions of apps/server/tests/authorization-code.test.ts); with it, it checks
 * that the organization exists and the owner can sign in, which is the check after a restart. Prints status codes and names only, never a secret.
 */
import { readFileSync, statSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  assertPrivateMode,
  parseRuntimeValues,
} from '../../../deploy/platform/components/control-secret.ts';
import {
  authorizationCodeChecks,
  identityFlows,
  loginFlow,
  readiness,
} from '../tests/support/flows.ts';

const { values: args } = parseArgs({
  options: {
    values: { type: 'string' },
    url: { type: 'string' },
    host: { type: 'string' },
    slug: { type: 'string' },
    'read-only': { type: 'boolean', default: false },
  },
});
for (const name of ['values', 'url', 'host', 'slug'] as const) {
  if (!args[name]) throw new Error(`--${name} is required`);
}
assertPrivateMode(statSync(args.values as string).mode, args.values as string);
const secrets = parseRuntimeValues(
  readFileSync(args.values as string, 'utf8'),
  args.values as string,
);
const base = new URL(args.url as string);
const host = args.host as string;

/** Rewrites the flows' `https://identity.test` URLs onto the gateway with the workload's Host. */
async function send(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const target = new URL(`${url.pathname}${url.search}`, base);
  const headers = new Headers(request.headers);
  headers.set('host', host);
  const body =
    request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
  return fetch(target, { method: request.method, headers, body, redirect: 'manual' });
}

const inputs = {
  fetch: send,
  ownerLogin: 'owner',
  ownerPassword: secrets.AUTH_BOOTSTRAP_OWNER_PASSWORD ?? '',
  accessClient: {
    id: 'access',
    secret: secrets.AUTH_ACCESS_CLIENT_SECRET ?? '',
    redirectUri: (secrets.AUTH_ACCESS_REDIRECT_URIS ?? '').split(',')[0] ?? '',
  },
  provisionerClient: { id: 'provisioner', secret: secrets.AUTH_PROVISIONER_CLIENT_SECRET ?? '' },
  organizationSlug: args.slug as string,
};

const started = performance.now();
if (args['read-only']) {
  const ready = await readiness(send);
  const token = await send(
    new Request('https://identity.test/oauth2/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`provisioner:${inputs.provisionerClient.secret}`).toString('base64')}`,
      },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'admin:read' }),
    }),
  );
  const { access_token: accessToken } = (await token.json()) as { access_token: string };
  const read = await send(
    new Request(`https://identity.test/api/admin/organizations/${inputs.organizationSlug}`, {
      headers: { authorization: `Bearer ${accessToken}` },
    }),
  );
  const login = await loginFlow(inputs);
  console.log(
    JSON.stringify(
      {
        ready,
        token: token.status,
        organizationRead: read.status,
        login,
        ms: Math.round(performance.now() - started),
      },
      null,
      2,
    ),
  );
  if (ready.status !== 200 || read.status !== 200) process.exit(1);
} else {
  const report = await identityFlows(inputs);
  const authorizationCode = await authorizationCodeChecks(inputs);
  console.log(
    JSON.stringify(
      { ...report, authorizationCode, ms: Math.round(performance.now() - started) },
      null,
      2,
    ),
  );
}
