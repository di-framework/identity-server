import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Hashing } from '../../../../packages/core/src/shared/infrastructure/crypto/hashing.ts';
import { issueAuthCode, type RedTeamContext, setupRedTeamServer } from './red-team-harness.ts';

describe('Red-Team Category 1: OAuth2 & OIDC Security', () => {
  let ctx: RedTeamContext;

  beforeAll(async () => {
    ctx = await setupRedTeamServer();
  });

  afterAll(async () => {
    await ctx?.stop();
  });

  test('PKCE Enforcement: Public client rejects authorization code exchange without code_verifier', async () => {
    const { publicPkceClient, regularUser1 } = ctx.fixtures;
    const verifier = Hashing.token(32);
    const challenge = Hashing.pkceChallenge(verifier);

    // 1. Obtain authorization code with PKCE
    const { code } = await issueAuthCode(ctx, {
      client: publicPkceClient,
      user: regularUser1,
      codeChallenge: challenge,
    });
    expect(code).toBeTruthy();

    // Probe 1: Attack without client auth -> 401 invalid_client
    const unauthRes = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: publicPkceClient.clientId,
        code,
        redirect_uri: publicPkceClient.redirectUris[0]!,
      }),
    });
    expect(unauthRes.status).toBe(401);

    // Probe 2: Authenticated client but missing code_verifier -> 400 invalid_grant
    const attackRes = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: publicPkceClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: publicPkceClient.redirectUris[0]!,
      }),
    });
    expect(attackRes.status).toBe(400);
    const attackBody = (await attackRes.json()) as { error: string };
    expect(attackBody.error).toBe('invalid_grant');
  });

  test('PKCE Downgrade: Rejects code_verifier that fails S256 verification or tampered verifier', async () => {
    const { publicPkceClient, regularUser1 } = ctx.fixtures;
    const verifier = Hashing.token(32);
    const challenge = Hashing.pkceChallenge(verifier);

    const { code } = await issueAuthCode(ctx, {
      client: publicPkceClient,
      user: regularUser1,
      codeChallenge: challenge,
    });
    expect(code).toBeTruthy();

    // Probe: Attempt exchange with tampered/wrong verifier
    const tamperedRes = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: publicPkceClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: publicPkceClient.redirectUris[0]!,
        code_verifier: 'attacker-wrong-verifier-12345678901234567890',
      }),
    });
    expect(tamperedRes.status).toBe(400);
    const body = (await tamperedRes.json()) as { error: string };
    expect(body.error).toBe('invalid_grant');
  });

  test('Authorization Code Replay Attack: Reusing an already-exchanged code is rejected', async () => {
    const { publicPkceClient, regularUser1 } = ctx.fixtures;
    const verifier = Hashing.token(32);
    const challenge = Hashing.pkceChallenge(verifier);

    const { code } = await issueAuthCode(ctx, {
      client: publicPkceClient,
      user: regularUser1,
      codeChallenge: challenge,
    });
    expect(code).toBeTruthy();

    // First exchange (legitimate)
    const validExchange = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: publicPkceClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: publicPkceClient.redirectUris[0]!,
        code_verifier: verifier,
      }),
    });
    expect(validExchange.status).toBe(200);

    // Second exchange (replay probe)
    const replayExchange = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: publicPkceClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: publicPkceClient.redirectUris[0]!,
        code_verifier: verifier,
      }),
    });
    expect(replayExchange.status).toBe(400);
    const replayBody = (await replayExchange.json()) as { error: string };
    expect(replayBody.error).toBe('invalid_grant');
  });

  test('Cross-Client Code Theft: Client B cannot exchange an authorization code issued to Client A', async () => {
    const { publicPkceClient, confidentialClient, regularUser1 } = ctx.fixtures;
    const verifier = Hashing.token(32);
    const challenge = Hashing.pkceChallenge(verifier);

    // Code issued to publicPkceClient
    const { code } = await issueAuthCode(ctx, {
      client: publicPkceClient,
      user: regularUser1,
      codeChallenge: challenge,
    });
    expect(code).toBeTruthy();

    // Confidential client attempts to redeem public client's code
    const stolenExchange = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: confidentialClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: publicPkceClient.redirectUris[0]!,
        code_verifier: verifier,
      }),
    });
    expect(stolenExchange.status).toBe(400);
    const stolenBody = (await stolenExchange.json()) as { error: string };
    expect(stolenBody.error).toBe('invalid_grant');
  });

  test('Redirect URI Mismatch: Token exchange fails if redirect_uri does not match authorization step', async () => {
    const { publicPkceClient, regularUser1 } = ctx.fixtures;
    const verifier = Hashing.token(32);
    const challenge = Hashing.pkceChallenge(verifier);

    const { code } = await issueAuthCode(ctx, {
      client: publicPkceClient,
      user: regularUser1,
      codeChallenge: challenge,
    });
    expect(code).toBeTruthy();

    // Probe: Swap redirect_uri during token exchange
    const mismatchRes = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: publicPkceClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://attacker.example/hijack',
        code_verifier: verifier,
      }),
    });
    expect(mismatchRes.status).toBe(400);
    const body = (await mismatchRes.json()) as { error: string };
    expect(body.error).toBe('invalid_grant');
  });

  test('Client Authentication: Rejects forged or invalid client credentials', async () => {
    const { confidentialClient } = ctx.fixtures;

    // Probe 1: Wrong password / secret
    const badSecretAuth = Buffer.from(`${confidentialClient.clientId}:WrongPassword123!`).toString(
      'base64',
    );
    const res1 = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${badSecretAuth}`,
      },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'admin:read' }),
    });
    expect(res1.status).toBe(401);
    expect(((await res1.json()) as { error: string }).error).toBe('invalid_client');

    // Probe 2: Non-existent client ID
    const nonExistentAuth = Buffer.from('cli_nonexistent_12345:someSecret').toString('base64');
    const res2 = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${nonExistentAuth}`,
      },
      body: new URLSearchParams({ grant_type: 'client_credentials' }),
    });
    expect(res2.status).toBe(401);
    expect(((await res2.json()) as { error: string }).error).toBe('invalid_client');

    // Probe 3: Malformed Basic Auth (no colon separator)
    const malformedAuth = Buffer.from('usernameOnlyWithoutColon').toString('base64');
    const res3 = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${malformedAuth}`,
      },
      body: new URLSearchParams({ grant_type: 'client_credentials' }),
    });
    expect(res3.status).toBe(401);
  });

  test('Token Revocation: Revoked access token is immediately rejected at /userinfo', async () => {
    const { confidentialClient } = ctx.fixtures;

    // 1. Issue token via client_credentials
    const tokenRes = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: confidentialClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'openid admin:read',
      }),
    });
    expect(tokenRes.status).toBe(200);
    const tokenBody = (await tokenRes.json()) as { access_token: string };
    const accessToken = tokenBody.access_token;

    // 2. Introspect: active
    const intro1 = await fetch(`${ctx.baseUrl}/oauth2/introspect`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: confidentialClient.basic,
      },
      body: new URLSearchParams({ token: accessToken }),
    });
    expect(intro1.status).toBe(200);
    expect(((await intro1.json()) as { active: boolean }).active).toBe(true);

    // 3. Revoke token
    const revokeRes = await fetch(`${ctx.baseUrl}/oauth2/revoke`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: confidentialClient.basic,
      },
      body: new URLSearchParams({ token: accessToken }),
    });
    expect(revokeRes.status).toBe(200);

    // 4. Introspect again: inactive
    const intro2 = await fetch(`${ctx.baseUrl}/oauth2/introspect`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: confidentialClient.basic,
      },
      body: new URLSearchParams({ token: accessToken }),
    });
    expect(intro2.status).toBe(200);
    expect(((await intro2.json()) as { active: boolean }).active).toBe(false);

    // 5. Userinfo call with revoked token
    const userinfoRes = await fetch(`${ctx.baseUrl}/userinfo`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(userinfoRes.status).toBe(401);
  });

  test('UserInfo Endpoint: Rejects tokens without openid scope', async () => {
    const { backendClient } = ctx.fixtures;

    // Issue token with only directory:read (no openid)
    const tokenRes = await fetch(`${ctx.baseUrl}/oauth2/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: backendClient.basic,
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'directory:read',
      }),
    });
    expect(tokenRes.status).toBe(200);
    const token = ((await tokenRes.json()) as { access_token: string }).access_token;

    // Call /userinfo
    const userinfoRes = await fetch(`${ctx.baseUrl}/userinfo`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(userinfoRes.status).toBe(403);
    expect(userinfoRes.headers.get('www-authenticate')).toContain('insufficient_scope');
  });
});
