import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createHmac, createSign, generateKeyPairSync } from 'node:crypto';
import { encodeBase64Url } from '../../../../packages/core/src/shared/infrastructure/crypto/base64url.ts';
import { type RedTeamContext, setupRedTeamServer } from './red-team-harness.ts';

describe('Red-Team Category 2: Cryptographic & JWS Token Security', () => {
  let ctx: RedTeamContext;

  beforeAll(async () => {
    ctx = await setupRedTeamServer();
  });

  afterAll(async () => {
    await ctx?.stop();
  });

  test('Algorithm Confusion: Rejects JWS with alg="none"', async () => {
    // Construct forged token with alg: none
    const header = encodeBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: 'none', typ: 'JWT' })),
    );
    const payload = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          sub: ctx.fixtures.adminUser.id,
          iss: ctx.settings.publicOrigin,
          aud: 'https://identity.test',
          exp: Math.floor(Date.now() / 1000) + 3600,
          scope: 'admin:read admin:write',
        }),
      ),
    );
    const forgedToken = `${header}.${payload}.`;

    // Attempt to access admin API
    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${forgedToken}` },
    });
    expect(res.status).toBe(401);
  });

  test('Algorithm Confusion: Rejects JWS with alg="HS256" signed with public key', async () => {
    // Fetch JWKS to get public key
    const jwksRes = await fetch(`${ctx.baseUrl}/oauth2/jwks`);
    expect(jwksRes.status).toBe(200);
    const jwks = (await jwksRes.json()) as { keys: Array<{ kid: string; n?: string; e?: string }> };
    const activeKey = jwks.keys[0]!;

    const header = encodeBase64Url(
      new TextEncoder().encode(JSON.stringify({ alg: 'HS256', kid: activeKey.kid, typ: 'JWT' })),
    );
    const payload = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          sub: ctx.fixtures.adminUser.id,
          iss: ctx.settings.publicOrigin,
          exp: Math.floor(Date.now() / 1000) + 3600,
          scope: 'admin:read admin:write',
        }),
      ),
    );
    const unsignedPart = `${header}.${payload}`;

    // HMAC sign with the public key modulus bytes (classic HS256-on-RSA confusion attack)
    const hmacSig = createHmac('sha256', activeKey.n ?? 'fallback-key')
      .update(unsignedPart)
      .digest();
    const forgedToken = `${unsignedPart}.${encodeBase64Url(new Uint8Array(hmacSig))}`;

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${forgedToken}` },
    });
    expect(res.status).toBe(401);
  });

  test('Signature Forgery: Rejects JWS signed with an untrusted RSA private key', async () => {
    // Generate untrusted attacker keypair
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });

    const header = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({ alg: 'RS256', kid: ctx.signingKeys.kid, typ: 'JWT' }),
      ),
    );
    const payload = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          sub: ctx.fixtures.adminUser.id,
          iss: ctx.settings.publicOrigin,
          exp: Math.floor(Date.now() / 1000) + 3600,
          scope: 'admin:read admin:write',
        }),
      ),
    );
    const data = Buffer.from(`${header}.${payload}`);

    const signer = createSign('RSA-SHA256');
    signer.update(data);
    const sig = signer.sign(privateKey);
    const forgedToken = `${header}.${payload}.${encodeBase64Url(new Uint8Array(sig))}`;

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${forgedToken}` },
    });
    expect(res.status).toBe(401);
  });

  test('Payload Tampering: Changing claims invalidates legitimate signature', async () => {
    // Sign a genuine token
    const claims = {
      sub: ctx.fixtures.regularUser1.id,
      iss: ctx.settings.publicOrigin,
      exp: Math.floor(Date.now() / 1000) + 3600,
      scope: 'directory:read',
    };
    const legitimateToken = ctx.signingKeys.sign(claims);
    const [header, , signature] = legitimateToken.split('.');

    // Tamper payload to escalate to admin:write
    const tamperedPayload = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          sub: ctx.fixtures.regularUser1.id,
          iss: ctx.settings.publicOrigin,
          exp: Math.floor(Date.now() / 1000) + 3600,
          scope: 'admin:write admin:read',
        }),
      ),
    );
    const tamperedToken = `${header}.${tamperedPayload}.${signature}`;

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${tamperedToken}` },
    });
    expect(res.status).toBe(401);
  });

  test('Token Expiration: Rejects token with exp timestamp in the past', async () => {
    const expiredClaims = {
      sub: ctx.fixtures.adminUser.id,
      iss: ctx.settings.publicOrigin,
      exp: Math.floor(Date.now() / 1000) - 600, // 10 minutes ago
      scope: 'admin:read',
    };
    const expiredToken = ctx.signingKeys.sign(expiredClaims);

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${expiredToken}` },
    });
    expect(res.status).toBe(401);
  });

  test('Key ID Spoofing: Rejects token with nonexistent or malformed kid', async () => {
    const header = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({ alg: 'RS256', kid: 'kid-does-not-exist-in-jwks', typ: 'JWT' }),
      ),
    );
    const payload = encodeBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          sub: ctx.fixtures.adminUser.id,
          iss: ctx.settings.publicOrigin,
          exp: Math.floor(Date.now() / 1000) + 3600,
          scope: 'admin:read',
        }),
      ),
    );
    const forgedToken = `${header}.${payload}.invalidsignature`;

    const res = await fetch(`${ctx.baseUrl}/api/admin/users`, {
      headers: { authorization: `Bearer ${forgedToken}` },
    });
    expect(res.status).toBe(401);
  });
});
