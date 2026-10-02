import { describe, expect, test } from 'bun:test';
import { createHash, createHmac } from 'node:crypto';
import { ClientSecrets } from '../src/shared/domain/client-secrets.ts';
import { manualClock, systemClock } from '../src/shared/domain/clock.ts';
import { Hashing, TOKEN_PATTERN } from '../src/shared/infrastructure/crypto/hashing.ts';
import { PasswordHasher } from '../src/shared/infrastructure/crypto/passwords.ts';
import {
  SigningKeyError,
  SigningKeys,
  verifyJws,
} from '../src/shared/infrastructure/crypto/signing-keys.ts';
import { loadIdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import { akpPrivateJwk, publicOf, rsaPrivateJwk } from './support/keys.ts';

const rsa = rsaPrivateJwk('rsa-1');
const akp = akpPrivateJwk('akp-1');

function load(active: unknown, algorithm = 'RS256', previous = ''): SigningKeys {
  return SigningKeys.load({
    activePrivate: typeof active === 'string' ? active : JSON.stringify(active),
    previousPublicSet: previous,
    signingAlgorithm: algorithm,
  });
}

describe('hashing', () => {
  test('digests, tokens, client ids, and PKCE', () => {
    expect(Hashing.sha256Hex('abc')).toBe(createHash('sha256').update('abc').digest('hex'));
    expect(Hashing.sha256('abc').length).toBe(32);
    expect(Hashing.hmacSha256Base64Url(Buffer.from('k'), 'v')).toBe(
      createHmac('sha256', 'k').update('v').digest('base64url'),
    );
    expect(Hashing.token()).toMatch(TOKEN_PATTERN);
    expect(Hashing.token(16)).toHaveLength(22);
    expect(Hashing.clientId()).toMatch(/^cli_[0-9a-f]{16}$/);
    expect(Hashing.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
    expect(Hashing.equal('a', 'a')).toBe(true);
    expect(Hashing.equal('a', 'b')).toBe(false);
    expect(Hashing.equal('a', 'ab')).toBe(false);
  });

  test('clocks', () => {
    const clock = manualClock(1000);
    clock.advance(5);
    expect(clock.now()).toBe(1005);
    clock.set(7);
    expect(clock.now()).toBe(7);
    expect(Math.abs(systemClock().now() - Date.now())).toBeLessThan(1000);
  });
});

describe('passwords', () => {
  test('Argon2id hashes in the Spring Security v5.8 PHC shape and verify', async () => {
    const hasher = new PasswordHasher();
    const hash = await hasher.hash('correct horse battery staple');
    expect(hash).toStartWith('$argon2id$v=19$m=16384,t=2,p=1$');
    expect(await hasher.verify('correct horse battery staple', hash)).toBe(true);
    expect(await hasher.verify('wrong', hash)).toBe(false);
    expect(await hasher.verify('x', null)).toBe(false);
    expect(await hasher.verify('x', 'deadbeef')).toBe(false);
    expect(await hasher.verify('x', '$argon2id$garbage')).toBe(false);
  });
});

describe('client secrets', () => {
  test('derive idempotent secrets from the active signing key', () => {
    const jwk = '{"kid":"k"}';
    const secrets = new ClientSecrets(loadIdentitySettings({ AUTH_ACTIVE_PRIVATE_JWK: jwk }));
    const key = createHash('sha256').update(`gsio-oauth-idempotency-v1\0${jwk}`).digest();
    const expected = createHmac('sha256', key).update('urn:x\0create:c').digest('base64url');
    expect(secrets.sign('urn:x', 'create:c')).toBe(expected);
    expect(secrets.sign(undefined, 'create:c')).toMatch(TOKEN_PATTERN);
    const other = new ClientSecrets(
      loadIdentitySettings({ AUTH_ACTIVE_PRIVATE_JWK: '{"kid":"z"}' }),
    );
    expect(other.sign('urn:x', 'create:c')).not.toBe(expected);
    expect(secrets.hash('a')).toBe(Hashing.sha256Hex('a'));
    expect(secrets.hint('a')).toBe(Hashing.sha256Hex('a').slice(0, 16));
  });

  test('refuse to derive a secret without an active signing key', () => {
    const secrets = new ClientSecrets(loadIdentitySettings({ AUTH_ACTIVE_PRIVATE_JWK: ' ' }));
    expect(() => secrets.sign('urn:x', 'create:c')).toThrow('AUTH_ACTIVE_PRIVATE_JWK is required');
    expect(secrets.sign(undefined, 'create:c')).toMatch(TOKEN_PATTERN);
  });
});

describe('signing keys', () => {
  test('RS256 signs with the active kid and publishes previous public keys', () => {
    const previous = rsaPrivateJwk('rsa-0');
    const previousAkp = akpPrivateJwk('akp-0');
    const keys = load(
      rsa,
      'RS256',
      JSON.stringify({ keys: [publicOf(previous), { ...publicOf(previousAkp), use: 'sig' }] }),
    );
    expect(keys.algorithm).toBe('RS256');
    expect(keys.kid).toBe('rsa-1');
    const jwks = keys.jwks().keys;
    expect(jwks.map((key) => key.kid)).toEqual(['rsa-1', 'rsa-0', 'akp-0']);
    expect(jwks[0]).toEqual({
      kty: 'RSA',
      e: rsa.e,
      n: rsa.n,
      kid: 'rsa-1',
      alg: 'RS256',
      use: 'sig',
    });
    expect(jwks[1]).toEqual({ kty: 'RSA', n: previous.n, e: previous.e, kid: 'rsa-0', use: 'sig' });
    expect(jwks[2]).toEqual({
      kty: 'AKP',
      alg: 'ML-DSA-65',
      kid: 'akp-0',
      pub: previousAkp.pub,
      use: 'sig',
      key_ops: ['verify'],
    });
    for (const key of jwks) expect(key).not.toHaveProperty('d');
    const token = keys.sign({ sub: 'u', aud: 'c' });
    const header = JSON.parse(Buffer.from(token.split('.')[0] ?? '', 'base64url').toString());
    expect(header).toEqual({ alg: 'RS256', kid: 'rsa-1', typ: 'JWT' });
    expect(verifyJws(token, jwks, ['RS256'])).toEqual({ sub: 'u', aud: 'c' });
  });

  test('ML-DSA-65 signs AKP tokens verifiable with only the public key', () => {
    const keys = load(akp, 'ML-DSA-65');
    const [active] = keys.jwks().keys;
    expect(active).toEqual({
      kty: 'AKP',
      alg: 'ML-DSA-65',
      kid: 'akp-1',
      pub: akp.pub,
      use: 'sig',
      key_ops: ['verify'],
    });
    expect(active).not.toHaveProperty('priv');
    const token = keys.sign({ sub: 'u' });
    expect(Buffer.from(token.split('.')[2] ?? '', 'base64url').length).toBe(3309);
    expect(verifyJws(token, keys.jwks().keys, ['ML-DSA-65'])).toEqual({ sub: 'u' });
  });

  test('fails closed on every invalid configuration', () => {
    const cases: Array<[unknown, string, string, string]> = [
      [rsa, 'HS256', '', 'Unsupported signing algorithm'],
      ['  ', 'RS256', '', 'AUTH_ACTIVE_PRIVATE_JWK is required'],
      ['{', 'RS256', '', 'Active private JWK is not valid JSON'],
      ['[1]', 'RS256', '', 'Active private JWK must be a JSON object'],
      [{ ...rsa, kid: ' ' }, 'RS256', '', 'must include a kid'],
      [akp, 'RS256', '', 'RS256 requires an RSA JWK'],
      [publicOf(rsa), 'RS256', '', 'must contain private material'],
      [rsa, 'ML-DSA-65', '', 'ML-DSA-65 requires an AKP JWK'],
      [{ ...akp, alg: 'ML-DSA-44' }, 'ML-DSA-65', '', 'must use alg ML-DSA-65'],
      [{ ...akp, pub: 'AAAA' }, 'ML-DSA-65', '', 'must be 1952 bytes'],
      [{ ...akp, pub: 7 }, 'ML-DSA-65', '', 'must be 1952 bytes'],
      [{ ...akp, priv: undefined }, 'ML-DSA-65', '', '32-byte private seed'],
      [{ ...akp, pub: akpPrivateJwk('other').pub }, 'ML-DSA-65', '', 'public key does not match'],
      [rsa, 'RS256', '{', 'Previous public JWK set is not valid JSON'],
      [rsa, 'RS256', '{"keys":{}}', 'must contain a keys array'],
      [rsa, 'RS256', '{"keys":[7]}', 'Previous public JWK must be an object'],
      [rsa, 'RS256', JSON.stringify({ keys: [rsa] }), 'must not contain private material'],
      [rsa, 'RS256', JSON.stringify({ keys: [akp] }), 'must not contain private material'],
      [rsa, 'RS256', '{"keys":[{"kty":"EC"}]}', 'must be RSA or AKP'],
    ];
    for (const [active, algorithm, previous, message] of cases) {
      let error: unknown;
      try {
        load(active, algorithm, previous);
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(SigningKeyError);
      expect((error as Error).message).toContain(message);
      expect((error as Error).message).not.toContain(String(rsa.d));
    }
  });

  test('verification rejects malformed, foreign, and unsigned tokens', () => {
    const keys = load(rsa);
    const token = keys.sign({ sub: 'u' });
    const [header, claims] = token.split('.') as [string, string];
    expect(() => verifyJws('a.b', keys.jwks().keys, ['RS256'])).toThrow('Malformed token');
    expect(() => verifyJws(token, keys.jwks().keys, ['ML-DSA-65'])).toThrow(
      'Unexpected signing algorithm',
    );
    expect(() => verifyJws(`${header}.${claims}.AAAA`, keys.jwks().keys, ['RS256'])).toThrow(
      'Invalid token signature',
    );
    expect(() => verifyJws(token, [publicOf(rsaPrivateJwk('rsa-1'))], ['RS256'])).toThrow(
      'Invalid token signature',
    );
    expect(() =>
      verifyJws(token, [{ kty: 'RSA', kid: 'rsa-1', n: 'x', e: 'y' }], ['RS256']),
    ).toThrow('Invalid token signature');
    const unkeyed = `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${claims}.${token.split('.')[2]}`;
    expect(() => verifyJws(unkeyed, keys.jwks().keys, ['RS256'])).toThrow(
      'Invalid token signature',
    );
    const nullClaims = `${header}.${Buffer.from('null').toString('base64url')}.x`;
    expect(() => verifyJws(nullClaims, [], ['RS256'])).toThrow('Invalid token signature');
    const primitive = `${Buffer.from('7').toString('base64url')}.${claims}.x`;
    expect(() => verifyJws(primitive, [], ['RS256'])).toThrow('Malformed token');
  });
});
