import { expect, test } from 'bun:test';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import {
  argon2id,
  argon2idPhc,
  argon2idVerify,
} from '../src/shared/infrastructure/crypto/argon2id.ts';
import { decodeBase64Url, encodeBase64Url } from '../src/shared/infrastructure/crypto/base64url.ts';
import { mlDsaVerify } from '../src/shared/infrastructure/crypto/mldsa.ts';
import { hashPassword, verifyPassword } from '../src/shared/infrastructure/crypto/passwords.ts';
import { rs256Sign, rs256Signer, rs256Verify } from '../src/shared/infrastructure/crypto/rsa.ts';
import { SigningKeys, verifyJws } from '../src/shared/infrastructure/crypto/signing-keys.ts';
import { akpPrivateJwk, publicOf, rsaPrivateJwk } from './support/keys.ts';

const rfc = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';

test('argon2id matches the RFC 9106 vector and Bun passwords', async () => {
  const tag = argon2id(new Uint8Array(32).fill(1), {
    memoryCost: 32,
    timeCost: 3,
    parallelism: 4,
    salt: new Uint8Array(16).fill(2),
    secret: new Uint8Array(8).fill(3),
    associatedData: new Uint8Array(12).fill(4),
  });
  expect(Buffer.from(tag).toString('hex')).toBe(rfc);
  expect(() =>
    argon2id(new Uint8Array(), {
      memoryCost: 32,
      timeCost: 0,
      parallelism: 1,
      salt: new Uint8Array(8),
    }),
  ).toThrow('invalid argon2 parameters');
  expect(() =>
    argon2id(new Uint8Array(), {
      memoryCost: 4,
      timeCost: 1,
      parallelism: 1,
      salt: new Uint8Array(8),
    }),
  ).toThrow('argon2 memory is too small');
  const salt = Buffer.from('0123456789abcdef');
  const phc = argon2idPhc('correct horse battery staple', salt);
  expect(phc).toStartWith('$argon2id$v=19$m=16384,t=2,p=1$');
  expect(argon2idVerify('correct horse battery staple', phc)).toBe(true);
  expect(argon2idVerify('nope', phc)).toBe(false);
  expect(argon2idVerify('x', 'nope')).toBe(false);
  expect(argon2idVerify('x', '$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aaaa')).toBe(false);
  expect(await Bun.password.verify('correct horse battery staple', phc)).toBe(true);
  const generated = await hashPassword('another-password-value', undefined);
  expect(await verifyPassword('another-password-value', generated, undefined)).toBe(true);
  expect(await verifyPassword('nope', generated, undefined)).toBe(false);
  expect(
    await verifyPassword('x', generated, {
      hash: async () => '',
      verify: async () => {
        throw new Error('down');
      },
    }),
  ).toBe(false);
  expect(
    await verifyPassword(
      'another-password-value',
      argon2idPhc('another-password-value'),
      undefined,
    ),
  ).toBe(true);
  const tiny = argon2id(new Uint8Array([1]), {
    memoryCost: 8,
    timeCost: 1,
    parallelism: 1,
    hashLength: 4,
    salt: new Uint8Array(8).fill(9),
  });
  expect(tiny).toHaveLength(4);
}, 30_000);

test('RS256 and ML-DSA signatures verify with node:crypto', () => {
  const rsa = rsaPrivateJwk('rsa-portable');
  const message = new Uint8Array(Buffer.from('header.payload'));
  const signature = rs256Sign(message, { n: String(rsa.n), e: String(rsa.e), d: String(rsa.d) });
  const privateKey = createPrivateKey({ key: rsa as never, format: 'jwk' });
  const publicKey = createPublicKey(privateKey);
  expect(verify('sha256', message, publicKey, signature)).toBe(true);
  const nodeSignature = new Uint8Array(sign('sha256', message, privateKey));
  expect(rs256Verify(message, nodeSignature, { n: String(rsa.n), e: String(rsa.e) })).toBe(true);
  expect(
    rs256Verify(message, new Uint8Array([1, 2, 3]), { n: String(rsa.n), e: String(rsa.e) }),
  ).toBe(false);
  expect(rs256Verify(message, signature, { n: '%%%', e: 'AQAB' })).toBe(false);

  const akp = akpPrivateJwk('akp-portable');
  const keys = SigningKeys.load({
    activePrivate: JSON.stringify(akp),
    previousPublicSet: '',
    signingAlgorithm: 'ML-DSA-65',
  });
  const token = keys.sign({ sub: 'u' });
  const nodePublic = createPublicKey({ key: publicOf(akp) as never, format: 'jwk' });
  expect(
    verify(
      null,
      Buffer.from(token.split('.').slice(0, 2).join('.')),
      nodePublic,
      Buffer.from(token.split('.')[2] ?? '', 'base64url'),
    ),
  ).toBe(true);
  expect(mlDsaVerify(message, new Uint8Array([1]), new Uint8Array(8))).toBe(false);
  expect(verifyJws(token, keys.jwks().keys, ['ML-DSA-65']).sub).toBe('u');
});

test('RS256 signs natively when it can, else portably with blinding and CRT', () => {
  const rsa = rsaPrivateJwk('rsa-crt');
  const jwk = {
    n: String(rsa.n),
    e: String(rsa.e),
    d: String(rsa.d),
    p: String(rsa.p),
    q: String(rsa.q),
    dp: String(rsa.dp),
    dq: String(rsa.dq),
    qi: String(rsa.qi),
  };
  const message = new Uint8Array(Buffer.from('header.payload'));
  // PKCS#1 v1.5 is deterministic, so every path must produce OpenSSL's exact signature.
  const expected = new Uint8Array(
    sign('sha256', message, createPrivateKey({ key: rsa as never, format: 'jwk' })),
  );
  expect(rs256Signer(jwk)(message)).toEqual(expected);
  // The guest has no native RSA: blinded CRT, unblinded back to the same signature.
  expect(rs256Signer(jwk, null)(message)).toEqual(expected);
  // Without CRT parameters the native importer refuses the key, and signing stays portable.
  expect(rs256Signer({ n: jwk.n, e: jwk.e, d: jwk.d })(message)).toEqual(expected);
  // A faulty CRT step fails the public-exponent check instead of releasing a signature.
  expect(() => rs256Sign(message, { ...jwk, dp: jwk.dq })).toThrow(
    'RSA signature failed its check',
  );
});

test('base64url matches node and rejects bad input', () => {
  for (const size of [0, 1, 2, 3, 32]) {
    const bytes = Uint8Array.from({ length: size }, (_, index) => index + 7);
    const encoded = encodeBase64Url(bytes);
    expect(encoded).toBe(Buffer.from(bytes).toString('base64url'));
    expect(decodeBase64Url(encoded)).toEqual(bytes);
  }
  expect(() => decodeBase64Url('a')).toThrow('invalid base64url');
  expect(() => decodeBase64Url('ab+c')).toThrow('invalid base64url');
});
