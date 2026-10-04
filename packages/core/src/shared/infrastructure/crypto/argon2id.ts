import { blake2b } from '@noble/hashes/blake2.js';

const MASK = (1n << 64n) - 1n;
const BLOCK_BYTES = 1024;
const WORDS = 128;
const SYNC_POINTS = 4;

export interface Argon2idOptions {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
  hashLength?: number;
  salt: Uint8Array;
  secret?: Uint8Array;
  associatedData?: Uint8Array;
}

/** Argon2id tag. `memoryCost` is kibibytes, matching `Bun.password` and Spring Security. */
export function argon2id(password: Uint8Array, options: Argon2idOptions): Uint8Array {
  const hashLength = options.hashLength ?? 32;
  const lanes = options.parallelism;
  const passes = options.timeCost;
  if (lanes < 1 || passes < 1 || hashLength < 4) throw new Error('invalid argon2 parameters');
  const blocks = 4 * lanes * Math.floor(options.memoryCost / (4 * lanes));
  if (blocks < 8 * lanes) throw new Error('argon2 memory is too small');
  const laneLength = blocks / lanes;
  const segmentLength = laneLength / SYNC_POINTS;
  const memory: BigUint64Array<ArrayBufferLike>[] = Array.from(
    { length: blocks },
    () => new BigUint64Array(WORDS),
  );
  const h0 = blake2b(
    prehash(
      password,
      options.salt,
      lanes,
      hashLength,
      options.memoryCost,
      passes,
      options.secret,
      options.associatedData,
    ),
    { dkLen: 64 },
  );
  for (let lane = 0; lane < lanes; lane += 1) {
    memory[lane * laneLength] = hashBlock(h0, 0, lane);
    memory[lane * laneLength + 1] = hashBlock(h0, 1, lane);
  }
  for (let pass = 0; pass < passes; pass += 1) {
    for (let slice = 0; slice < SYNC_POINTS; slice += 1) {
      for (let lane = 0; lane < lanes; lane += 1) {
        const addresses = dataIndependent(pass, slice)
          ? addressBlock(pass, lane, slice, blocks, passes, segmentLength)
          : undefined;
        for (let index = 0; index < segmentLength; index += 1) {
          const absolute = slice * segmentLength + index;
          if (pass === 0 && absolute < 2) continue;
          const prev = absolute === 0 ? laneLength - 1 : absolute - 1;
          const pseudo = addresses
            ? (addresses[Math.floor(index / WORDS)]?.[index % WORDS] ?? 0n)
            : (memory[lane * laneLength + prev]?.[0] ?? 0n);
          const refLane = pass === 0 && slice === 0 ? lane : Number(pseudo >> 32n) % lanes;
          const refIndex = indexAlpha(
            pass,
            slice,
            index,
            lane === refLane,
            segmentLength,
            laneLength,
            Number(pseudo & 0xffffffffn),
          );
          const next = compress(
            memory[lane * laneLength + prev] ?? zero(),
            memory[refLane * laneLength + refIndex] ?? zero(),
          );
          const current = lane * laneLength + absolute;
          memory[current] = pass === 0 ? next : xorBlock(memory[current] ?? zero(), next);
        }
      }
    }
  }
  let final = memory[laneLength - 1] ?? zero();
  for (let lane = 1; lane < lanes; lane += 1) {
    final = xorBlock(final, memory[lane * laneLength + laneLength - 1] ?? zero());
  }
  return hashVariable(bytesOf(final), hashLength);
}

/** PHC string with the Spring Security v5.8 parameters and a fresh 16-byte salt. */
export function argon2idPhc(password: string, salt = randomSalt()): string {
  const tag = argon2id(new TextEncoder().encode(password), {
    memoryCost: 16384,
    timeCost: 2,
    parallelism: 1,
    salt,
  });
  return `$argon2id$v=19$m=16384,t=2,p=1$${phc64(salt)}$${phc64(tag)}`;
}

export function argon2idVerify(password: string, phc: string): boolean {
  const match =
    /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(phc);
  if (!match) return false;
  const memoryCost = Number(match[1]);
  const timeCost = Number(match[2]);
  const parallelism = Number(match[3]);
  const salt = phc64Decode(match[4] ?? '');
  const expected = phc64Decode(match[5] ?? '');
  if (salt.length === 0 || expected.length === 0) return false;
  let actual: Uint8Array;
  try {
    actual = argon2id(new TextEncoder().encode(password), {
      memoryCost,
      timeCost,
      parallelism,
      hashLength: expected.length,
      salt,
    });
  } catch {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < actual.length; index += 1)
    diff |= (actual[index] ?? 0) ^ (expected[index] ?? 0);
  return diff === 0;
}

function randomSalt(): Uint8Array {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return salt;
}

function dataIndependent(pass: number, slice: number): boolean {
  return pass === 0 && slice < 2;
}

function addressBlock(
  pass: number,
  lane: number,
  slice: number,
  blocks: number,
  passes: number,
  segmentLength: number,
): BigUint64Array[] {
  const input = new BigUint64Array(WORDS);
  input[0] = BigInt(pass);
  input[1] = BigInt(lane);
  input[2] = BigInt(slice);
  input[3] = BigInt(blocks);
  input[4] = BigInt(passes);
  input[5] = 2n;
  const count = Math.ceil(segmentLength / WORDS);
  const out: BigUint64Array[] = [];
  for (let block = 1; block <= count; block += 1) {
    input[6] = BigInt(block);
    out.push(compress(zero(), compress(zero(), input)));
  }
  return out;
}

function indexAlpha(
  pass: number,
  slice: number,
  index: number,
  sameLane: boolean,
  segmentLength: number,
  laneLength: number,
  pseudo: number,
): number {
  let area: number;
  if (pass === 0) {
    if (slice === 0) area = index - 1;
    else if (sameLane) area = slice * segmentLength + index - 1;
    else area = slice * segmentLength + (index === 0 ? -1 : 0);
  } else if (sameLane) {
    area = laneLength - segmentLength + index - 1;
  } else {
    area = laneLength - segmentLength + (index === 0 ? -1 : 0);
  }
  if (area < 1) area = 1;
  const square = BigInt(pseudo >>> 0) ** 2n;
  const offset = area - 1 - Number((BigInt(area) * (square >> 32n)) >> 32n);
  const start = pass === 0 || slice === SYNC_POINTS - 1 ? 0 : (slice + 1) * segmentLength;
  return (start + offset) % laneLength;
}

function prehash(
  password: Uint8Array,
  salt: Uint8Array,
  lanes: number,
  hashLength: number,
  memory: number,
  passes: number,
  secret: Uint8Array = new Uint8Array(),
  associated: Uint8Array = new Uint8Array(),
): Uint8Array {
  const input = concat(
    le32(lanes),
    le32(hashLength),
    le32(memory),
    le32(passes),
    le32(0x13),
    le32(2),
    le32(password.length),
    password,
    le32(salt.length),
    salt,
    le32(secret.length),
    secret,
    le32(associated.length),
    associated,
  );
  return input;
}

function hashBlock(h0: Uint8Array, column: number, lane: number): BigUint64Array {
  return wordsOf(hashVariable(concat(h0, le32(column), le32(lane)), BLOCK_BYTES));
}

function hashVariable(input: Uint8Array, length: number): Uint8Array {
  if (length <= 64) return blake2b(concat(le32(length), input), { dkLen: length });
  const blocks = Math.ceil(length / 32) - 2;
  let v = blake2b(concat(le32(length), input), { dkLen: 64 });
  const out = new Uint8Array(length);
  out.set(v.subarray(0, 32), 0);
  for (let index = 1; index < blocks; index += 1) {
    v = blake2b(v, { dkLen: 64 });
    out.set(v.subarray(0, 32), index * 32);
  }
  const last = blake2b(v, { dkLen: length - 32 * blocks });
  out.set(last, blocks * 32);
  return out;
}

function compress(x: BigUint64Array, y: BigUint64Array): BigUint64Array {
  const r = xorBlock(x, y);
  const q = new BigUint64Array(WORDS);
  for (let row = 0; row < 8; row += 1) {
    const state = words(r, row * 16, 16);
    permute(state);
    for (let index = 0; index < 16; index += 1) q[row * 16 + index] = state[index] ?? 0n;
  }
  const z = new BigUint64Array(WORDS);
  for (let column = 0; column < 8; column += 1) {
    const state: bigint[] = [];
    for (let row = 0; row < 8; row += 1) {
      state.push(q[row * 16 + column * 2] ?? 0n, q[row * 16 + column * 2 + 1] ?? 0n);
    }
    permute(state);
    for (let row = 0; row < 8; row += 1) {
      z[row * 16 + column * 2] = state[row * 2] ?? 0n;
      z[row * 16 + column * 2 + 1] = state[row * 2 + 1] ?? 0n;
    }
  }
  return xorBlock(z, r);
}

function words(block: BigUint64Array, offset: number, count: number): bigint[] {
  return Array.from({ length: count }, (_, index) => block[offset + index] ?? 0n);
}

function permute(v: bigint[]): void {
  blake(v, 0, 4, 8, 12);
  blake(v, 1, 5, 9, 13);
  blake(v, 2, 6, 10, 14);
  blake(v, 3, 7, 11, 15);
  blake(v, 0, 5, 10, 15);
  blake(v, 1, 6, 11, 12);
  blake(v, 2, 7, 8, 13);
  blake(v, 3, 4, 9, 14);
}

function blake(v: bigint[], a: number, b: number, c: number, d: number): void {
  mix(v, a, b, c, d, 32n, 24n);
  mix(v, a, b, c, d, 16n, 63n);
}

function word(block: ArrayLike<bigint>, index: number): bigint {
  return block[index] ?? 0n;
}

function mix(
  v: bigint[],
  a: number,
  b: number,
  c: number,
  d: number,
  rd: bigint,
  rb: bigint,
): void {
  const low = (value: bigint) => value & 0xffffffffn;
  v[a] = (word(v, a) + word(v, b) + 2n * low(word(v, a)) * low(word(v, b))) & MASK;
  v[d] = rotr((word(v, d) ^ word(v, a)) & MASK, rd);
  v[c] = (word(v, c) + word(v, d) + 2n * low(word(v, c)) * low(word(v, d))) & MASK;
  v[b] = rotr((word(v, b) ^ word(v, c)) & MASK, rb);
}

function rotr(value: bigint, bits: bigint): bigint {
  return ((value >> bits) | (value << (64n - bits))) & MASK;
}

function xorBlock(left: BigUint64Array, right: BigUint64Array): BigUint64Array {
  const out = new BigUint64Array(WORDS);
  for (let index = 0; index < WORDS; index += 1) {
    out[index] = (word(left, index) ^ word(right, index)) & MASK;
  }
  return out;
}

function zero(): BigUint64Array {
  return new BigUint64Array(WORDS);
}

function wordsOf(bytes: Uint8Array): BigUint64Array {
  const words = new BigUint64Array(WORDS);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let index = 0; index < WORDS; index += 1) words[index] = view.getBigUint64(index * 8, true);
  return words;
}

function bytesOf(words: BigUint64Array): Uint8Array {
  const bytes = new Uint8Array(BLOCK_BYTES);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < WORDS; index += 1)
    view.setBigUint64(index * 8, words[index] ?? 0n, true);
  return bytes;
}

function le32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function phc64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replaceAll('=', '');
}

function phc64Decode(value: string): Uint8Array {
  const pad = value.length % 4 === 0 ? '' : '='.repeat(4 - (value.length % 4));
  return new Uint8Array(Buffer.from(value + pad, 'base64'));
}
