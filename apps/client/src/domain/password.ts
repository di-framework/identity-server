export const MIN_PASSWORD_LENGTH = 12;

export function hashPassword(password: string): string {
  return new Bun.CryptoHasher('sha256').update(password).digest('hex');
}

export function passwordMatches(password: string, hash: string | null): boolean {
  if (!hash) return false;
  return hashPassword(password) === hash;
}
