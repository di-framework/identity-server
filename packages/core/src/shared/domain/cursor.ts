import { Container } from '@di-framework/core/decorators';
import { decodeBase64Url, encodeBase64Url } from '../infrastructure/crypto/base64url.ts';

/** Opaque directory cursors. A cursor is the member id packed as 16 bytes. */
@Container()
export class CursorCodec {
  encode(id: string): string {
    return encodeBase64Url(hexToBytes(id.replaceAll('-', '')));
  }

  decode(value: string | undefined): { id?: string; invalid: boolean } {
    if (!value) return { invalid: false };
    let bytes: Uint8Array;
    try {
      bytes = decodeBase64Url(value);
    } catch {
      return { invalid: true };
    }
    if (bytes.length !== 16) return { invalid: true };
    const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
    const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    return { id, invalid: false };
  }

  limit(raw: string | undefined): number {
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) return 100;
    return Math.min(100, Math.max(1, Math.trunc(parsed)));
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
