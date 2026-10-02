import { Container } from '@di-framework/core/decorators';

/** Opaque directory cursors. A cursor is the member id packed as 16 bytes. */
@Container()
export class CursorCodec {
  encode(id: string): string {
    return Buffer.from(id.replaceAll('-', ''), 'hex').toString('base64url');
  }

  decode(value: string | undefined): { id?: string; invalid: boolean } {
    if (!value) return { invalid: false };
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length !== 16) return { invalid: true };
    const hex = bytes.toString('hex');
    const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    return { id, invalid: false };
  }

  limit(raw: string | undefined): number {
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) return 100;
    return Math.min(100, Math.max(1, Math.trunc(parsed)));
  }
}
