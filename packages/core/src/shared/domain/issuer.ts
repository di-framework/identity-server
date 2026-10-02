import { Container } from '@di-framework/core/decorators';
import { IdentityError } from './identity-error.ts';

/** Canonical issuer URIs for identity links (`IdentityLinkService.canonicalizeIssuer`). */
@Container()
export class IssuerCanonicalizer {
  canonicalize(raw: string): string {
    const trimmed = raw.trim();
    if (!trimmed) throw new IdentityError(400, 'Issuer cannot be blank');
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      throw new IdentityError(400, 'Invalid issuer URI format');
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new IdentityError(400, 'Issuer URI scheme must be http or https');
    }
    if (!url.hostname) throw new IdentityError(400, 'Issuer URI must contain a host');
    if (url.search || url.hash || trimmed.endsWith('?') || trimmed.includes('#')) {
      throw new IdentityError(400, 'Issuer URI must not contain a query or fragment');
    }
    const port = url.port && url.port !== '80' && url.port !== '443' ? `:${url.port}` : '';
    const path = url.pathname === '/' ? '' : url.pathname.replace(/\/+$/, '');
    return `${url.protocol}//${url.hostname}${port}${path}`;
  }
}
