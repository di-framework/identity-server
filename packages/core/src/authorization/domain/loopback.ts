/**
 * Loopback redirect URIs of public native clients (RFC 8252 section 7.3): `http` on
 * `127.0.0.1` or `[::1]`. The port is not part of the registration, because a native client
 * listens on whatever port is free when it starts.
 */
export interface LoopbackRedirect {
  host: string;
  path: string;
}

/** Host and path of an `http` URI on a loopback address, ignoring its port. */
export function parseLoopback(uri: string): LoopbackRedirect | undefined {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:') return undefined;
  if (url.hostname !== '127.0.0.1' && url.hostname !== '[::1]') return undefined;
  return { host: url.hostname, path: `${url.pathname}${url.search}` };
}

/** True when `uri` is a loopback redirect a public client may register. */
export function isLoopbackRedirect(uri: string): boolean {
  return parseLoopback(uri) !== undefined;
}
