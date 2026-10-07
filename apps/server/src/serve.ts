import { controlPlane } from '../../api/src/control-plane.ts';
import { handle } from '../../client/src/server/handler.ts';

const ASSET_NAME = /^[A-Za-z0-9._-]+$/;

/** A directory URL, or the guest's embedded asset bytes. */
export type AssetSource = URL | ReadonlyMap<string, Uint8Array>;

/** One port: the JSON API and OAuth endpoints, static assets, then the browser pages. */
export async function routeRequest(
  request: Request,
  assets: AssetSource,
  shell?: string,
): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (controlPlane.handles(pathname)) return controlPlane.fetch(request);
  if (pathname.startsWith('/assets/')) return asset(pathname.slice('/assets/'.length), assets);
  return handle(request, undefined, shell);
}

async function asset(name: string, assets: AssetSource): Promise<Response> {
  if (!ASSET_NAME.test(name)) return new Response(null, { status: 404 });
  const headers = new Headers({
    'content-type': contentType(name),
    'x-content-type-options': 'nosniff',
    'cache-control': 'public, max-age=31536000, immutable',
  });
  if (!(assets instanceof URL)) {
    const bytes = assets.get(name);
    if (!bytes) return new Response(null, { status: 404 });
    return new Response(bytes, { headers });
  }
  const file = Bun.file(new URL(name, assets));
  if (!(await file.exists())) return new Response(null, { status: 404 });
  return new Response(file, { headers });
}

function contentType(name: string): string {
  if (name.endsWith('.css')) return 'text/css; charset=utf-8';
  if (name.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (name.endsWith('.svg')) return 'image/svg+xml';
  return 'application/octet-stream';
}
