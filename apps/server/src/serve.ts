import { controlPlane } from '../../api/src/control-plane.ts';
import { handle } from '../../client/src/server/handler.ts';

const ASSET_NAME = /^[A-Za-z0-9._-]+$/;

/** One port: the JSON API and OAuth endpoints, static assets, then the browser pages. */
export async function routeRequest(request: Request, assets: URL): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (controlPlane.handles(pathname)) return controlPlane.fetch(request);
  if (pathname.startsWith('/assets/')) return asset(pathname.slice('/assets/'.length), assets);
  return handle(request);
}

async function asset(name: string, assets: URL): Promise<Response> {
  if (!ASSET_NAME.test(name)) return new Response(null, { status: 404 });
  const file = Bun.file(new URL(name, assets));
  if (!(await file.exists())) return new Response(null, { status: 404 });
  return new Response(file);
}
