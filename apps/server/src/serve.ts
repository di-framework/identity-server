import { controlPlane } from '../../api/src/control-plane.ts';
import type { Store } from '../../client/src/domain/model.ts';
import { handle } from '../../client/src/server/handler.ts';

const ASSET_NAME = /^[A-Za-z0-9._-]+$/;

export async function routeRequest(request: Request, store: Store, assets: URL): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (pathname.startsWith('/api/')) return controlPlane.fetch(request);
  if (pathname.startsWith('/assets/')) return asset(pathname.slice('/assets/'.length), assets);
  return handle(request, store);
}

async function asset(name: string, assets: URL): Promise<Response> {
  if (!ASSET_NAME.test(name)) return new Response(null, { status: 404 });
  const file = Bun.file(new URL(name, assets));
  if (!(await file.exists())) return new Response(null, { status: 404 });
  return new Response(file);
}
