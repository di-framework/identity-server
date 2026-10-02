import { systemClock } from '../domain/clock.ts';
import { createStore } from '../domain/model.ts';
import { handle } from './handler.ts';

const dist = new URL('../../dist/', import.meta.url);
const built = await Bun.build({
  entrypoints: [new URL('../main.tsx', import.meta.url).pathname],
  outdir: dist.pathname,
  target: 'browser',
});

if (!built.success) {
  console.error(built.logs);
  process.exit(1);
}

const store = createStore(systemClock());
const port = Number(process.env.PORT ?? 4180);

Bun.serve({
  port,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/assets/')) {
      const name = url.pathname.slice('/assets/'.length);
      if (!/^[A-Za-z0-9._-]+$/.test(name)) return new Response(null, { status: 404 });
      const file = Bun.file(new URL(name, dist));
      if (!(await file.exists())) return new Response(null, { status: 404 });
      return new Response(file);
    }
    return handle(request, store);
  },
});

console.log(`identity client http://127.0.0.1:${port}`);
