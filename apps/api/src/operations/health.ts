import { Component, Container } from '@di-framework/core/decorators';
import { Readiness } from '@di-framework/identity/src/bootstrap/application/readiness.ts';

/** `GET /health` (always `{"ok":true}`) and `GET /ready` (200 or 503 with each check). */
@Container()
export class OperationsEndpoints {
  constructor(@Component(Readiness) private readonly readiness: Readiness) {}

  handles(pathname: string): boolean {
    return pathname === '/health' || pathname === '/ready';
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'GET') {
      return new Response(null, { status: 405, headers: { allow: 'GET' } });
    }
    if (new URL(request.url).pathname === '/health') return Response.json({ ok: true });
    const report = await this.readiness.check();
    return Response.json(report, { status: report.ok ? 200 : 503 });
  }
}
