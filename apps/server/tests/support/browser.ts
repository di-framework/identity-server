/** A cookie jar over a `fetch`-shaped handler, for driving pages and redirects in tests. */
export class Browser {
  private readonly jar = new Map<string, string>();
  csrf = '';

  constructor(private readonly fetch: (request: Request) => Promise<Response>) {}

  async send(
    method: string,
    path: string,
    options: { form?: Record<string, string | string[]>; json?: boolean; csrf?: boolean } = {},
  ): Promise<Response> {
    const headers = new Headers();
    if (this.jar.size > 0) {
      headers.set('cookie', [...this.jar].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    if (options.json) headers.set('accept', 'application/json');
    let body: string | undefined;
    if (method === 'POST') {
      headers.set('content-type', 'application/x-www-form-urlencoded');
      const form = new URLSearchParams();
      for (const [key, value] of Object.entries(options.form ?? {})) {
        for (const item of Array.isArray(value) ? value : [value]) form.append(key, item);
      }
      if (options.csrf !== false) form.set('_csrf', this.csrf);
      body = form.toString();
    }
    const url = path.startsWith('http') ? path : `https://identity.test${path}`;
    const response = await this.fetch(new Request(url, { method, headers, body }));
    for (const header of response.headers.getSetCookie()) {
      const [pair = '', ...attributes] = header.split(';');
      const [name = '', value = ''] = pair.split('=');
      if (attributes.some((part) => part.trim() === 'Max-Age=0')) this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return response;
  }

  async page<T = Record<string, unknown>>(path: string): Promise<T> {
    const response = await this.send('GET', path, { json: true });
    const model = (await response.json()) as T & { csrf: string };
    this.csrf = model.csrf;
    return model;
  }

  async signIn(username: string, password: string): Promise<Response> {
    await this.page('/login');
    return this.send('POST', '/login', { form: { username, password } });
  }
}
