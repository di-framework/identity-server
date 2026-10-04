import net, { type Socket } from 'node:net';
import type { MailMessage, MailSender } from '../domain/mail.ts';

export interface SmtpOptions {
  host: string;
  port: number;
  username: string;
  password: string;
  from: string;
  /** Authenticate with AUTH PLAIN or AUTH LOGIN when a username is set. */
  auth: boolean;
  /** Upgrade with STARTTLS when the server offers it (JavaMail `starttls.enable`). */
  starttls: boolean;
  /** Implicit TLS from the first byte (JavaMail `ssl.enable`). */
  ssl: boolean;
  /** TLS options; certificate verification is on unless `rejectUnauthorized` is false. */
  tls?: { rejectUnauthorized?: boolean; ca?: string };
  timeoutMs?: number;
  /** Name sent in EHLO. */
  clientName?: string;
}

/** SMTP failure. Messages carry the reply code only, never recipients or content. */
export class SmtpError extends Error {
  constructor(
    message: string,
    readonly code?: number,
  ) {
    super(message);
    this.name = 'SmtpError';
  }
}

interface Reply {
  code: number;
  lines: string[];
}

type TlsConnect = (options: {
  host?: string;
  port?: number;
  servername?: string;
  socket?: Socket;
  rejectUnauthorized?: boolean;
  ca?: string;
}) => Socket;

/**
 * `node:tls` when the host linked it. A variable specifier keeps the guest bundle from importing
 * `wasi:tls` until a relay actually asks for TLS; a host without that link fails the send.
 */
export async function loadSmtpTls(
  load: () => Promise<{ connect: TlsConnect }> = loadNodeTls,
): Promise<{ connect: TlsConnect }> {
  try {
    const loaded = await load();
    if (typeof loaded.connect !== 'function') throw new Error('missing connect');
    return loaded;
  } catch {
    throw new SmtpError('SMTP TLS is not available');
  }
}

async function loadNodeTls(): Promise<{ connect: TlsConnect }> {
  const specifier = 'node:tls';
  return (await import(specifier)) as { connect: TlsConnect };
}

/** Minimal RFC 5321 client on `node:net`: EHLO, STARTTLS, AUTH, MAIL, RCPT, DATA, QUIT. */
export class SmtpMailSender implements MailSender {
  constructor(private readonly options: SmtpOptions) {}

  async send(message: MailMessage): Promise<void> {
    const session = await SmtpSession.open(this.options);
    try {
      await session.deliver(message);
    } finally {
      session.close();
    }
  }
}

/** Formats a plain-text message with base64 body so any server accepts it as 7-bit. */
export function formatMessage(
  from: string,
  message: MailMessage,
  date = new Date(),
  id: string = crypto.randomUUID(),
): string {
  const domain = from.includes('@') ? from.slice(from.lastIndexOf('@') + 1) : 'localhost';
  const body = Buffer.from(message.text.replaceAll(/\r?\n/g, '\r\n'), 'utf8')
    .toString('base64')
    .replaceAll(/(.{76})/g, '$1\r\n');
  return [
    `From: ${header(from)}`,
    `To: ${header(message.to)}`,
    `Subject: ${encodedWord(header(message.subject))}`,
    `Date: ${date.toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: <${id}@${header(domain)}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    body,
  ].join('\r\n');
}

function header(value: string): string {
  return value.replaceAll(/[\r\n]+/g, ' ').trim();
}

function encodedWord(value: string): string {
  if (/^[\x20-\x7e]*$/.test(value)) return value;
  return `=?UTF-8?B?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

class SmtpSession {
  private buffer = '';
  private waiting: ((reply: Reply | Error) => void) | undefined;
  private failure: Error | undefined;
  private active: Socket;

  private constructor(
    private readonly options: SmtpOptions,
    socket: Socket,
  ) {
    this.active = socket;
  }

  static async open(options: SmtpOptions): Promise<SmtpSession> {
    const socket = options.ssl ? await connectTls(options) : await connectPlain(options);
    const session = new SmtpSession(options, socket);
    session.watch(socket);
    return session;
  }

  async deliver(message: MailMessage): Promise<void> {
    await this.expect(await this.reply(), [220]);
    await this.ehlo();
    if (this.options.starttls && !this.options.ssl && this.offers('STARTTLS')) {
      await this.command('STARTTLS', [220]);
      await this.upgrade();
      await this.ehlo();
    }
    if (this.options.auth && this.options.username) await this.authenticate();
    await this.command(`MAIL FROM:<${header(this.options.from)}>`, [250]);
    await this.command(`RCPT TO:<${header(message.to)}>`, [250, 251]);
    await this.command('DATA', [354]);
    const data = formatMessage(this.options.from, message)
      .split('\r\n')
      .map((line) => (line.startsWith('.') ? `.${line}` : line))
      .join('\r\n');
    await this.command(`${data}\r\n.`, [250]);
    await this.command('QUIT', [221]).catch(() => undefined);
  }

  close(): void {
    this.active.end();
  }

  private async ehlo(): Promise<void> {
    const reply = await this.command(`EHLO ${this.options.clientName ?? 'identity'}`, [250]);
    this.capabilities = reply.lines.slice(1).map((line) => line.toUpperCase());
  }

  private capabilities: string[] = [];

  private offers(extension: string): boolean {
    return this.capabilities.some((line) => line === extension || line.startsWith(`${extension} `));
  }

  private async authenticate(): Promise<void> {
    const mechanisms = this.capabilities.find((line) => line.startsWith('AUTH '))?.split(' ') ?? [];
    const { username, password } = this.options;
    if (mechanisms.includes('PLAIN') || !mechanisms.includes('LOGIN')) {
      const token = Buffer.from(`\0${username}\0${password}`, 'utf8').toString('base64');
      await this.command(`AUTH PLAIN ${token}`, [235]);
      return;
    }
    await this.command('AUTH LOGIN', [334]);
    await this.command(Buffer.from(username, 'utf8').toString('base64'), [334]);
    await this.command(Buffer.from(password, 'utf8').toString('base64'), [235]);
  }

  private async upgrade(): Promise<void> {
    const tls = await loadSmtpTls();
    this.unwatch(this.active);
    // Bytes after the 220 arrived in plaintext; read as TLS replies they would let anyone on
    // the path forge the post-upgrade EHLO (STARTTLS response injection).
    if (this.buffer !== '') throw new SmtpError('SMTP server sent data before TLS');
    const secure = await new Promise<Socket>((resolve, reject) => {
      let settled = false;
      const socket = tls.connect({
        socket: this.active,
        ...tlsName(this.options.host),
        rejectUnauthorized: this.options.tls?.rejectUnauthorized ?? true,
        ...(this.options.tls?.ca ? { ca: this.options.tls.ca } : {}),
      });
      const fail = () => {
        if (settled) return;
        settled = true;
        reject(new SmtpError('SMTP TLS handshake failed'));
      };
      socket.once('error', fail);
      socket.once('secureConnect', () => {
        if (settled) return;
        const verify = this.options.tls?.rejectUnauthorized ?? true;
        const authorized = !('authorized' in socket) || socket.authorized !== false;
        if (verify && !authorized) {
          fail();
          return;
        }
        settled = true;
        socket.removeAllListeners('error');
        resolve(socket);
      });
    });
    this.active = secure;
    this.watch(secure);
  }

  private watch(socket: Socket): void {
    const lost = () => this.fail(new SmtpError('SMTP connection closed'));
    socket.on('data', (chunk: Buffer | string) => {
      this.receive(typeof chunk === 'string' ? chunk : chunk.toString('utf8'));
    });
    socket.on('end', lost);
    socket.on('close', lost);
    socket.on('error', lost);
  }

  private unwatch(socket: Socket): void {
    socket.removeAllListeners('data');
    socket.removeAllListeners('end');
    socket.removeAllListeners('close');
    socket.removeAllListeners('error');
    socket.on('error', () => undefined);
  }

  private async command(line: string, codes: number[]): Promise<Reply> {
    this.active.write(`${line}\r\n`);
    return this.expect(await this.reply(), codes);
  }

  private async expect(reply: Reply, codes: number[]): Promise<Reply> {
    if (!codes.includes(reply.code)) {
      throw new SmtpError(`SMTP server replied ${reply.code}`, reply.code);
    }
    return reply;
  }

  private receive(chunk: string): void {
    this.buffer += chunk;
    this.release();
  }

  private fail(error: Error): void {
    this.failure ??= error;
    this.release();
  }

  private release(): void {
    if (!this.waiting) return;
    const reply = this.parse();
    if (reply) {
      const waiter = this.waiting;
      this.waiting = undefined;
      waiter(reply);
    } else if (this.failure) {
      const waiter = this.waiting;
      this.waiting = undefined;
      waiter(this.failure);
    }
  }

  /** One complete reply (`250-a`, `250-b`, `250 c`) from the buffer, or undefined. */
  private parse(): Reply | undefined {
    const lines: string[] = [];
    let offset = 0;
    while (true) {
      const end = this.buffer.indexOf('\r\n', offset);
      if (end < 0) return undefined;
      const line = this.buffer.slice(offset, end);
      offset = end + 2;
      lines.push(line.slice(4));
      if (line.charAt(3) !== '-') {
        this.buffer = this.buffer.slice(offset);
        return { code: Number(line.slice(0, 3)), lines };
      }
    }
  }

  private reply(): Promise<Reply> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiting = undefined;
        reject(new SmtpError('SMTP server timed out'));
      }, this.options.timeoutMs ?? 15_000);
      this.waiting = (reply) => {
        clearTimeout(timer);
        if (reply instanceof Error) reject(reply);
        else resolve(reply);
      };
      this.release();
    });
  }
}

/** Node rejects an IP address as a TLS server name; the certificate's IP SAN is checked instead. */
function tlsName(host: string): { servername?: string } {
  return net.isIP(host) ? {} : { servername: host };
}

function connectPlain(options: SmtpOptions): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: options.host, port: options.port });
    const fail = () => {
      socket.destroy();
      reject(new SmtpError('SMTP connection failed'));
    };
    socket.once('error', fail);
    socket.once('connect', () => {
      socket.off('error', fail);
      resolve(socket);
    });
  });
}

async function connectTls(options: SmtpOptions): Promise<Socket> {
  const tls = await loadSmtpTls();
  const verify = options.tls?.rejectUnauthorized ?? true;
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tls.connect({
      host: options.host,
      port: options.port,
      ...tlsName(options.host),
      rejectUnauthorized: verify,
      ...(options.tls?.ca ? { ca: options.tls.ca } : {}),
    });
    const fail = (message: string) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new SmtpError(message));
    };
    socket.once('error', (error: NodeJS.ErrnoException) => {
      const refused =
        error?.code === 'ECONNREFUSED' ||
        error?.code === 'ENOTFOUND' ||
        error?.code === 'EAI_AGAIN';
      fail(refused ? 'SMTP connection failed' : 'SMTP TLS handshake failed');
    });
    socket.once('secureConnect', () => {
      const authorized = !('authorized' in socket) || socket.authorized !== false;
      if (verify && !authorized) {
        fail('SMTP TLS handshake failed');
        return;
      }
      if (settled) return;
      settled = true;
      socket.removeAllListeners('error');
      resolve(socket);
    });
  });
}

/** Mail port used when no SMTP host is configured. Every send fails, as an unreachable relay would. */
export class UnconfiguredMailSender implements MailSender {
  send(): Promise<void> {
    return Promise.reject(new SmtpError('SMTP is not configured'));
  }
}
