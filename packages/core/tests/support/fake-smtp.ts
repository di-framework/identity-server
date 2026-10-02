import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Socket, TCPSocketListener } from 'bun';

/** Self-signed localhost certificate, generated once per test process with the openssl CLI. */
let certificate: { key: string; cert: string } | undefined;
export function testCertificate(): { key: string; cert: string } {
  if (certificate) return certificate;
  const directory = mkdtempSync(join(tmpdir(), 'identity-smtp-'));
  const result = Bun.spawnSync([
    'openssl',
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    join(directory, 'key.pem'),
    '-out',
    join(directory, 'cert.pem'),
    '-days',
    '2',
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ]);
  if (result.exitCode !== 0) throw new Error('openssl could not create a test certificate');
  certificate = {
    key: readFileSync(join(directory, 'key.pem'), 'utf8'),
    cert: readFileSync(join(directory, 'cert.pem'), 'utf8'),
  };
  return certificate;
}

export interface FakeSmtpOptions {
  /** Advertise and accept STARTTLS. */
  starttls?: boolean;
  /** Implicit TLS listener. */
  implicitTls?: boolean;
  /** AUTH mechanisms to advertise, for example `PLAIN LOGIN` or `LOGIN`. */
  auth?: string;
  /** Replace the reply to a command verb (`RCPT`, `MAIL`, `DATA`, `EHLO`, `QUIT`, `.`). */
  replies?: Record<string, string>;
  /** Close the connection right after the greeting. */
  closeAfterGreeting?: boolean;
  /** Never send the greeting. */
  silent?: boolean;
  /** Close instead of answering QUIT. */
  dropOnQuit?: boolean;
}

interface Connection {
  /** Set on the raw socket after STARTTLS; its later bytes are TLS records, not commands. */
  replaced?: boolean;
  buffer: string;
  inData: boolean;
  data: string[];
  login?: 'user' | 'pass';
  user?: string;
}

/** Minimal SMTP server for tests. Records commands, credentials, and delivered messages. */
export class FakeSmtpServer {
  readonly commands: string[] = [];
  readonly messages: string[] = [];
  readonly credentials: Array<{ username: string; password: string }> = [];
  upgraded = false;
  private readonly listener: TCPSocketListener<Connection>;

  constructor(private readonly options: FakeSmtpOptions = {}) {
    const server = this;
    const tls = options.implicitTls ? testCertificate() : undefined;
    this.listener = Bun.listen<Connection>({
      hostname: '127.0.0.1',
      port: 0,
      ...(tls ? { tls } : {}),
      socket: {
        open(socket) {
          socket.data = { buffer: '', inData: false, data: [] };
          if (options.silent) return;
          socket.write('220 fake.test ESMTP\r\n');
          if (options.closeAfterGreeting) socket.end();
        },
        data(socket, chunk) {
          server.receive(socket, chunk.toString('utf8'));
        },
      },
    });
  }

  get port(): number {
    return this.listener.port;
  }

  stop(): void {
    this.listener.stop(true);
  }

  private receive(socket: Socket<Connection>, chunk: string): void {
    const state = socket.data;
    if (state.replaced) return;
    state.buffer += chunk;
    let end = state.buffer.indexOf('\r\n');
    while (end >= 0) {
      const line = state.buffer.slice(0, end);
      state.buffer = state.buffer.slice(end + 2);
      if (this.line(socket, state, line) === 'upgraded') return;
      end = state.buffer.indexOf('\r\n');
    }
  }

  private line(
    socket: Socket<Connection>,
    state: Connection,
    line: string,
  ): 'upgraded' | undefined {
    if (state.inData) {
      if (line === '.') {
        state.inData = false;
        this.messages.push(state.data.join('\r\n'));
        state.data = [];
        this.reply(socket, '.', '250 queued');
      } else {
        state.data.push(line.startsWith('..') ? line.slice(1) : line);
      }
      return undefined;
    }
    this.commands.push(line);
    if (state.login === 'user') {
      state.user = Buffer.from(line, 'base64').toString('utf8');
      state.login = 'pass';
      socket.write('334 UGFzc3dvcmQ6\r\n');
      return undefined;
    }
    if (state.login === 'pass') {
      this.credentials.push({
        username: state.user ?? '',
        password: Buffer.from(line, 'base64').toString('utf8'),
      });
      state.login = undefined;
      socket.write('235 ok\r\n');
      return undefined;
    }
    const verb = line.split(' ')[0]?.toUpperCase() ?? '';
    switch (verb) {
      case 'EHLO': {
        const extensions = ['250-fake.test'];
        if (this.options.starttls && !this.upgraded) extensions.push('250-STARTTLS');
        if (this.options.auth) extensions.push(`250-AUTH ${this.options.auth}`);
        extensions.push('250 8BITMIME');
        this.reply(socket, verb, extensions.join('\r\n'));
        return undefined;
      }
      case 'STARTTLS': {
        socket.write('220 go ahead\r\n');
        const server = this;
        this.upgraded = true;
        state.replaced = true;
        socket.upgradeTLS({
          tls: testCertificate(),
          socket: {
            open(tlsSocket) {
              tlsSocket.data = { buffer: '', inData: false, data: [] };
            },
            data(tlsSocket, chunk) {
              server.receive(tlsSocket as Socket<Connection>, chunk.toString('utf8'));
            },
          },
        });
        return 'upgraded';
      }
      case 'AUTH': {
        const [, mechanism, initial] = line.split(' ');
        if (mechanism === 'PLAIN') {
          const [, username = '', password = ''] = Buffer.from(initial ?? '', 'base64')
            .toString('utf8')
            .split('\0');
          this.credentials.push({ username, password });
          socket.write('235 ok\r\n');
        } else {
          state.login = 'user';
          socket.write('334 VXNlcm5hbWU6\r\n');
        }
        return undefined;
      }
      case 'DATA':
        state.inData = true;
        this.reply(socket, verb, '354 go');
        return undefined;
      case 'QUIT':
        if (this.options.dropOnQuit) {
          socket.end();
          return undefined;
        }
        this.reply(socket, verb, '221 bye');
        socket.end();
        return undefined;
      default:
        this.reply(socket, verb, '250 ok');
        return undefined;
    }
  }

  private reply(socket: Socket<Connection>, verb: string, fallback: string): void {
    socket.write(`${this.options.replies?.[verb] ?? fallback}\r\n`);
  }
}
