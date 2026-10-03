import { afterEach, describe, expect, test } from 'bun:test';
import { useContainer } from '@di-framework/core/container';
import { IdentityModule } from '../src/composition.ts';
import { Mailer } from '../src/mail/application/mailer.ts';
import {
  formatMessage,
  loadSmtpTls,
  SmtpError,
  SmtpMailSender,
  type SmtpOptions,
  UnconfiguredMailSender,
} from '../src/mail/infrastructure/smtp-mail-sender.ts';
import { loadIdentitySettings } from '../src/shared/infrastructure/identity-settings.ts';
import { type FakeSmtpOptions, FakeSmtpServer, testCertificate } from './support/fake-smtp.ts';
import { useRecordingMail } from './support/mail.ts';

const servers: FakeSmtpServer[] = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop();
});

function server(options: FakeSmtpOptions = {}): FakeSmtpServer {
  const instance = new FakeSmtpServer(options);
  servers.push(instance);
  return instance;
}

function sender(port: number, options: Partial<SmtpOptions> = {}): SmtpMailSender {
  return new SmtpMailSender({
    host: '127.0.0.1',
    port,
    username: '',
    password: '',
    from: 'no-reply@identity.test',
    auth: false,
    starttls: false,
    ssl: false,
    timeoutMs: 2000,
    ...options,
  });
}

const message = {
  to: 'ada@example.com',
  subject: 'Your GSIO sign-in link',
  text: 'line one\n.line two',
};

function body(raw: string): string {
  const [, encoded = ''] = raw.split('\r\n\r\n');
  return Buffer.from(encoded.replaceAll('\r\n', ''), 'base64').toString('utf8');
}

describe('SMTP client', () => {
  test('delivers a plain-text message without authentication', async () => {
    const smtp = server();
    await sender(smtp.port).send(message);
    expect(smtp.commands.slice(0, 4)).toEqual([
      'EHLO identity',
      'MAIL FROM:<no-reply@identity.test>',
      'RCPT TO:<ada@example.com>',
      'DATA',
    ]);
    expect(smtp.commands.at(-1)).toBe('QUIT');
    const [raw = ''] = smtp.messages;
    expect(raw).toContain('Subject: Your GSIO sign-in link');
    expect(raw).toContain('From: no-reply@identity.test');
    expect(raw).toContain('Message-ID: <');
    expect(raw).toContain('@identity.test>');
    expect(body(raw)).toBe('line one\r\n.line two');
  });

  test('authenticates with PLAIN, or LOGIN when only LOGIN is offered', async () => {
    const plain = server({ auth: 'PLAIN LOGIN' });
    await sender(plain.port, { auth: true, username: 'mailer', password: 'p@ss' }).send(message);
    expect(plain.credentials).toEqual([{ username: 'mailer', password: 'p@ss' }]);
    const login = server({ auth: 'LOGIN' });
    await sender(login.port, { auth: true, username: 'mailer', password: 'p@ss' }).send(message);
    expect(login.credentials).toEqual([{ username: 'mailer', password: 'p@ss' }]);
    expect(login.commands).toContain('AUTH LOGIN');
    const skipped = server({ auth: 'PLAIN' });
    await sender(skipped.port, { auth: true }).send(message);
    expect(skipped.credentials).toEqual([]);
  });

  test('upgrades with STARTTLS when offered and verifies the certificate', async () => {
    const smtp = server({ starttls: true, auth: 'PLAIN' });
    await sender(smtp.port, {
      starttls: true,
      auth: true,
      username: 'mailer',
      password: 'secret',
      tls: { ca: testCertificate().cert },
    }).send(message);
    expect(smtp.upgraded).toBe(true);
    expect(smtp.commands.filter((command) => command.startsWith('EHLO'))).toHaveLength(2);
    expect(smtp.credentials).toEqual([{ username: 'mailer', password: 'secret' }]);
    expect(body(smtp.messages[0] ?? '')).toBe('line one\r\n.line two');

    const untrusted = server({ starttls: true });
    await expect(sender(untrusted.port, { starttls: true }).send(message)).rejects.toThrow(
      'SMTP TLS handshake failed',
    );
    const insecure = server({ starttls: true });
    await sender(insecure.port, {
      starttls: true,
      // The fixture certificate is local. Production SMTP keeps verification on unless set.
      // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
      tls: { rejectUnauthorized: false },
    }).send(message);
    expect(insecure.messages).toHaveLength(1);

    const injected = server({ starttls: true, injectAfterStartTls: '250-AUTH PLAIN\r\n' });
    await expect(
      sender(injected.port, { starttls: true, tls: { ca: testCertificate().cert } }).send(message),
    ).rejects.toThrow('SMTP server sent data before TLS');
    expect(injected.messages).toHaveLength(0);

    const notOffered = server();
    await sender(notOffered.port, { starttls: true }).send(message);
    expect(notOffered.upgraded).toBe(false);
    expect(notOffered.messages).toHaveLength(1);
  });

  test('speaks implicit TLS', async () => {
    const smtp = server({ implicitTls: true });
    await sender(smtp.port, {
      ssl: true,
      starttls: true,
      tls: { ca: testCertificate().cert },
    }).send(message);
    expect(smtp.messages).toHaveLength(1);
    expect(smtp.commands).not.toContain('STARTTLS');
  });

  test('fails with the reply code and never the message content', async () => {
    const rejected = server({ replies: { RCPT: '550 5.1.1 no such user' } });
    const error = await sender(rejected.port)
      .send(message)
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(SmtpError);
    expect(error).toMatchObject({ code: 550, message: 'SMTP server replied 550' });
    expect(String(error)).not.toContain('ada@example.com');

    const multiline = server({ replies: { EHLO: '550-first\r\n550 second' } });
    await expect(sender(multiline.port).send(message)).rejects.toMatchObject({ code: 550 });

    const closed = server({ closeAfterGreeting: true });
    await expect(sender(closed.port).send(message)).rejects.toThrow('SMTP connection closed');

    const silent = server({ silent: true });
    await expect(sender(silent.port, { timeoutMs: 50 }).send(message)).rejects.toThrow(
      'SMTP server timed out',
    );

    const refused = server();
    const port = refused.port;
    refused.stop();
    await expect(sender(port).send(message)).rejects.toThrow('SMTP connection failed');
    const tlsRefused = server({ implicitTls: true });
    const tlsPort = tlsRefused.port;
    tlsRefused.stop();
    await expect(
      sender(tlsPort, {
        ssl: true,
        // nosemgrep: problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification
        tls: { rejectUnauthorized: false },
      }).send(message),
    ).rejects.toThrow('SMTP connection failed');

    const dropped = server({ dropOnQuit: true });
    await sender(dropped.port).send(message);
    expect(dropped.messages).toHaveLength(1);

    await expect(new UnconfiguredMailSender().send()).rejects.toThrow('SMTP is not configured');
    await expect(
      loadSmtpTls(async () => {
        throw new Error('unlinked');
      }),
    ).rejects.toThrow('SMTP TLS is not available');
    await expect(loadSmtpTls(async () => ({ connect: undefined as never }))).rejects.toThrow(
      'SMTP TLS is not available',
    );
  });

  test('formats headers safely', () => {
    const raw = formatMessage(
      'sender',
      { to: 'a@b.c\r\nBcc: evil@x', subject: 'Héllo\nX-Injected: 1', text: 'hi' },
      new Date(Date.UTC(2026, 0, 2, 3, 4, 5)),
      'fixed-id',
    );
    expect(raw).toContain('To: a@b.c Bcc: evil@x\r\n');
    expect(raw).toContain(
      `Subject: =?UTF-8?B?${Buffer.from('Héllo X-Injected: 1').toString('base64')}?=`,
    );
    expect(raw).toContain('Message-ID: <fixed-id@localhost>');
    expect(raw).toContain('Date: Fri, 02 Jan 2026 03:04:05 +0000');
    expect(raw.split('\r\n').filter((line) => line.startsWith('X-Injected'))).toEqual([]);
    const long = formatMessage('a@b.c', { to: 'x@y.z', subject: 's', text: 'x'.repeat(200) });
    expect(long.split('\r\n\r\n')[1]?.split('\r\n')[0]).toHaveLength(76);
  });
});

describe('mail port wiring', () => {
  test('the module picks SMTP only when a host is configured, and the mailer resolves lazily', async () => {
    expect(IdentityModule.mailSender(loadIdentitySettings({}))).toBeInstanceOf(
      UnconfiguredMailSender,
    );
    expect(
      IdentityModule.mailSender(loadIdentitySettings({ SMTP_HOST: 'smtp.example' })),
    ).toBeInstanceOf(SmtpMailSender);
    const recorder = useRecordingMail();
    await useContainer().resolve(Mailer).send({ to: 'x@example.com', subject: 's', text: 't' });
    expect(recorder.to('x@example.com')).toHaveLength(1);
  });
});
