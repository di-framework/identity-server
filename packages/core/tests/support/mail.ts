import { useContainer } from '@di-framework/core/container';
import type { MailMessage, MailSender } from '../../src/mail/domain/mail.ts';
import { MAIL } from '../../src/shared/domain/tokens.ts';

/** In-memory mail port. `failNext` makes the next sends throw, as an unreachable relay would. */
export class RecordingMailSender implements MailSender {
  sent: MailMessage[] = [];
  failNext = 0;

  async send(message: MailMessage): Promise<void> {
    if (this.failNext > 0) {
      this.failNext -= 1;
      throw new Error('relay unavailable');
    }
    this.sent.push(message);
  }

  to(address: string): MailMessage[] {
    return this.sent.filter((message) => message.to === address);
  }

  /** Token from the last passwordless link mailed to `address`. */
  lastToken(address: string): string | undefined {
    const text = this.to(address).at(-1)?.text ?? '';
    return /token=([A-Za-z0-9_-]{43})/.exec(text)?.[1];
  }
}

let recorder: RecordingMailSender | undefined;

/** Registers one process-wide recording sender as the mail port. */
export function useRecordingMail(): RecordingMailSender {
  recorder ??= new RecordingMailSender();
  useContainer().registerValue(MAIL, recorder);
  return recorder;
}
