import { useContainer } from '@di-framework/core/container';
import { Container } from '@di-framework/core/decorators';
import { MAIL } from '../../shared/domain/tokens.ts';
import type { MailMessage, MailSender } from '../domain/mail.ts';

/**
 * Resolves the registered `MailSender` on each send, so a test or a reconfigured process can
 * replace it after services were constructed.
 */
@Container()
export class Mailer implements MailSender {
  send(message: MailMessage): Promise<void> {
    return useContainer().resolve<MailSender>(MAIL).send(message);
  }
}
