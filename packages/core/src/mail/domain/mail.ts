export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

/** Outbound mail port. Implementations throw when a message is not accepted. */
export interface MailSender {
  send(message: MailMessage): Promise<void>;
}
