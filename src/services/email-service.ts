import { EmailMessage } from 'cloudflare:email';
import { Env } from '../types/env';

export interface EmailOptions {
  to: string;
  subject: string;
  htmlBody: string;
  textBody?: string;
}

export interface SendEmailResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

export class EmailService {
  private readonly sendEmailBinding: Env['send_email'];
  private readonly fromEmail: string;
  private readonly appName: string;
  private readonly supportEmail: string;

  constructor(env: Env) {
    if (!env.send_email || typeof env.send_email.send !== 'function') {
      throw new Error('Cloudflare send_email binding not configured');
    }

    this.sendEmailBinding = env.send_email;
    this.fromEmail = env.FROM_EMAIL || 'noreply@example.com';
    this.appName = env.APP_NAME?.trim() || 'My App';
    this.supportEmail = env.SUPPORT_EMAIL?.trim() || 'support@example.com';
  }

  async sendEmail(options: EmailOptions): Promise<SendEmailResult> {
    try {
      const { to, subject, htmlBody, textBody } = options;

      if (!to || !subject || !htmlBody) {
        return {
          success: false,
          error: 'Missing required email parameters'
        };
      }

      const messageId = this.generateMessageId();
      const rawMessage = this.buildRawMimeMessage({
        to,
        subject,
        htmlBody,
        textBody,
        messageId
      });
      const emailMessage = new EmailMessage(this.fromEmail, to, rawMessage);
      await this.sendEmailBinding.send(emailMessage);

      return {
        success: true,
        messageId
      };
    } catch (error) {
      console.error('Error sending email:', error);

      if (error instanceof Error) {
        return {
          success: false,
          error: `Email send error: ${error.message}`
        };
      }

      return {
        success: false,
        error: 'Unknown error occurred while sending email'
      };
    }
  }

  async sendVerificationEmail(to: string, otp: string, otpExpiryMinutes: number = 10): Promise<SendEmailResult> {
    const subject = `${this.appName} — Verify your email`;
    const htmlBody = this.generateVerificationEmailHTML(to, otp, otpExpiryMinutes);
    const textBody = this.generateVerificationEmailText(to, otp, otpExpiryMinutes);

    return this.sendEmail({
      to,
      subject,
      htmlBody,
      textBody
    });
  }

  private generateMessageId(): string {
    const fromDomain = this.getFromAddressDomain();
    return `<cf-email-${Date.now()}-${Math.random().toString(36).slice(2, 10)}@${fromDomain}>`;
  }

  private getFromAddressDomain(): string {
    const emailMatch = this.fromEmail.match(/<?([^\s<>@]+@[^\s<>@]+)>?/);
    if (!emailMatch) {
      return 'workers.dev';
    }

    const [, address] = emailMatch;
    const domain = address.split('@')[1];
    return domain || 'workers.dev';
  }

  private buildRawMimeMessage(options: EmailOptions & { messageId: string }): string {
    const { to, subject, htmlBody, textBody, messageId } = options;
    const boundary = `cf-boundary-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const plainTextBody = this.normalizeLineEndings(textBody || this.stripHtml(htmlBody));
    const normalizedHtmlBody = this.normalizeLineEndings(htmlBody);

    return [
      `From: ${this.fromEmail}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      `Message-ID: ${messageId}`,
      'MIME-Version: 1.0',
      `Date: ${new Date().toUTCString()}`,
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      plainTextBody,
      '',
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      normalizedHtmlBody,
      '',
      `--${boundary}--`,
      ''
    ].join('\r\n');
  }

  private stripHtml(html: string): string {
    return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  }

  private normalizeLineEndings(value: string): string {
    return value.replace(/\r?\n/g, '\r\n');
  }

  private generateVerificationEmailHTML(email: string, otp: string, expiryMinutes: number): string {
    const safeApp = this.escapeHtml(this.appName);
    const safeEmail = this.escapeHtml(email);
    const safeSupport = this.escapeHtml(this.supportEmail);
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${safeApp} — verification</title>
</head>
<body style="margin:0;font-family:system-ui,-apple-system,sans-serif;line-height:1.5;background:#f4f4f5;color:#18181b;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width:480px;background:#fff;border-radius:8px;padding:28px 24px;box-shadow:0 1px 3px rgba(0,0,0,.08);">
          <tr><td>
            <h1 style="margin:0 0 8px;font-size:20px;">${safeApp}</h1>
            <p style="margin:0 0 16px;color:#52525b;font-size:15px;">Sign-in verification code</p>
            <p style="margin:0 0 12px;font-size:15px;">Use this code to verify <strong>${safeEmail}</strong>:</p>
            <p style="margin:16px 0;font-size:28px;letter-spacing:0.2em;font-weight:700;text-align:center;font-variant-numeric:tabular-nums;">${this.escapeHtml(otp)}</p>
            <p style="margin:0 0 20px;font-size:14px;color:#71717a;">This code expires in ${expiryMinutes} minutes. If you did not request it, you can ignore this message.</p>
            <p style="margin:0;font-size:13px;color:#a1a1aa;">Questions? <a href="mailto:${safeSupport}" style="color:#2563eb;">${safeSupport}</a></p>
          </td></tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
  }

  private escapeHtml(s: string): string {
    return s
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  private generateVerificationEmailText(email: string, otp: string, expiryMinutes: number): string {
    return `
${this.appName} — email verification

We received a request to verify ${email}.

Your code: ${otp}

This code expires in ${expiryMinutes} minutes. If you did not request it, ignore this email.

Support: ${this.supportEmail}
`.trim();
  }
}
