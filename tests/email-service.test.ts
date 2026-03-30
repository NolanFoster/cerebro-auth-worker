import { describe, it, expect, beforeEach, vi } from 'vitest';
import { EmailMessage } from 'cloudflare:email';
import { EmailService } from '../src/services/email-service';

const createMockEnv = () => ({
  OTP_KV: {} as any,
  ENVIRONMENT: 'development' as const,
  JWT_SECRET: 'test-jwt-secret',
  JWT_ISSUER: 'https://auth-worker.test',
  JWT_AUDIENCE: 'test-app',
  FROM_EMAIL: 'test@example.com',
  APP_NAME: 'Test App',
  SUPPORT_EMAIL: 'support@example.com',
  send_email: {
    send: vi.fn().mockResolvedValue(undefined)
  }
});

describe('EmailService', () => {
  let emailService: EmailService;
  let mockEnv: ReturnType<typeof createMockEnv>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockEnv = createMockEnv();
    emailService = new EmailService(mockEnv as any);
  });

  describe('constructor', () => {
    it('should initialize with default values', () => {
      const service = new EmailService({
        ...mockEnv,
        FROM_EMAIL: undefined as any
      } as any);

      expect(service).toBeInstanceOf(EmailService);
    });

    it('should use provided environment values', () => {
      const service = new EmailService(mockEnv as any);
      expect(service).toBeInstanceOf(EmailService);
    });

    it('should throw error when send_email binding is missing', () => {
      expect(() => {
        new EmailService({
          ...mockEnv,
          send_email: undefined as any
        } as any);
      }).toThrow('Cloudflare send_email binding not configured');
    });
  });

  describe('sendEmail', () => {
    it('should validate required parameters', async () => {
      const result = await emailService.sendEmail({
        to: '',
        subject: 'Test',
        htmlBody: 'Test body'
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Missing required email parameters');
    });

    it('should send MIME email through Cloudflare binding', async () => {
      const result = await emailService.sendEmail({
        to: 'test@example.com',
        subject: 'Test Subject',
        htmlBody: '<p>Test HTML</p>',
        textBody: 'Test text'
      });

      expect(result.success).toBe(true);
      expect(result.messageId).toMatch(/^<cf-email-.*@example\.com>$/);
      expect(mockEnv.send_email.send).toHaveBeenCalledTimes(1);

      const sentMessage = vi.mocked(mockEnv.send_email.send).mock.calls[0][0] as EmailMessage;
      expect(sentMessage).toBeInstanceOf(EmailMessage);
      expect((sentMessage as any).from).toBe('test@example.com');
      expect((sentMessage as any).to).toBe('test@example.com');
      expect((sentMessage as any).raw).toContain('Subject:');
      expect((sentMessage as any).raw).toContain(`Message-ID: ${result.messageId}`);
      expect((sentMessage as any).raw).toContain('Test text');
      expect((sentMessage as any).raw).toContain('Test HTML');
    });

    it('should return error when Cloudflare send fails', async () => {
      vi.mocked(mockEnv.send_email.send).mockRejectedValue(new Error('Send failed'));

      const result = await emailService.sendEmail({
        to: 'test@example.com',
        subject: 'Test Subject',
        htmlBody: '<p>Test HTML</p>'
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('Email send error: Send failed');
    });
  });

  describe('sendVerificationEmail', () => {
    it('should call sendEmail with correct parameters', async () => {
      const sendEmailSpy = vi.spyOn(emailService, 'sendEmail').mockResolvedValue({
        success: true,
        messageId: 'test-id'
      });

      const result = await emailService.sendVerificationEmail('test@example.com', '123456', 15);

      expect(sendEmailSpy).toHaveBeenCalledWith({
        to: 'test@example.com',
        subject: 'Test App — Verify your email',
        htmlBody: expect.stringContaining('123456'),
        textBody: expect.stringContaining('123456')
      });

      expect(result.success).toBe(true);
      expect(result.messageId).toBe('test-id');
    });

    it('should handle different expiry times', async () => {
      const sendEmailSpy = vi.spyOn(emailService, 'sendEmail').mockResolvedValue({
        success: true,
        messageId: 'test-id'
      });

      const result = await emailService.sendVerificationEmail('test@example.com', '123456', 30);

      expect(result.success).toBe(true);
      expect(sendEmailSpy).toHaveBeenCalledWith({
        to: 'test@example.com',
        subject: 'Test App — Verify your email',
        htmlBody: expect.stringContaining('30 minutes'),
        textBody: expect.stringContaining('30 minutes')
      });
    });
  });
});
