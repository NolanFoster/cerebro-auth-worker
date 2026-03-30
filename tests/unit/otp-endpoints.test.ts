import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import app from '@/index';
import { Env } from '@/types/env';

// Setup crypto polyfill for testing
beforeAll(async () => {
  // @ts-ignore - Node.js crypto import for test environment
  const { webcrypto } = await import('node:crypto');
  
  if (!(globalThis as any).crypto) {
    // Adding crypto to globalThis for testing
    (globalThis as any).crypto = webcrypto;
  }
});

// We'll use vi.mocked() approach like the health tests

describe('OTP Endpoints', () => {
  let mockEnv: Env;
  let sendEmailMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    sendEmailMock = vi.fn().mockResolvedValue(undefined);

    mockEnv = {
      OTP_KV: {
        put: vi.fn(),
        get: vi.fn(),
        delete: vi.fn(),
        list: vi.fn(),
        getWithMetadata: vi.fn()
      } as unknown as KVNamespace,
      USER_MANAGEMENT_WORKER_URL: 'https://user-management-worker-preview.your-domain.workers.dev',
      ENVIRONMENT: 'preview',
      JWT_SECRET: 'test-jwt-secret',
      JWT_ISSUER: 'https://auth-worker.test',
      JWT_AUDIENCE: 'test-app',
      FROM_EMAIL: 'verify@example.com',
      APP_NAME: 'Test App',
      send_email: {
        send: sendEmailMock
      }
    };

    // Mock User Management Worker integration
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ success: true })
    } as Response));

    // Mock OTP_KV operations to simulate actual KV behavior
    const otpStore = new Map<string, { value: string; expiration?: number }>();
    
    vi.mocked(mockEnv.OTP_KV.put).mockImplementation(async (key: string, value: any, options?: any) => {
      const expiration = options?.expirationTtl ? Date.now() + (options.expirationTtl * 1000) : undefined;
      otpStore.set(key, { value: value as string, expiration });
    });

    (vi.mocked(mockEnv.OTP_KV.get) as any).mockImplementation(async (key: string) => {
      const item = otpStore.get(key);
      if (!item) return null;
      
      if (item.expiration && Date.now() > item.expiration) {
        otpStore.delete(key);
        return null;
      }
      
      return item.value;
    });

    vi.mocked(mockEnv.OTP_KV.delete).mockImplementation(async (key: string) => {
      otpStore.delete(key);
    });

    // Mock successful D1 operation by default
  });

  describe('POST /otp/generate', () => {
    it('should generate OTP successfully', async () => {
      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.message).toBe('OTP generated successfully. Please check your email for the verification code.');
      expect(result.otp).toBeUndefined();
      expect(result.emailSent).toBeDefined();
      expect(sendEmailMock).toHaveBeenCalledTimes(1);
    });

    it('should reject request without email', async () => {
      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Email is required and must be a string');
    });

    it('should reject request with invalid email type', async () => {
      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 123 })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Email is required and must be a string');
    });

    it('should reject request when OTP already exists', async () => {
      const email = 'test@example.com';
      
      // Generate first OTP
      const request1 = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      
      await app.fetch(request1, mockEnv);

      // Try to generate second OTP
      const request2 = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const response2 = await app.fetch(request2, mockEnv);
      const result2 = await response2.json() as any;

      expect(response2.status).toBe(409);
      expect(result2.success).toBe(false);
      expect(result2.message).toContain('OTP already exists');
    });

    it('should not return OTP in any environment', async () => {
      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.otp).toBeUndefined();
      expect(result.emailSent).toBeDefined();
    });

    it('should return success with emailSent false when email delivery fails', async () => {
      sendEmailMock.mockRejectedValueOnce(new Error('send failed'));

      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.emailSent).toBe(false);
    });

    it('should return success with emailSent false when email binding is missing', async () => {
      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      });

      const envWithoutEmailBinding = {
        ...mockEnv,
        send_email: undefined as any
      };

      const response = await app.fetch(request, envWithoutEmailBinding);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.emailSent).toBe(false);
    });

    it('should return 500 when OTP storage fails', async () => {
      vi.mocked(mockEnv.OTP_KV.put).mockRejectedValueOnce(new Error('KV write failed'));

      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(500);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Failed to store OTP');
    });

    it('should return 500 for invalid JSON payload', async () => {
      const request = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{bad-json'
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(500);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Internal server error');
    });
  });

  describe('POST /otp/verify', () => {
    it('should verify correct OTP', async () => {
      const email = 'test@example.com';
      const testOTP = '123456';
      
      // Store OTP directly using the OTP manager (bypassing the endpoint)
      const { storeOTP } = await import('../../src/utils/otp-manager');
      await storeOTP(mockEnv.OTP_KV, email, testOTP, 10);

      // Verify OTP
      const verifyRequest = new Request('http://localhost/otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp: testOTP })
      });

      const verifyResponse = await app.fetch(verifyRequest, mockEnv);
      const verifyResult = await verifyResponse.json() as any;

      expect(verifyResponse.status).toBe(200);
      expect(verifyResult.success).toBe(true);
      expect(verifyResult.message).toBe('OTP verified successfully');
    });

    it('should reject incorrect OTP', async () => {
      const email = 'test@example.com';
      
      // Generate OTP
      const generateRequest = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      
      await app.fetch(generateRequest, mockEnv);

      // Verify with wrong OTP
      const verifyRequest = new Request('http://localhost/otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp: '000000' })
      });

      const verifyResponse = await app.fetch(verifyRequest, mockEnv);
      const verifyResult = await verifyResponse.json() as any;

      expect(verifyResponse.status).toBe(400);
      expect(verifyResult.success).toBe(false);
      expect(verifyResult.message).toBe('Invalid OTP');
      expect(verifyResult.remainingAttempts).toBe(2);
    });

    it('should reject request without email', async () => {
      const request = new Request('http://localhost/otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp: '123456' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Email is required and must be a string');
    });

    it('should reject request without OTP', async () => {
      const request = new Request('http://localhost/otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('OTP is required and must be a string');
    });
  });

  describe('GET /otp/status/:email', () => {
    it('should return status for existing OTP', async () => {
      const email = 'test@example.com';
      
      // Generate OTP
      const generateRequest = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      
      await app.fetch(generateRequest, mockEnv);

      // Check status
      const statusRequest = new Request(`http://localhost/otp/status/${encodeURIComponent(email)}`, {
        method: 'GET'
      });

      const statusResponse = await app.fetch(statusRequest, mockEnv);
      const statusResult = await statusResponse.json() as any;

      expect(statusResponse.status).toBe(200);
      expect(statusResult.success).toBe(true);
      expect(statusResult.exists).toBe(true);
      expect(statusResult.attempts).toBe(0);
      expect(statusResult.expiresAt).toBeDefined();
    });

    it('should return status for non-existent OTP', async () => {
      const email = 'nonexistent@example.com';
      
      const statusRequest = new Request(`http://localhost/otp/status/${encodeURIComponent(email)}`, {
        method: 'GET'
      });

      const statusResponse = await app.fetch(statusRequest, mockEnv);
      const statusResult = await statusResponse.json() as any;

      expect(statusResponse.status).toBe(200);
      expect(statusResult.success).toBe(true);
      expect(statusResult.exists).toBe(false);
      expect(statusResult.attempts).toBeUndefined();
      expect(statusResult.expiresAt).toBeUndefined();
    });
  });

  describe('DELETE /otp/:email', () => {
    it('should delete existing OTP', async () => {
      const email = 'test@example.com';
      
      // Generate OTP
      const generateRequest = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });
      
      await app.fetch(generateRequest, mockEnv);

      // Delete OTP
      const deleteRequest = new Request(`http://localhost/otp/${encodeURIComponent(email)}`, {
        method: 'DELETE'
      });

      const deleteResponse = await app.fetch(deleteRequest, mockEnv);
      const deleteResult = await deleteResponse.json() as any;

      expect(deleteResponse.status).toBe(200);
      expect(deleteResult.success).toBe(true);
      expect(deleteResult.message).toBe('OTP deleted successfully');

      // Verify OTP is gone
      const statusRequest = new Request(`http://localhost/otp/status/${encodeURIComponent(email)}`, {
        method: 'GET'
      });

      const statusResponse = await app.fetch(statusRequest, mockEnv);
      const statusResult = await statusResponse.json() as any;

      expect(statusResult.exists).toBe(false);
    });

    it('should return success even for non-existent OTP', async () => {
      const email = 'nonexistent@example.com';
      
      const deleteRequest = new Request(`http://localhost/otp/${encodeURIComponent(email)}`, {
        method: 'DELETE'
      });

      const deleteResponse = await app.fetch(deleteRequest, mockEnv);
      const deleteResult = await deleteResponse.json() as any;

      expect(deleteResponse.status).toBe(200);
      expect(deleteResult.success).toBe(true);
      expect(deleteResult.message).toBe('OTP deleted successfully');
    });
  });

  describe('Integration flow', () => {
    it('should handle complete OTP lifecycle', async () => {
      const email = 'integration@example.com';

      // 1. Generate OTP
      const generateRequest = new Request('http://localhost/otp/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const generateResponse = await app.fetch(generateRequest, mockEnv);
      const generateResult = await generateResponse.json() as any;
      
      expect(generateResponse.status).toBe(200);
      expect(generateResult.success).toBe(true);
      expect(generateResult.otp).toBeUndefined();
      expect(generateResult.emailSent).toBeDefined();

      // 2. Check status
      const statusRequest = new Request(`http://localhost/otp/status/${encodeURIComponent(email)}`, {
        method: 'GET'
      });

      const statusResponse = await app.fetch(statusRequest, mockEnv);
      const statusResult = await statusResponse.json() as any;

      expect(statusResponse.status).toBe(200);
      expect(statusResult.exists).toBe(true);
      expect(statusResult.attempts).toBe(0);

      // 3. Store our test OTP directly to ensure verification works
      const testOTP = '123456';
      const { storeOTP } = await import('../../src/utils/otp-manager');
      await storeOTP(mockEnv.OTP_KV, email, testOTP, 10);

      // 4. Verify OTP (use the test OTP we know)
      const verifyRequest = new Request('http://localhost/otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp: testOTP })
      });

      const verifyResponse = await app.fetch(verifyRequest, mockEnv);
      const verifyResult = await verifyResponse.json() as any;

      expect(verifyResponse.status).toBe(200);
      expect(verifyResult.success).toBe(true);

      // 5. Check status after verification (should be gone)
      const finalStatusRequest = new Request(`http://localhost/otp/status/${encodeURIComponent(email)}`, {
        method: 'GET'
      });

      const finalStatusResponse = await app.fetch(finalStatusRequest, mockEnv);
      const finalStatusResult = await finalStatusResponse.json() as any;

      expect(finalStatusResult.exists).toBe(false);
    });
  });

  describe('POST /email/send-verification', () => {
    it('should send verification email successfully', async () => {
      const request = new Request('http://localhost/email/send-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', otp: '123456', expiryMinutes: 15 })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.message).toBe('Verification email sent successfully');
      expect(result.messageId).toBeDefined();
      expect(sendEmailMock).toHaveBeenCalledTimes(1);
    });

    it('should reject request without email', async () => {
      const request = new Request('http://localhost/email/send-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ otp: '123456' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Email is required and must be a string');
    });

    it('should reject request without otp', async () => {
      const request = new Request('http://localhost/email/send-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('OTP is required and must be a string');
    });

    it('should return 500 when email provider returns failure', async () => {
      sendEmailMock.mockRejectedValueOnce(new Error('send failed'));

      const request = new Request('http://localhost/email/send-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', otp: '123456' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(500);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Failed to send verification email');
      expect(result.error).toBeDefined();
    });

    it('should return 500 when email binding is missing', async () => {
      const envWithoutEmailBinding = {
        ...mockEnv,
        send_email: undefined as any
      };

      const request = new Request('http://localhost/email/send-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', otp: '123456' })
      });

      const response = await app.fetch(request, envWithoutEmailBinding);
      const result = await response.json() as any;

      expect(response.status).toBe(500);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Internal server error');
    });

    it('should return 500 for malformed JSON body', async () => {
      const request = new Request('http://localhost/email/send-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{bad-json'
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(500);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Internal server error');
    });
  });
});
