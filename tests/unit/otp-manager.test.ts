import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import {
  storeOTP,
  verifyOTPForEmail,
  hasOTP,
  deleteOTP,
  getOTPStats
} from '../../src/utils/otp-manager';
import { hashEmail } from '../../src/utils/crypto';

// Setup crypto polyfill for testing
beforeAll(async () => {
  // @ts-ignore - Node.js crypto import for test environment
  const { webcrypto } = await import('node:crypto');
  
  if (!(globalThis as any).crypto) {
    // Adding crypto to globalThis for testing
    (globalThis as any).crypto = webcrypto;
  }
});

// Mock KV namespace
class MockKVNamespace {
  private store = new Map<string, { value: string; expiration?: number }>();

  async get(key: string): Promise<string | null> {
    const item = this.store.get(key);
    if (!item) return null;
    
    if (item.expiration && Date.now() > item.expiration) {
      this.store.delete(key);
      return null;
    }
    
    return item.value;
  }

  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    const expiration = options?.expirationTtl ? Date.now() + (options.expirationTtl * 1000) : undefined;
    this.store.set(key, { value, expiration });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  // Mock implementations for other KV methods (not used in our tests)
  async list(): Promise<any> { return { keys: [] }; }
  async getWithMetadata(): Promise<any> { return { value: null, metadata: null }; }
}

describe('OTP Manager', () => {
  let mockKV: MockKVNamespace;

  beforeEach(() => {
    mockKV = new MockKVNamespace();
  });

  describe('storeOTP', () => {
    it('should store OTP successfully with generated OTP', async () => {
      const email = 'test@example.com';
      const result = await storeOTP(mockKV as unknown as KVNamespace, email);

      expect(result.success).toBe(true);
      expect(result.message).toBe('OTP stored successfully');
      expect(result.otp).toBeDefined();
      expect(result.otp).toHaveLength(6);
    });

    it('should store OTP successfully with provided OTP', async () => {
      const email = 'test@example.com';
      const otp = '123456';
      const result = await storeOTP(mockKV as unknown as KVNamespace, email, otp);

      expect(result.success).toBe(true);
      expect(result.message).toBe('OTP stored successfully');
      expect(result.otp).toBe(otp);
    });

    it('should store OTP with custom expiry', async () => {
      const email = 'test@example.com';
      const result = await storeOTP(mockKV as unknown as KVNamespace, email, undefined, 10);

      expect(result.success).toBe(true);
      expect(result.otp).toBeDefined();
    });

    it('should return failure when KV put throws', async () => {
      const failingKV = {
        ...mockKV,
        put: async () => {
          throw new Error('KV put failed');
        }
      } as unknown as KVNamespace;

      const result = await storeOTP(failingKV, 'test@example.com', '123456');
      expect(result.success).toBe(false);
      expect(result.message).toBe('Failed to store OTP');
    });
  });

  describe('verifyOTPForEmail', () => {
    it('should verify correct OTP', async () => {
      const email = 'test@example.com';
      const storeResult = await storeOTP(mockKV as unknown as KVNamespace, email);
      
      const verifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, storeResult.otp!);
      
      expect(verifyResult.success).toBe(true);
      expect(verifyResult.message).toBe('OTP verified successfully');
    });

    it('should reject incorrect OTP', async () => {
      const email = 'test@example.com';
      await storeOTP(mockKV as unknown as KVNamespace, email, '123456');
      
      const verifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '654321');
      
      expect(verifyResult.success).toBe(false);
      expect(verifyResult.message).toBe('Invalid OTP');
      expect(verifyResult.remainingAttempts).toBe(2);
    });

    it('should return not found for non-existent OTP', async () => {
      const email = 'test@example.com';
      
      const verifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '123456');
      
      expect(verifyResult.success).toBe(false);
      expect(verifyResult.message).toBe('OTP not found or expired');
    });

    it('should handle maximum attempts exceeded', async () => {
      const email = 'test@example.com';
      await storeOTP(mockKV as unknown as KVNamespace, email, '123456');
      
      // Make 3 failed attempts
      await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '000001');
      await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '000002');
      const finalResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '000003');
      
      expect(finalResult.success).toBe(false);
      expect(finalResult.message).toBe('Invalid OTP. Maximum attempts exceeded.');
      expect(finalResult.remainingAttempts).toBeUndefined();
    });

    it('should delete OTP after successful verification', async () => {
      const email = 'test@example.com';
      const storeResult = await storeOTP(mockKV as unknown as KVNamespace, email);
      
      await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, storeResult.otp!);
      
      // Try to verify again - should fail as OTP is deleted
      const secondVerifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, storeResult.otp!);
      expect(secondVerifyResult.success).toBe(false);
      expect(secondVerifyResult.message).toBe('OTP not found or expired');
    });

    it('should return expired when OTP has expired', async () => {
      const email = 'expired@example.com';
      await storeOTP(mockKV as unknown as KVNamespace, email, '123456', 0.001);
      await new Promise(resolve => setTimeout(resolve, 100));

      const verifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '123456');
      expect(verifyResult.success).toBe(false);
      expect(verifyResult.message).toBe('OTP has expired');
    });

    it('should reject immediately when attempts are already maxed', async () => {
      const email = 'maxed@example.com';
      const emailHash = await hashEmail(email);
      const record = {
        hash: 'irrelevant',
        salt: 'irrelevant',
        expiresAt: Date.now() + 60_000,
        attempts: 3,
        createdAt: Date.now()
      };

      await (mockKV as unknown as KVNamespace).put(emailHash, JSON.stringify(record), { expirationTtl: 120 });
      const verifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '123456');

      expect(verifyResult.success).toBe(false);
      expect(verifyResult.message).toBe('Maximum verification attempts exceeded');
    });
  });

  describe('hasOTP', () => {
    it('should return true when OTP exists', async () => {
      const email = 'test@example.com';
      await storeOTP(mockKV as unknown as KVNamespace, email);
      
      const exists = await hasOTP(mockKV as unknown as KVNamespace, email);
      expect(exists).toBe(true);
    });

    it('should return false when OTP does not exist', async () => {
      const email = 'test@example.com';
      
      const exists = await hasOTP(mockKV as unknown as KVNamespace, email);
      expect(exists).toBe(false);
    });

    it('should return false for expired OTP', async () => {
      const email = 'test@example.com';
      // Store OTP with very short expiry
      await storeOTP(mockKV as unknown as KVNamespace, email, undefined, 0.001); // 0.001 minutes = 0.06 seconds
      
      // Wait for expiry
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const exists = await hasOTP(mockKV as unknown as KVNamespace, email);
      expect(exists).toBe(false);
    });

    it('should return false when KV get throws', async () => {
      const failingKV = {
        ...mockKV,
        get: async () => {
          throw new Error('KV get failed');
        }
      } as unknown as KVNamespace;

      const exists = await hasOTP(failingKV, 'test@example.com');
      expect(exists).toBe(false);
    });
  });

  describe('deleteOTP', () => {
    it('should delete existing OTP', async () => {
      const email = 'test@example.com';
      await storeOTP(mockKV as unknown as KVNamespace, email);
      
      const deleted = await deleteOTP(mockKV as unknown as KVNamespace, email);
      expect(deleted).toBe(true);
      
      const exists = await hasOTP(mockKV as unknown as KVNamespace, email);
      expect(exists).toBe(false);
    });

    it('should return true even if OTP does not exist', async () => {
      const email = 'test@example.com';
      
      const deleted = await deleteOTP(mockKV as unknown as KVNamespace, email);
      expect(deleted).toBe(true);
    });

    it('should return false when KV delete throws', async () => {
      const failingKV = {
        ...mockKV,
        delete: async () => {
          throw new Error('KV delete failed');
        }
      } as unknown as KVNamespace;

      const deleted = await deleteOTP(failingKV, 'test@example.com');
      expect(deleted).toBe(false);
    });
  });

  describe('getOTPStats', () => {
    it('should return stats for existing OTP', async () => {
      const email = 'test@example.com';
      await storeOTP(mockKV as unknown as KVNamespace, email);
      
      const stats = await getOTPStats(mockKV as unknown as KVNamespace, email);
      
      expect(stats.exists).toBe(true);
      expect(stats.attempts).toBe(0);
      expect(stats.expiresAt).toBeDefined();
      expect(stats.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should return stats with attempts after failed verification', async () => {
      const email = 'test@example.com';
      await storeOTP(mockKV as unknown as KVNamespace, email, '123456');
      
      // Make a failed attempt
      await verifyOTPForEmail(mockKV as unknown as KVNamespace, email, '654321');
      
      const stats = await getOTPStats(mockKV as unknown as KVNamespace, email);
      
      expect(stats.exists).toBe(true);
      expect(stats.attempts).toBe(1);
    });

    it('should return not exists for non-existent OTP', async () => {
      const email = 'test@example.com';
      
      const stats = await getOTPStats(mockKV as unknown as KVNamespace, email);
      
      expect(stats.exists).toBe(false);
      expect(stats.attempts).toBeUndefined();
      expect(stats.expiresAt).toBeUndefined();
    });

    it('should return not exists when KV get throws', async () => {
      const failingKV = {
        ...mockKV,
        get: async () => {
          throw new Error('KV get failed');
        }
      } as unknown as KVNamespace;

      const stats = await getOTPStats(failingKV, 'test@example.com');
      expect(stats.exists).toBe(false);
    });
  });

  describe('Email normalization', () => {
    it('should handle same email with different cases', async () => {
      const email1 = 'Test@Example.Com';
      const email2 = 'test@example.com';
      
      await storeOTP(mockKV as unknown as KVNamespace, email1, '123456');
      
      const verifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email2, '123456');
      expect(verifyResult.success).toBe(true);
    });

    it('should handle email with whitespace', async () => {
      const email1 = '  test@example.com  ';
      const email2 = 'test@example.com';
      
      await storeOTP(mockKV as unknown as KVNamespace, email1, '123456');
      
      const verifyResult = await verifyOTPForEmail(mockKV as unknown as KVNamespace, email2, '123456');
      expect(verifyResult.success).toBe(true);
    });
  });
});
