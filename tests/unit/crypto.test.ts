import { describe, it, expect, beforeAll } from 'vitest';
import {
  hashEmail,
  hashOTP,
  verifyOTP,
  generateOTP,
  generateSecureToken,
  createExpirationTime,
  isExpired
} from '../../src/utils/crypto';

// Setup crypto polyfill for testing
beforeAll(async () => {
  // @ts-ignore - Node.js crypto import for test environment
  const { webcrypto } = await import('node:crypto');
  
  if (!(globalThis as any).crypto) {
    // Adding crypto to globalThis for testing
    (globalThis as any).crypto = webcrypto;
  }
});

describe('Crypto Utils', () => {
  describe('hashEmail', () => {
    it('should hash email consistently', async () => {
      const email = 'test@example.com';
      const hash1 = await hashEmail(email);
      const hash2 = await hashEmail(email);
      
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 produces 64 hex characters
    });

    it('should normalize email case and whitespace', async () => {
      const email1 = 'Test@Example.Com';
      const email2 = '  test@example.com  ';
      
      const hash1 = await hashEmail(email1);
      const hash2 = await hashEmail(email2);
      
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different emails', async () => {
      const email1 = 'test1@example.com';
      const email2 = 'test2@example.com';
      
      const hash1 = await hashEmail(email1);
      const hash2 = await hashEmail(email2);
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('hashOTP', () => {
    it('should hash OTP with generated salt', async () => {
      const otp = '123456';
      const result = await hashOTP(otp);
      
      expect(result.hash).toHaveLength(64); // SHA-256 hex
      expect(result.salt).toHaveLength(32); // 16 bytes as hex
    });

    it('should hash OTP with provided salt', async () => {
      const otp = '123456';
      const salt = 'abcdef1234567890abcdef1234567890';
      
      const result = await hashOTP(otp, salt);
      
      expect(result.hash).toHaveLength(64);
      expect(result.salt).toBe(salt);
    });

    it('should produce same hash for same OTP and salt', async () => {
      const otp = '123456';
      const salt = 'abcdef1234567890abcdef1234567890';
      
      const result1 = await hashOTP(otp, salt);
      const result2 = await hashOTP(otp, salt);
      
      expect(result1.hash).toBe(result2.hash);
      expect(result1.salt).toBe(result2.salt);
    });

    it('should produce different hashes for different OTPs', async () => {
      const salt = 'abcdef1234567890abcdef1234567890';
      
      const result1 = await hashOTP('123456', salt);
      const result2 = await hashOTP('654321', salt);
      
      expect(result1.hash).not.toBe(result2.hash);
    });
  });

  describe('verifyOTP', () => {
    it('should verify correct OTP', async () => {
      const otp = '123456';
      const { hash, salt } = await hashOTP(otp);
      
      const isValid = await verifyOTP(otp, hash, salt);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect OTP', async () => {
      const otp = '123456';
      const { hash, salt } = await hashOTP(otp);
      
      const isValid = await verifyOTP('654321', hash, salt);
      expect(isValid).toBe(false);
    });

    it('should reject OTP with wrong salt', async () => {
      const otp = '123456';
      const { hash } = await hashOTP(otp);
      const wrongSalt = 'wrongsalt123456789012345678901234';
      
      const isValid = await verifyOTP(otp, hash, wrongSalt);
      expect(isValid).toBe(false);
    });
  });

  describe('generateOTP', () => {
    it('should generate OTP with default length', () => {
      const otp = generateOTP();
      expect(otp).toHaveLength(6);
      expect(/^\d+$/.test(otp)).toBe(true); // Only digits
    });

    it('should generate OTP with custom length', () => {
      const otp = generateOTP(8);
      expect(otp).toHaveLength(8);
      expect(/^\d+$/.test(otp)).toBe(true);
    });

    it('should generate different OTPs', () => {
      const otp1 = generateOTP();
      const otp2 = generateOTP();
      
      // While theoretically they could be the same, it's extremely unlikely
      expect(otp1).not.toBe(otp2);
    });
  });

  describe('generateSecureToken', () => {
    it('should generate token with default length', () => {
      const token = generateSecureToken();
      expect(token).toHaveLength(64); // 32 bytes as hex
      expect(/^[0-9a-f]+$/.test(token)).toBe(true); // Only hex characters
    });

    it('should generate token with custom length', () => {
      const token = generateSecureToken(16);
      expect(token).toHaveLength(32); // 16 bytes as hex
    });

    it('should generate different tokens', () => {
      const token1 = generateSecureToken();
      const token2 = generateSecureToken();
      
      expect(token1).not.toBe(token2);
    });
  });

  describe('createExpirationTime', () => {
    it('should create expiration time with default minutes', () => {
      const now = Date.now();
      const expiration = createExpirationTime();
      
      expect(expiration).toBeGreaterThan(now);
      expect(expiration).toBeLessThanOrEqual(now + 5 * 60 * 1000 + 100); // 5 minutes + small buffer
    });

    it('should create expiration time with custom minutes', () => {
      const now = Date.now();
      const expiration = createExpirationTime(10);
      
      expect(expiration).toBeGreaterThan(now);
      expect(expiration).toBeLessThanOrEqual(now + 10 * 60 * 1000 + 100); // 10 minutes + small buffer
    });
  });

  describe('isExpired', () => {
    it('should return false for future timestamp', () => {
      const futureTime = Date.now() + 60000; // 1 minute from now
      expect(isExpired(futureTime)).toBe(false);
    });

    it('should return true for past timestamp', () => {
      const pastTime = Date.now() - 60000; // 1 minute ago
      expect(isExpired(pastTime)).toBe(true);
    });

    it('should return true for current timestamp', () => {
      const now = Date.now();
      expect(isExpired(now)).toBe(true);
    });
  });
});
