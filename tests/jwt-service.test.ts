import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JWTService, CustomJWTPayload } from '../src/services/jwt-service';

// Mock environment
const mockEnv = {
  JWT_SECRET: 'test-secret-key-for-jwt-signing-32-chars-long',
  JWT_ISSUER: 'https://auth-worker.test',
  JWT_AUDIENCE: 'my-app',
  RP_ID: 'example.com',
  RP_NAME: 'Example',
  RP_ORIGINS: 'https://example.com',
  OTP_KV: {} as any,
  ENVIRONMENT: 'development' as const,
  FROM_EMAIL: 'test@example.com',
  send_email: {
    send: vi.fn().mockResolvedValue(undefined)
  }
};

describe('JWTService', () => {
  let jwtService: JWTService;

  beforeEach(() => {
    jwtService = new JWTService(mockEnv);
  });

  describe('constructor', () => {
    it('should throw error when JWT_SECRET is missing', () => {
      expect(() => {
        new JWTService({
          ...mockEnv,
          JWT_SECRET: undefined as any
        });
      }).toThrow('JWT_SECRET not configured');
    });

    it('should throw when JWT_ISSUER is missing', () => {
      expect(() => {
        new JWTService({
          ...mockEnv,
          JWT_ISSUER: ''
        });
      }).toThrow('JWT_ISSUER not configured');
    });

    it('should throw when JWT_AUDIENCE is missing', () => {
      expect(() => {
        new JWTService({
          ...mockEnv,
          JWT_AUDIENCE: ''
        });
      }).toThrow('JWT_AUDIENCE not configured');
    });

    it('should initialize with valid JWT_SECRET', () => {
      expect(jwtService).toBeInstanceOf(JWTService);
    });
  });

  describe('createToken', () => {
    it('should create a valid JWT token', async () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';
      const expiresIn = 3600; // 1 hour

      const result = await jwtService.createToken(userId, email, expiresIn);

      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();
      expect(result.payload).toBeDefined();
      expect(result.payload?.sub).toBe(userId);
      expect(result.payload?.email).toBe(email);
      expect(result.payload?.aud).toBe('my-app');
      expect(result.payload?.iss).toBe('https://auth-worker.test');
    });

    it('should create token with default expiration (24 hours)', async () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';

      const result = await jwtService.createToken(userId, email);

      expect(result.success).toBe(true);
      expect(result.payload?.exp).toBeGreaterThan(result.payload!.iat + 86399); // 24 hours - 1 second
      expect(result.payload?.exp).toBeLessThanOrEqual(result.payload!.iat + 86401); // 24 hours + 1 second
    });

    it('should generate unique JWT IDs for different tokens', async () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';

      const result1 = await jwtService.createToken(userId, email);
      const result2 = await jwtService.createToken(userId, email);

      expect(result1.success).toBe(true);
      expect(result2.success).toBe(true);
      expect(result1.payload?.jti).not.toBe(result2.payload?.jti);
    });
  });

  describe('verifyToken', () => {
    it('should verify a valid token', async () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';

      const createResult = await jwtService.createToken(userId, email);
      expect(createResult.success).toBe(true);

      const verifyResult = await jwtService.verifyToken(createResult.token!);
      
      expect(verifyResult.success).toBe(true);
      expect(verifyResult.payload?.sub).toBe(userId);
      expect(verifyResult.payload?.email).toBe(email);
    });

    it('should reject invalid tokens', async () => {
      const verifyResult = await jwtService.verifyToken('invalid-token');
      
      expect(verifyResult.success).toBe(false);
      expect(verifyResult.error).toBeDefined();
    });

    it('should reject tokens with wrong signature', async () => {
      // Create token with different secret
      const differentEnv = {
        ...mockEnv,
        JWT_SECRET: 'different-secret-key-for-jwt-signing-32-chars',
        JWT_ISSUER: mockEnv.JWT_ISSUER,
        JWT_AUDIENCE: mockEnv.JWT_AUDIENCE
      };
      const differentService = new JWTService(differentEnv);
      
      const token = await differentService.createToken('test-user', 'test@example.com');
      expect(token.success).toBe(true);

      // Try to verify with original service
      const verifyResult = await jwtService.verifyToken(token.token!);
      
      expect(verifyResult.success).toBe(false);
      expect(verifyResult.error).toBeDefined();
    });

    it('should reject expired tokens', async () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';
      const expiresIn = 1; // 1 second

      const createResult = await jwtService.createToken(userId, email, expiresIn);
      expect(createResult.success).toBe(true);

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      const verifyResult = await jwtService.verifyToken(createResult.token!);
      
      expect(verifyResult.success).toBe(false);
      expect(verifyResult.error).toBeDefined();
    });
  });

  describe('decodeToken', () => {
    it('should decode token without verification', async () => {
      const userId = 'test-user-id';
      const email = 'test@example.com';

      const createResult = await jwtService.createToken(userId, email);
      expect(createResult.success).toBe(true);

      const decodeResult = jwtService.decodeToken(createResult.token!);
      
      expect(decodeResult.success).toBe(true);
      expect(decodeResult.payload?.sub).toBe(userId);
      expect(decodeResult.payload?.email).toBe(email);
    });

    it('should decode invalid format tokens', () => {
      const decodeResult = jwtService.decodeToken('invalid.format.token');
      
      expect(decodeResult.success).toBe(false);
      expect(decodeResult.error).toBeDefined();
    });
  });

  describe('token expiration utilities', () => {
    it('should correctly identify expired tokens', () => {
      const payload: CustomJWTPayload = {
        sub: 'test-user',
        email: 'test@example.com',
        iat: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        exp: Math.floor(Date.now() / 1000) - 1800, // 30 minutes ago
        jti: 'test-jti',
        aud: 'my-app',
        iss: 'https://auth-worker.test'
      };

      expect(jwtService.isTokenExpired(payload)).toBe(true);
    });

    it('should correctly identify valid tokens', () => {
      const payload: CustomJWTPayload = {
        sub: 'test-user',
        email: 'test@example.com',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        jti: 'test-jti',
        aud: 'my-app',
        iss: 'https://auth-worker.test'
      };

      expect(jwtService.isTokenExpired(payload)).toBe(false);
    });

    it('should calculate correct time until expiration', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload: CustomJWTPayload = {
        sub: 'test-user',
        email: 'test@example.com',
        iat: now,
        exp: now + 3600, // 1 hour from now
        jti: 'test-jti',
        aud: 'my-app',
        iss: 'https://auth-worker.test'
      };

      const timeUntilExpiration = jwtService.getTimeUntilExpiration(payload);
      expect(timeUntilExpiration).toBeGreaterThan(3590); // Within 10 seconds of 3600
      expect(timeUntilExpiration).toBeLessThanOrEqual(3600);
    });

    it('should return 0 for expired tokens', () => {
      const payload: CustomJWTPayload = {
        sub: 'test-user',
        email: 'test@example.com',
        iat: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        exp: Math.floor(Date.now() / 1000) - 1800, // 30 minutes ago
        jti: 'test-jti',
        aud: 'my-app',
        iss: 'https://auth-worker.test'
      };

      expect(jwtService.getTimeUntilExpiration(payload)).toBe(0);
    });
  });
});
