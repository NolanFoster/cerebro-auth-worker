import { describe, it, expect, beforeEach, vi } from 'vitest';
import app from '../../src/index';

// Mock environment with JWT_SECRET
const mockEnv = {
  OTP_KV: {
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn()
  } as any,
  USER_MANAGEMENT_WORKER_URL: 'http://localhost:8787',
  ENVIRONMENT: 'preview' as const,
  JWT_SECRET: 'test-secret-key-for-jwt-signing-32-chars-long',
  JWT_ISSUER: 'https://auth-worker.test',
  JWT_AUDIENCE: 'test-app',
  RP_ID: 'example.com',
  RP_NAME: 'Example',
  RP_ORIGINS: 'https://example.com',
  FROM_EMAIL: 'test@example.com',
  send_email: {
    send: vi.fn().mockResolvedValue(undefined)
  }
};

describe('JWT Endpoints', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('POST /auth/validate', () => {
    it('should validate a valid JWT token', async () => {
      // Create a valid token first
      const { JWTService } = await import('../../src/services/jwt-service');
      const jwtService = new JWTService(mockEnv);
      const tokenResult = await jwtService.createToken('test-user-id', 'test@example.com');
      
      expect(tokenResult.success).toBe(true);
      const token = tokenResult.token!;

      // Validate the token
      const request = new Request('http://localhost/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.user.id).toBe('test-user-id');
      expect(result.user.email).toBe('test@example.com');
      expect(result.expiresAt).toBeDefined();
      expect(result.timeUntilExpiration).toBeGreaterThan(0);
    });

    it('should reject request without token', async () => {
      const request = new Request('http://localhost/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Token is required and must be a string');
    });

    it('should reject request with invalid token type', async () => {
      const request = new Request('http://localhost/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 123 })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Token is required and must be a string');
    });

    it('should reject invalid JWT tokens', async () => {
      const request = new Request('http://localhost/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'invalid.jwt.token' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(false);
      expect(result.valid).toBe(false);
      expect(result.message).toBeDefined();
    });

    it('should reject expired JWT tokens', async () => {
      // Create a token that expires in 1 second
      const { JWTService } = await import('../../src/services/jwt-service');
      const jwtService = new JWTService(mockEnv);
      const tokenResult = await jwtService.createToken('test-user-id', 'test@example.com', 1);
      
      expect(tokenResult.success).toBe(true);
      const token = tokenResult.token!;

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Try to validate the expired token
      const request = new Request('http://localhost/auth/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(false);
      expect(result.valid).toBe(false);
      expect(result.message).toBeDefined();
    });
  });

  describe('POST /auth/refresh', () => {
    it('should refresh a valid token that is close to expiration', async () => {
      // Create a token that expires in 30 minutes
      const { JWTService } = await import('../../src/services/jwt-service');
      const jwtService = new JWTService(mockEnv);
      const tokenResult = await jwtService.createToken('test-user-id', 'test@example.com', 1800);
      
      expect(tokenResult.success).toBe(true);
      const token = tokenResult.token!;

      // Refresh the token
      const request = new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.message).toBe('Token refreshed successfully');
      expect(result.token).toBeDefined();
      expect(result.token).not.toBe(token); // Should be a new token
      expect(result.expiresIn).toBe(604800);
      expect(result.user.id).toBe('test-user-id');
      expect(result.user.email).toBe('test@example.com');
    });

    it('should reject request without token', async () => {
      const request = new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Token is required and must be a string');
    });

    it('should reject request with invalid token type', async () => {
      const request = new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 123 })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBe('Token is required and must be a string');
    });

    it('should reject invalid JWT tokens', async () => {
      const request = new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'invalid.jwt.token' })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBeDefined();
    });

    it('should refresh a valid token regardless of time until expiration', async () => {
      // Create a token that expires in 2 hours (sliding window refreshes any valid token)
      const { JWTService } = await import('../../src/services/jwt-service');
      const jwtService = new JWTService(mockEnv);
      const tokenResult = await jwtService.createToken('test-user-id', 'test@example.com', 7200);

      expect(tokenResult.success).toBe(true);
      const token = tokenResult.token!;

      // Refresh the token — sliding window allows refresh at any time
      const request = new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(200);
      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();
      expect(result.token).not.toBe(token);
      expect(result.expiresIn).toBe(604800);
    });

    it('should reject expired tokens', async () => {
      // Create a token that expires in 1 second
      const { JWTService } = await import('../../src/services/jwt-service');
      const jwtService = new JWTService(mockEnv);
      const tokenResult = await jwtService.createToken('test-user-id', 'test@example.com', 1);
      
      expect(tokenResult.success).toBe(true);
      const token = tokenResult.token!;

      // Wait for token to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Try to refresh the expired token
      const request = new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });

      const response = await app.fetch(request, mockEnv);
      const result = await response.json() as any;

      expect(response.status).toBe(400);
      expect(result.success).toBe(false);
      expect(result.message).toBeDefined();
    });
  });
});
