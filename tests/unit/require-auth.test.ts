import { describe, it, expect, beforeAll, vi } from 'vitest';
import { Hono } from 'hono';
import { requireAuth, type AuthVars } from '../../src/middleware/require-auth';
import { JWTService } from '../../src/services/jwt-service';
import type { Env } from '../../src/types/env';

beforeAll(async () => {
  // @ts-ignore - Node.js crypto import for test environment
  const { webcrypto } = await import('node:crypto');
  if (!(globalThis as any).crypto) {
    (globalThis as any).crypto = webcrypto;
  }
});

const mockEnv: Env = {
  OTP_KV: {} as any,
  ENVIRONMENT: 'preview',
  JWT_SECRET: 'test-secret-key-for-jwt-signing-32-chars-long',
  JWT_ISSUER: 'https://auth-worker.test',
  JWT_AUDIENCE: 'test-app',
  RP_ID: 'example.com',
  RP_NAME: 'Example',
  RP_ORIGINS: 'https://example.com',
  send_email: { send: vi.fn() } as any,
};

function buildApp() {
  const app = new Hono<{ Bindings: Env; Variables: AuthVars }>();
  app.get('/protected', requireAuth, (c) => {
    return c.json({
      userId: c.get('userId'),
      email: c.get('email'),
      jti: c.get('jti'),
    });
  });
  return app;
}

describe('requireAuth middleware', () => {
  it('rejects missing Authorization header', async () => {
    const app = buildApp();
    const res = await app.fetch(new Request('http://x/protected'), mockEnv);
    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.success).toBe(false);
  });

  it('rejects malformed Authorization header', async () => {
    const app = buildApp();
    const res = await app.fetch(
      new Request('http://x/protected', { headers: { Authorization: 'Token abc' } }),
      mockEnv
    );
    expect(res.status).toBe(401);
  });

  it('rejects an invalid bearer token', async () => {
    const app = buildApp();
    const res = await app.fetch(
      new Request('http://x/protected', { headers: { Authorization: 'Bearer not-a-jwt' } }),
      mockEnv
    );
    expect(res.status).toBe(401);
  });

  it('accepts a valid bearer token and exposes claims via context', async () => {
    const jwtService = new JWTService(mockEnv);
    const { token } = await jwtService.createToken('user-123', 'u@example.com', 60);
    const app = buildApp();
    const res = await app.fetch(
      new Request('http://x/protected', { headers: { Authorization: `Bearer ${token}` } }),
      mockEnv
    );
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.userId).toBe('user-123');
    expect(body.email).toBe('u@example.com');
    expect(body.jti).toBeTruthy();
  });
});
