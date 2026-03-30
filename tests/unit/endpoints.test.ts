import { describe, it, expect } from 'vitest';
import app from '@/index';
import { Env } from '@/types/env';

describe('Root Endpoint', () => {
  const mockEnv: Env = {
    OTP_KV: {} as KVNamespace,
    USER_MANAGEMENT_WORKER_URL: 'https://user-management-worker-preview.your-domain.workers.dev',
    ENVIRONMENT: 'preview',
    JWT_SECRET: 'test-jwt-secret',
    JWT_ISSUER: 'https://auth-worker.test',
    JWT_AUDIENCE: 'test-app',
    send_email: {
      send: async () => {}
    }
  };

  it('should return worker information', async () => {
    const req = new Request('http://localhost/', { method: 'GET' });
    const response = await app.fetch(req, mockEnv);
    const data = await response.json() as any;

    expect(response.status).toBe(200);
    expect(data.name).toBe('auth-worker');
    expect(data.version).toBe('1.0.0');
    expect(data.endpoints).toBeInstanceOf(Array);
    expect(data.endpoints[0].path).toBe('/health');
  });
});

describe('404 Handler', () => {
  const mockEnv: Env = {
    OTP_KV: {} as KVNamespace,
    USER_MANAGEMENT_WORKER_URL: 'https://user-management-worker-preview.your-domain.workers.dev',
    ENVIRONMENT: 'preview',
    JWT_SECRET: 'test-jwt-secret',
    JWT_ISSUER: 'https://auth-worker.test',
    JWT_AUDIENCE: 'test-app',
    send_email: {
      send: async () => {}
    }
  };

  it('should return 404 for unknown endpoints', async () => {
    const req = new Request('http://localhost/unknown', { method: 'GET' });
    const response = await app.fetch(req, mockEnv);
    const data = await response.json() as any;

    expect(response.status).toBe(404);
    expect(data.error).toBe('Not Found');
    expect(data.message).toContain('/unknown');
  });
});