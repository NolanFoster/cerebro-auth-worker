import { describe, it, expect, vi } from 'vitest';
import { Hono } from 'hono';
import { Env } from '@/types/env';

describe('Error Handler', () => {
  it('should handle errors properly', async () => {
    const app = new Hono<{ Bindings: Env }>();
    
    // Add a route that throws an error
    app.get('/error', () => {
      throw new Error('Test error');
    });

    // Add the error handler
    app.onError((err, c) => {
      console.error(`Error handling request: ${err}`);
      return c.json({
        error: 'Internal Server Error',
        message: err.message || 'An unexpected error occurred'
      }, 500);
    });

      const mockEnv: Env = {
    OTP_KV: {} as KVNamespace,
    USER_MANAGEMENT_WORKER_URL: 'https://user-management-worker-preview.your-domain.workers.dev',
    ENVIRONMENT: 'preview',
    JWT_SECRET: 'test-jwt-secret',
    JWT_ISSUER: 'https://auth-worker.test',
    JWT_AUDIENCE: 'test-app',
    RP_ID: 'example.com',
    RP_NAME: 'Example',
    RP_ORIGINS: 'https://example.com',
    send_email: {
      send: async () => {}
    }
  };

    // Spy on console.error
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const req = new Request('http://localhost/error', { method: 'GET' });
    const response = await app.fetch(req, mockEnv);
    const data = await response.json() as any;

    expect(response.status).toBe(500);
    expect(data.error).toBe('Internal Server Error');
    expect(data.message).toBe('Test error');
    expect(consoleErrorSpy).toHaveBeenCalledWith('Error handling request: Error: Test error');

    consoleErrorSpy.mockRestore();
  });
});