import { describe, it, expect, vi, beforeEach } from 'vitest';
import app from '@/index';
import { Env } from '@/types/env';

interface HealthResponse {
  status: string;
  timestamp: string;
  environment: string;
  services: {
    otp_kv: string;
    user_management: string;
    email: string;
  };
}

describe('Health Endpoint', () => {
  let mockEnv: Env;

  beforeEach(() => {
    mockEnv = {
      OTP_KV: {
        put: vi.fn(),
        get: vi.fn(),
      } as unknown as KVNamespace,
      USER_MANAGEMENT_WORKER_URL: 'https://user-management-worker-preview.your-domain.workers.dev',
      ENVIRONMENT: 'preview',
      JWT_SECRET: 'test-jwt-secret',
      JWT_ISSUER: 'https://auth-worker.test',
      JWT_AUDIENCE: 'test-app',
      send_email: {
        send: vi.fn().mockResolvedValue(undefined)
      }
    };
  });

  it('should skip user management health when URL is not configured', async () => {
    vi.mocked(mockEnv.OTP_KV.put).mockResolvedValue(undefined);
    vi.mocked(mockEnv.OTP_KV.get).mockResolvedValue('test-value' as any);

    const envNoUm = { ...mockEnv, USER_MANAGEMENT_WORKER_URL: undefined };

    const req = new Request('http://localhost/health', { method: 'GET' });
    const response = await app.fetch(req, envNoUm);
    const data = await response.json() as HealthResponse;

    expect(response.status).toBe(200);
    expect(data.status).toBe('healthy');
    expect(data.services.user_management).toBe('skipped');
    expect(data.services.otp_kv).toBe('healthy');
    expect(data.services.email).toBe('healthy');
  });

  it('should return healthy when all services are operational', async () => {
    // Mock successful OTP_KV operations
    vi.mocked(mockEnv.OTP_KV.put).mockResolvedValue(undefined);
    vi.mocked(mockEnv.OTP_KV.get).mockResolvedValue('test-value' as any);

    // Mock successful User Management Worker health check
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200
    } as Response));

    const req = new Request('http://localhost/health', { method: 'GET' });
    const response = await app.fetch(req, mockEnv);
    const data = await response.json() as HealthResponse;

    expect(response.status).toBe(200);
    expect(data.status).toBe('healthy');
    expect(data.services.otp_kv).toBe('healthy');
    expect(data.services.user_management).toBe('healthy');
    expect(data.services.email).toBe('healthy');
    expect(data.environment).toBe('preview');
  });

  it('should return degraded when OTP_KV is unhealthy', async () => {
    // Mock failed OTP_KV operations
    vi.mocked(mockEnv.OTP_KV.put).mockRejectedValue(new Error('OTP_KV Error'));

    // Mock successful User Management Worker health check
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200
    } as Response));

    const req = new Request('http://localhost/health', { method: 'GET' });
    const response = await app.fetch(req, mockEnv);
    const data = await response.json() as HealthResponse;

    expect(response.status).toBe(503);
    expect(data.status).toBe('degraded');
    expect(data.services.otp_kv).toBe('unhealthy');
    expect(data.services.user_management).toBe('healthy');
    expect(data.services.email).toBe('healthy');
  });

  it('should return degraded when User Management Worker is unhealthy', async () => {
    // Mock successful OTP_KV operations
    vi.mocked(mockEnv.OTP_KV.put).mockResolvedValue(undefined);
    vi.mocked(mockEnv.OTP_KV.get).mockResolvedValue('test-value' as any);

    // Mock failed User Management Worker health check
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network Error')));

    const req = new Request('http://localhost/health', { method: 'GET' });
    const response = await app.fetch(req, mockEnv);
    const data = await response.json() as HealthResponse;

    expect(response.status).toBe(503);
    expect(data.status).toBe('degraded');
    expect(data.services.otp_kv).toBe('healthy');
    expect(data.services.user_management).toBe('unhealthy');
    expect(data.services.email).toBe('healthy');
  });

  it('should return degraded when email binding is unhealthy', async () => {
    // Mock successful OTP_KV operations
    vi.mocked(mockEnv.OTP_KV.put).mockResolvedValue(undefined);
    vi.mocked(mockEnv.OTP_KV.get).mockResolvedValue('test-value' as any);

    // Mock successful User Management Worker health check
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200
    } as Response));

    // Create environment without send_email binding to make email unhealthy
    const envWithoutEmail = {
      ...mockEnv,
      send_email: undefined as any
    };

    const req = new Request('http://localhost/health', { method: 'GET' });
    const response = await app.fetch(req, envWithoutEmail);
    const data = await response.json() as HealthResponse;

    expect(response.status).toBe(503);
    expect(data.status).toBe('degraded');
    expect(data.services.otp_kv).toBe('healthy');
    expect(data.services.user_management).toBe('healthy');
    expect(data.services.email).toBe('unhealthy');
  });

  it('should return unhealthy when all services are down', async () => {
    // Mock failed OTP_KV operations
    vi.mocked(mockEnv.OTP_KV.put).mockRejectedValue(new Error('OTP_KV Error'));

    // Mock failed User Management Worker health check
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network Error')));

    // Create environment without send_email binding to make email unhealthy
    const envWithoutEmail = {
      ...mockEnv,
      send_email: undefined as any
    };

    const req = new Request('http://localhost/health', { method: 'GET' });
    const response = await app.fetch(req, envWithoutEmail);
    const data = await response.json() as HealthResponse;

    expect(response.status).toBe(500);
    expect(data.status).toBe('unhealthy');
    expect(data.services.otp_kv).toBe('unhealthy');
    expect(data.services.user_management).toBe('unhealthy');
    expect(data.services.email).toBe('unhealthy');
  });
});