import { describe, it, expect, beforeEach, vi } from 'vitest';
import { recordLogin } from '../../src/services/user-sync';
import type { Env } from '../../src/types/env';

function env(overrides: Partial<Env> = {}): Env {
  return {
    OTP_KV: {} as any,
    ENVIRONMENT: 'preview',
    JWT_SECRET: 's',
    JWT_ISSUER: 'i',
    JWT_AUDIENCE: 'a',
    RP_ID: 'example.com',
    RP_NAME: 'Example',
    RP_ORIGINS: 'https://example.com',
    send_email: { send: vi.fn() } as any,
    ...overrides,
  } as Env;
}

describe('recordLogin', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('no-ops when USER_MANAGEMENT_WORKER_URL is not set', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    await recordLogin(env(), { userId: 'u', email: 'e@x.com', method: 'OTP' });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('skips user creation when user already exists', async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    await recordLogin(
      env({ USER_MANAGEMENT_WORKER_URL: 'https://ums.test' }),
      { userId: 'u1', email: 'e@x.com', method: 'PASSKEY', ipAddress: '1.2.3.4', userAgent: 'UA' }
    );

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(fetchSpy.mock.calls[0][0]).toBe('https://ums.test/users/email/u1');
    expect(fetchSpy.mock.calls[1][0]).toBe('https://ums.test/login-history');
    const body = JSON.parse(fetchSpy.mock.calls[1][1].body);
    expect(body.login_method).toBe('PASSKEY');
    expect(body.ip_address).toBe('1.2.3.4');
    expect(body.user_agent).toBe('UA');
  });

  it('creates user when lookup 404s', async () => {
    const fetchSpy = vi.fn()
      .mockResolvedValueOnce({ ok: false })
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce({ ok: true });
    vi.stubGlobal('fetch', fetchSpy);

    await recordLogin(
      env({ USER_MANAGEMENT_WORKER_URL: 'https://ums.test' }),
      { userId: 'new-user', email: 'new@x.com', method: 'OTP' }
    );

    expect(fetchSpy).toHaveBeenCalledTimes(3);
    expect(fetchSpy.mock.calls[1][0]).toBe('https://ums.test/users');
    expect(fetchSpy.mock.calls[1][1].method).toBe('POST');
  });

  it('swallows fetch errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network down')));
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await expect(
      recordLogin(
        env({ USER_MANAGEMENT_WORKER_URL: 'https://ums.test' }),
        { userId: 'u', email: 'e@x.com', method: 'OTP' }
      )
    ).resolves.toBeUndefined();
    expect(errSpy).toHaveBeenCalled();
  });

  it('logs when userId is empty', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await recordLogin(
      env({ USER_MANAGEMENT_WORKER_URL: 'https://ums.test' }),
      { userId: '', email: 'e@x.com', method: 'OTP' }
    );
    expect(errSpy).toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
