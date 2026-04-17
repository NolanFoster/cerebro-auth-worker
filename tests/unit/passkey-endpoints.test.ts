import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = vi.hoisted(() => ({
  generateRegistrationOptions: vi.fn(),
  verifyRegistrationResponse: vi.fn(),
  generateAuthenticationOptions: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
}));

vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
}));

vi.mock('@simplewebauthn/server/helpers', () => ({
  isoBase64URL: {
    // @ts-ignore - Buffer available in Node test env
    fromBuffer: (buf: Uint8Array) =>
      // @ts-ignore
      Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    // @ts-ignore
    toBuffer: (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
  },
  isoUint8Array: {
    fromUTF8String: (s: string) => new TextEncoder().encode(s),
  },
}));

beforeAll(async () => {
  // @ts-ignore - Node.js crypto import for test environment
  const { webcrypto } = await import('node:crypto');
  if (!(globalThis as any).crypto) {
    (globalThis as any).crypto = webcrypto;
  }
});

class MockKVNamespace {
  store = new Map<string, { value: string; expiration?: number }>();
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
    const expiration = options?.expirationTtl ? Date.now() + options.expirationTtl * 1000 : undefined;
    this.store.set(key, { value, expiration });
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  async list(): Promise<any> {
    return { keys: [] };
  }
  async getWithMetadata(): Promise<any> {
    return { value: null, metadata: null };
  }
}

async function buildEnv() {
  const kv = new MockKVNamespace();
  return {
    env: {
      OTP_KV: kv as unknown as KVNamespace,
      ENVIRONMENT: 'preview' as const,
      JWT_SECRET: 'test-secret-key-for-jwt-signing-32-chars-long',
      JWT_ISSUER: 'https://auth-worker.test',
      JWT_AUDIENCE: 'test-app',
      RP_ID: 'example.com',
      RP_NAME: 'Example',
      RP_ORIGINS: 'https://example.com',
      FROM_EMAIL: 'test@example.com',
      send_email: { send: vi.fn().mockResolvedValue(undefined) } as any,
    },
    kv,
  };
}

async function bearerFor(env: any, userId: string, email: string): Promise<string> {
  const { JWTService } = await import('../../src/services/jwt-service');
  const svc = new JWTService(env);
  const { token } = await svc.createToken(userId, email, 300);
  return token!;
}

describe('passkey endpoints', () => {
  beforeEach(() => {
    generateRegistrationOptions.mockReset();
    verifyRegistrationResponse.mockReset();
    generateAuthenticationOptions.mockReset();
    verifyAuthenticationResponse.mockReset();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve({}) }));
  });

  describe('POST /passkey/register/options', () => {
    it('requires auth', async () => {
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const res = await app.fetch(new Request('http://x/passkey/register/options', { method: 'POST' }), env);
      expect(res.status).toBe(401);
    });

    it('returns options and persists the challenge', async () => {
      generateRegistrationOptions.mockResolvedValue({ challenge: 'reg-chal', rp: { id: 'example.com' } });
      const app = (await import('../../src/index')).default;
      const { env, kv } = await buildEnv();
      const token = await bearerFor(env, 'user-1', 'u@example.com');

      const res = await app.fetch(
        new Request('http://x/passkey/register/options', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.options.challenge).toBe('reg-chal');
      expect(await kv.get('pk:chal:reg:user-1')).toContain('reg-chal');
    });
  });

  describe('POST /passkey/register/verify', () => {
    it('rejects when challenge is missing', async () => {
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const token = await bearerFor(env, 'user-1', 'u@example.com');
      const res = await app.fetch(
        new Request('http://x/passkey/register/verify', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: { foo: 'bar' } }),
        }),
        env
      );
      expect(res.status).toBe(400);
    });

    it('rejects body missing response', async () => {
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const token = await bearerFor(env, 'user-1', 'u@example.com');
      const res = await app.fetch(
        new Request('http://x/passkey/register/verify', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }),
        env
      );
      expect(res.status).toBe(400);
    });

    it('saves credential on successful verification', async () => {
      generateRegistrationOptions.mockResolvedValue({ challenge: 'reg-chal' });
      verifyRegistrationResponse.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'new-cred',
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
            transports: ['internal'],
          },
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
        },
      });

      const app = (await import('../../src/index')).default;
      const { env, kv } = await buildEnv();
      const token = await bearerFor(env, 'user-1', 'u@example.com');

      // First get options to seed challenge
      await app.fetch(
        new Request('http://x/passkey/register/options', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );

      const res = await app.fetch(
        new Request('http://x/passkey/register/verify', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: { id: 'new-cred' }, name: 'Phone' }),
        }),
        env
      );
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.success).toBe(true);
      expect(body.credential.credentialId).toBe('new-cred');
      expect(body.credential.name).toBe('Phone');
      expect(await kv.get('pk:cred:new-cred')).toBeTruthy();
    });

    it('returns 400 when verification fails', async () => {
      generateRegistrationOptions.mockResolvedValue({ challenge: 'reg-chal' });
      verifyRegistrationResponse.mockResolvedValue({ verified: false });

      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const token = await bearerFor(env, 'user-2', 'v@example.com');

      await app.fetch(
        new Request('http://x/passkey/register/options', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );

      const res = await app.fetch(
        new Request('http://x/passkey/register/verify', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: { id: 'x' } }),
        }),
        env
      );
      expect(res.status).toBe(400);
    });
  });

  describe('POST /passkey/authenticate/options', () => {
    it('issues options with empty allowCredentials when no email given', async () => {
      generateAuthenticationOptions.mockResolvedValue({ challenge: 'auth-chal' });
      const app = (await import('../../src/index')).default;
      const { env, kv } = await buildEnv();

      const res = await app.fetch(
        new Request('http://x/passkey/authenticate/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }),
        env
      );
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.sessionId).toBeTruthy();
      expect(body.options.challenge).toBe('auth-chal');
      expect(await kv.get(`pk:chal:auth:${body.sessionId}`)).toBeTruthy();
    });
  });

  describe('POST /passkey/authenticate/verify', () => {
    it('rejects missing sessionId', async () => {
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const res = await app.fetch(
        new Request('http://x/passkey/authenticate/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: {} }),
        }),
        env
      );
      expect(res.status).toBe(400);
    });

    it('rejects unknown sessionId', async () => {
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const res = await app.fetch(
        new Request('http://x/passkey/authenticate/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId: 'nope', response: { id: 'c' } }),
        }),
        env
      );
      expect(res.status).toBe(400);
    });

    it('rejects unknown credential', async () => {
      generateAuthenticationOptions.mockResolvedValue({ challenge: 'auth-chal' });
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();

      const optionsRes = await app.fetch(
        new Request('http://x/passkey/authenticate/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }),
        env
      );
      const { sessionId } = (await optionsRes.json()) as any;

      const res = await app.fetch(
        new Request('http://x/passkey/authenticate/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId, response: { id: 'does-not-exist' } }),
        }),
        env
      );
      expect(res.status).toBe(404);
    });

    it('returns JWT on successful assertion and updates counter', async () => {
      generateRegistrationOptions.mockResolvedValue({ challenge: 'reg-chal' });
      verifyRegistrationResponse.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'cred-happy',
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
            transports: ['internal'],
          },
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
        },
      });
      generateAuthenticationOptions.mockResolvedValue({ challenge: 'auth-chal' });
      verifyAuthenticationResponse.mockResolvedValue({
        verified: true,
        authenticationInfo: { credentialID: 'cred-happy', newCounter: 5 },
      });

      const app = (await import('../../src/index')).default;
      const { env, kv } = await buildEnv();
      const token = await bearerFor(env, 'user-happy', 'happy@example.com');

      // Register first
      await app.fetch(
        new Request('http://x/passkey/register/options', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );
      await app.fetch(
        new Request('http://x/passkey/register/verify', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: { id: 'cred-happy' } }),
        }),
        env
      );

      // Now authenticate
      const optionsRes = await app.fetch(
        new Request('http://x/passkey/authenticate/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }),
        env
      );
      const { sessionId } = (await optionsRes.json()) as any;

      const verifyRes = await app.fetch(
        new Request('http://x/passkey/authenticate/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId, response: { id: 'cred-happy' } }),
        }),
        env
      );
      expect(verifyRes.status).toBe(200);
      const body = await verifyRes.json() as any;
      expect(body.token).toBeTruthy();
      expect(body.user.id).toBe('user-happy');

      const stored = JSON.parse((await kv.get('pk:cred:cred-happy'))!);
      expect(stored.counter).toBe(5);
      expect(stored.lastUsedAt).toBeGreaterThan(0);
    });

    it('returns 401 when library fails to verify assertion', async () => {
      generateRegistrationOptions.mockResolvedValue({ challenge: 'reg-chal' });
      verifyRegistrationResponse.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'cred-fail',
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
            transports: ['internal'],
          },
          credentialDeviceType: 'singleDevice',
          credentialBackedUp: false,
        },
      });
      generateAuthenticationOptions.mockResolvedValue({ challenge: 'auth-chal' });
      verifyAuthenticationResponse.mockResolvedValue({
        verified: false,
        authenticationInfo: { credentialID: 'cred-fail', newCounter: 0 },
      });

      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const token = await bearerFor(env, 'user-fail', 'fail@example.com');

      await app.fetch(
        new Request('http://x/passkey/register/options', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );
      await app.fetch(
        new Request('http://x/passkey/register/verify', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: { id: 'cred-fail' } }),
        }),
        env
      );

      const optionsRes = await app.fetch(
        new Request('http://x/passkey/authenticate/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }),
        env
      );
      const { sessionId } = (await optionsRes.json()) as any;

      const res = await app.fetch(
        new Request('http://x/passkey/authenticate/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sessionId, response: { id: 'cred-fail' } }),
        }),
        env
      );
      expect(res.status).toBe(401);
    });
  });

  describe('GET /passkey/list', () => {
    it('requires auth', async () => {
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const res = await app.fetch(new Request('http://x/passkey/list'), env);
      expect(res.status).toBe(401);
    });

    it('lists registered credentials for the caller', async () => {
      generateRegistrationOptions.mockResolvedValue({ challenge: 'reg-chal' });
      verifyRegistrationResponse.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'listed-cred',
            publicKey: new Uint8Array([9]),
            counter: 0,
            transports: ['internal'],
          },
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
        },
      });
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const token = await bearerFor(env, 'user-list', 'l@example.com');

      await app.fetch(
        new Request('http://x/passkey/register/options', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );
      await app.fetch(
        new Request('http://x/passkey/register/verify', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ response: { id: 'listed-cred' }, name: 'MacBook' }),
        }),
        env
      );

      const res = await app.fetch(
        new Request('http://x/passkey/list', {
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.credentials).toHaveLength(1);
      expect(body.credentials[0].name).toBe('MacBook');
    });
  });

  describe('DELETE /passkey/:credentialId', () => {
    it('returns 404 for unknown credential', async () => {
      const app = (await import('../../src/index')).default;
      const { env } = await buildEnv();
      const token = await bearerFor(env, 'user-del', 'd@example.com');
      const res = await app.fetch(
        new Request('http://x/passkey/missing', {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` },
        }),
        env
      );
      expect(res.status).toBe(404);
    });
  });
});
