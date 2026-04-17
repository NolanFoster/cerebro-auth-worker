import { describe, it, expect, beforeEach, vi } from 'vitest';

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

import { PasskeyService } from '../../src/services/passkey-service';
import type { Env } from '../../src/types/env';
import type { CredentialRecord } from '../../src/utils/passkey-manager';

const baseEnv = (): Env =>
  ({
    OTP_KV: {} as any,
    ENVIRONMENT: 'preview',
    JWT_SECRET: 's',
    JWT_ISSUER: 'i',
    JWT_AUDIENCE: 'a',
    RP_ID: 'example.com',
    RP_NAME: 'Example',
    RP_ORIGINS: 'https://example.com, https://app.example.com',
    send_email: { send: vi.fn() } as any,
  }) as Env;

describe('PasskeyService', () => {
  beforeEach(() => {
    generateRegistrationOptions.mockReset();
    verifyRegistrationResponse.mockReset();
    generateAuthenticationOptions.mockReset();
    verifyAuthenticationResponse.mockReset();
  });

  describe('constructor validation', () => {
    it('throws when RP_ID missing', () => {
      expect(() => new PasskeyService({ ...baseEnv(), RP_ID: '' })).toThrow(/RP_ID/);
    });
    it('throws when RP_NAME missing', () => {
      expect(() => new PasskeyService({ ...baseEnv(), RP_NAME: '   ' })).toThrow(/RP_NAME/);
    });
    it('throws when RP_ORIGINS missing', () => {
      expect(() => new PasskeyService({ ...baseEnv(), RP_ORIGINS: '' })).toThrow(/RP_ORIGINS/);
    });
    it('throws when RP_ORIGINS has no valid entries', () => {
      expect(() => new PasskeyService({ ...baseEnv(), RP_ORIGINS: ',,' })).toThrow(/RP_ORIGINS/);
    });
  });

  describe('generateRegistration', () => {
    it('forwards RP info and exclude list; returns challenge', async () => {
      generateRegistrationOptions.mockResolvedValue({
        challenge: 'abc',
        rp: { id: 'example.com', name: 'Example' },
      });
      const svc = new PasskeyService(baseEnv());
      const result = await svc.generateRegistration('user-1', 'u@example.com', [
        { id: 'old-cred', transports: ['internal'] },
      ]);

      expect(generateRegistrationOptions).toHaveBeenCalledTimes(1);
      const call = generateRegistrationOptions.mock.calls[0][0];
      expect(call.rpID).toBe('example.com');
      expect(call.rpName).toBe('Example');
      expect(call.userName).toBe('u@example.com');
      expect(call.excludeCredentials).toEqual([{ id: 'old-cred', transports: ['internal'] }]);
      expect(result.challenge).toBe('abc');
    });
  });

  describe('verifyRegistration', () => {
    it('maps verified library result to our credential shape', async () => {
      verifyRegistrationResponse.mockResolvedValue({
        verified: true,
        registrationInfo: {
          credential: {
            id: 'new-cred-id',
            publicKey: new Uint8Array([1, 2, 3]),
            counter: 0,
            transports: ['internal', 'hybrid'],
          },
          credentialDeviceType: 'multiDevice',
          credentialBackedUp: true,
        },
      });
      const svc = new PasskeyService(baseEnv());
      const result = await svc.verifyRegistration({} as any, 'chal');

      expect(result.verified).toBe(true);
      expect(result.credentialId).toBe('new-cred-id');
      expect(result.counter).toBe(0);
      expect(result.transports).toEqual(['internal', 'hybrid']);
      expect(result.deviceType).toBe('multiDevice');
      expect(result.backedUp).toBe(true);
      expect(result.publicKey).toBeTruthy();
    });

    it('returns verified:false when library rejects', async () => {
      verifyRegistrationResponse.mockResolvedValue({ verified: false });
      const svc = new PasskeyService(baseEnv());
      const result = await svc.verifyRegistration({} as any, 'chal');
      expect(result.verified).toBe(false);
      expect(result.credentialId).toBeUndefined();
    });

    it('passes the full origins array to the library', async () => {
      verifyRegistrationResponse.mockResolvedValue({ verified: false });
      const svc = new PasskeyService(baseEnv());
      await svc.verifyRegistration({} as any, 'chal');
      const call = verifyRegistrationResponse.mock.calls[0][0];
      expect(call.expectedOrigin).toEqual(['https://example.com', 'https://app.example.com']);
      expect(call.expectedRPID).toBe('example.com');
    });
  });

  describe('generateAuthentication', () => {
    it('forwards allowCredentials when provided', async () => {
      generateAuthenticationOptions.mockResolvedValue({ challenge: 'a-chal' });
      const svc = new PasskeyService(baseEnv());
      await svc.generateAuthentication([{ id: 'c1', transports: ['internal'] }]);

      const call = generateAuthenticationOptions.mock.calls[0][0];
      expect(call.rpID).toBe('example.com');
      expect(call.userVerification).toBe('preferred');
      expect(call.allowCredentials).toEqual([{ id: 'c1', transports: ['internal'] }]);
    });

    it('omits allowCredentials for discoverable-credential flow', async () => {
      generateAuthenticationOptions.mockResolvedValue({ challenge: 'a-chal' });
      const svc = new PasskeyService(baseEnv());
      await svc.generateAuthentication();
      const call = generateAuthenticationOptions.mock.calls[0][0];
      expect(call.allowCredentials).toBeUndefined();
    });
  });

  describe('verifyAuthentication', () => {
    const stored: CredentialRecord = {
      credentialId: 'cred-1',
      userId: 'user-1',
      email: 'u@example.com',
      publicKey: 'AQID',
      counter: 7,
      transports: ['internal'],
      deviceType: 'singleDevice',
      backedUp: false,
      name: 'p',
      createdAt: 0,
    };

    it('returns newCounter from library on success', async () => {
      verifyAuthenticationResponse.mockResolvedValue({
        verified: true,
        authenticationInfo: { credentialID: 'cred-1', newCounter: 8 },
      });
      const svc = new PasskeyService(baseEnv());
      const result = await svc.verifyAuthentication({} as any, 'chal', stored);
      expect(result.verified).toBe(true);
      expect(result.newCounter).toBe(8);
      expect(result.credentialId).toBe('cred-1');
    });

    it('returns verified:false when library fails verification', async () => {
      verifyAuthenticationResponse.mockResolvedValue({
        verified: false,
        authenticationInfo: { credentialID: 'cred-1', newCounter: 7 },
      });
      const svc = new PasskeyService(baseEnv());
      const result = await svc.verifyAuthentication({} as any, 'chal', stored);
      expect(result.verified).toBe(false);
    });
  });
});
