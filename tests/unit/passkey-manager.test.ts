import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import {
  storeRegChallenge,
  consumeRegChallenge,
  storeAuthChallenge,
  consumeAuthChallenge,
  saveCredential,
  getCredential,
  saveCredentialCounter,
  updateCredentialCounter,
  listUserCredentialHints,
  listUserCredentials,
  deleteCredential,
  type CredentialRecord,
} from '../../src/utils/passkey-manager';

beforeAll(async () => {
  // @ts-ignore - Node.js crypto import for test environment
  const { webcrypto } = await import('node:crypto');
  if (!(globalThis as any).crypto) {
    (globalThis as any).crypto = webcrypto;
  }
});

class MockKVNamespace {
  private store = new Map<string, { value: string; expiration?: number }>();

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

  keys(): string[] {
    return Array.from(this.store.keys());
  }

  async list(): Promise<any> {
    return { keys: [] };
  }

  async getWithMetadata(): Promise<any> {
    return { value: null, metadata: null };
  }
}

const sampleCredential = (overrides: Partial<CredentialRecord> = {}): CredentialRecord => ({
  credentialId: 'cred-1',
  userId: 'user-abc',
  email: 'user@example.com',
  publicKey: 'pk-base64url',
  counter: 0,
  transports: ['internal'],
  deviceType: 'multiDevice',
  backedUp: true,
  name: 'My Passkey',
  createdAt: 1_700_000_000_000,
  ...overrides,
});

describe('passkey-manager', () => {
  let kv: MockKVNamespace;

  beforeEach(() => {
    kv = new MockKVNamespace();
  });

  describe('registration challenges', () => {
    it('stores and consumes a registration challenge exactly once, even under concurrency', async () => {
      await storeRegChallenge(kv as unknown as KVNamespace, {
        challenge: 'chal-1',
        userId: 'user-1',
        email: 'a@example.com',
        createdAt: Date.now(),
      });

      const [first, second] = await Promise.all([
        consumeRegChallenge(kv as unknown as KVNamespace, 'user-1'),
        consumeRegChallenge(kv as unknown as KVNamespace, 'user-1'),
      ]);
      const nonNull = [first, second].filter(Boolean);
      expect(nonNull).toHaveLength(1);
      expect(nonNull[0]?.challenge).toBe('chal-1');
    });

    it('returns null for a missing challenge', async () => {
      const result = await consumeRegChallenge(kv as unknown as KVNamespace, 'does-not-exist');
      expect(result).toBeNull();
    });
  });

  describe('authentication challenges', () => {
    it('stores and consumes an auth challenge atomically under concurrent calls', async () => {
      await storeAuthChallenge(kv as unknown as KVNamespace, 'sess-1', {
        challenge: 'auth-chal',
        allowCredentialIds: ['c1'],
        email: 'a@example.com',
        createdAt: Date.now(),
      });

      const [first, second] = await Promise.all([
        consumeAuthChallenge(kv as unknown as KVNamespace, 'sess-1'),
        consumeAuthChallenge(kv as unknown as KVNamespace, 'sess-1'),
      ]);
      const claimed = [first, second].filter(Boolean);
      expect(claimed).toHaveLength(1);
      expect(claimed[0]?.challenge).toBe('auth-chal');
      expect(claimed[0]?.allowCredentialIds).toEqual(['c1']);

      const third = await consumeAuthChallenge(kv as unknown as KVNamespace, 'sess-1');
      expect(third).toBeNull();
    });
  });

  describe('credential CRUD', () => {
    it('saves a credential and adds it to the user index exactly once', async () => {
      const cred = sampleCredential();
      await saveCredential(kv as unknown as KVNamespace, cred);

      const stored = await getCredential(kv as unknown as KVNamespace, cred.credentialId);
      expect(stored).not.toBeNull();
      expect(stored?.email).toBe(cred.email);

      // idempotent save — index should not duplicate
      await saveCredential(kv as unknown as KVNamespace, cred);
      const list = await listUserCredentials(kv as unknown as KVNamespace, cred.userId);
      expect(list).toHaveLength(1);
    });

    it('lists credential hints in a single KV read without N+1 credential lookups', async () => {
      const credA = sampleCredential({ credentialId: 'a', transports: ['internal'] });
      const credB = sampleCredential({ credentialId: 'b', transports: ['hybrid', 'usb'] });
      await saveCredential(kv as unknown as KVNamespace, credA);
      await saveCredential(kv as unknown as KVNamespace, credB);

      const getSpy = vi.spyOn(kv, 'get');
      const hints = await listUserCredentialHints(kv as unknown as KVNamespace, credA.userId);

      expect(hints).toEqual([
        { credentialId: 'a', transports: ['internal'] },
        { credentialId: 'b', transports: ['hybrid', 'usb'] },
      ]);
      expect(getSpy).toHaveBeenCalledTimes(1);
      expect(getSpy).toHaveBeenCalledWith(`pk:user:${credA.userId}:creds`);
    });

    it('falls back to reading credential records when legacy index lacks inline hints', async () => {
      const cred = sampleCredential({ credentialId: 'legacy-1', transports: ['ble'] });
      await (kv as unknown as KVNamespace).put(`pk:cred:${cred.credentialId}`, JSON.stringify(cred));
      await (kv as unknown as KVNamespace).put(
        `pk:user:${cred.userId}:creds`,
        JSON.stringify({ credentialIds: [cred.credentialId] })
      );

      const hints = await listUserCredentialHints(kv as unknown as KVNamespace, cred.userId);
      expect(hints).toEqual([{ credentialId: 'legacy-1', transports: ['ble'] }]);
    });

    it('lists credentials for the correct user only', async () => {
      const credA = sampleCredential({ credentialId: 'a', userId: 'user-a' });
      const credB = sampleCredential({ credentialId: 'b', userId: 'user-b' });
      await saveCredential(kv as unknown as KVNamespace, credA);
      await saveCredential(kv as unknown as KVNamespace, credB);

      const listA = await listUserCredentials(kv as unknown as KVNamespace, 'user-a');
      expect(listA.map((c) => c.credentialId)).toEqual(['a']);
    });

    it('returns [] when the user has no credentials', async () => {
      const result = await listUserCredentials(kv as unknown as KVNamespace, 'unknown-user');
      expect(result).toEqual([]);
      expect(await listUserCredentialHints(kv as unknown as KVNamespace, 'unknown-user')).toEqual([]);
    });

    it('never regresses counter when concurrent updates arrive out of order with stale snapshots', async () => {
      const initial = sampleCredential({ counter: 0 });
      await saveCredential(kv as unknown as KVNamespace, initial);

      // Both concurrent callers read the same initial snapshot (counter: 0),
      // then the higher counter (2) writes before the stale lower counter (1).
      const snapshotA = (await getCredential(kv as unknown as KVNamespace, initial.credentialId))!;
      const snapshotB = (await getCredential(kv as unknown as KVNamespace, initial.credentialId))!;

      await Promise.all([
        saveCredentialCounter(kv as unknown as KVNamespace, snapshotA, 2, 1_700_000_002_000),
        saveCredentialCounter(kv as unknown as KVNamespace, snapshotB, 1, 1_700_000_001_000),
      ]);

      const rawPersisted = JSON.parse(
        (await kv.get(`pk:cred:${initial.credentialId}`))!
      ) as CredentialRecord;
      expect(rawPersisted.counter).toBe(2);
      expect(rawPersisted.lastUsedAt).toBe(1_700_000_002_000);

      const ok = await updateCredentialCounter(
        kv as unknown as KVNamespace,
        initial.credentialId,
        42,
        1_700_000_003_000
      );
      expect(ok).toBe(true);

      const updated = await getCredential(kv as unknown as KVNamespace, initial.credentialId);
      expect(updated?.counter).toBe(42);
      expect(updated?.lastUsedAt).toBe(1_700_000_003_000);
    });

    it('returns false when updating counter of missing credential', async () => {
      const ok = await updateCredentialCounter(
        kv as unknown as KVNamespace,
        'missing',
        1,
        Date.now()
      );
      expect(ok).toBe(false);
    });

    it('deletes credential and removes it from both user index arrays', async () => {
      const cred = sampleCredential();
      await saveCredential(kv as unknown as KVNamespace, cred);

      const deleted = await deleteCredential(
        kv as unknown as KVNamespace,
        cred.userId,
        cred.credentialId
      );
      expect(deleted).toBe(true);

      expect(await getCredential(kv as unknown as KVNamespace, cred.credentialId)).toBeNull();
      expect(await listUserCredentials(kv as unknown as KVNamespace, cred.userId)).toEqual([]);
      expect(await listUserCredentialHints(kv as unknown as KVNamespace, cred.userId)).toEqual([]);
    });

    it('refuses to delete a credential owned by a different user', async () => {
      const cred = sampleCredential({ userId: 'owner' });
      await saveCredential(kv as unknown as KVNamespace, cred);

      const deleted = await deleteCredential(
        kv as unknown as KVNamespace,
        'attacker',
        cred.credentialId
      );
      expect(deleted).toBe(false);

      expect(await getCredential(kv as unknown as KVNamespace, cred.credentialId)).not.toBeNull();
    });

    it('returns false deleting a non-existent credential', async () => {
      const deleted = await deleteCredential(kv as unknown as KVNamespace, 'u', 'nope');
      expect(deleted).toBe(false);
    });

    it('returns null for malformed credential JSON', async () => {
      await (kv as unknown as KVNamespace).put('pk:cred:broken', '{not-json');
      const result = await getCredential(kv as unknown as KVNamespace, 'broken');
      expect(result).toBeNull();
    });
  });
});
