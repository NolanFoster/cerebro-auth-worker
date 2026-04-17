/**
 * Passkey (WebAuthn) storage utilities backed by the shared OTP_KV namespace.
 *
 * Key layout (prefixed so it cannot collide with OTP entries):
 *   pk:chal:reg:{userId}            — short-lived registration challenge (TTL 300s)
 *   pk:chal:auth:{sessionId}        — short-lived authentication challenge (TTL 300s)
 *   pk:cred:{credentialId}          — credential record (no TTL)
 *   pk:user:{userId}:creds          — index of credentialIds belonging to a user (no TTL)
 */

import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';

export interface RegChallengeRecord {
  challenge: string;
  userId: string;
  email: string;
  createdAt: number;
}

export interface AuthChallengeRecord {
  challenge: string;
  allowCredentialIds: string[];
  email?: string;
  createdAt: number;
}

export interface CredentialRecord {
  credentialId: string;
  userId: string;
  email: string;
  publicKey: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
  name: string;
  createdAt: number;
  lastUsedAt?: number;
}

export interface UserCredentialIndex {
  credentialIds: string[];
}

const CHALLENGE_TTL_SECONDS = 300;

const regChallengeKey = (userId: string) => `pk:chal:reg:${userId}`;
const authChallengeKey = (sessionId: string) => `pk:chal:auth:${sessionId}`;
const credentialKey = (credentialId: string) => `pk:cred:${credentialId}`;
const userIndexKey = (userId: string) => `pk:user:${userId}:creds`;

export async function storeRegChallenge(
  kv: KVNamespace,
  record: RegChallengeRecord
): Promise<void> {
  await kv.put(regChallengeKey(record.userId), JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS,
  });
}

export async function consumeRegChallenge(
  kv: KVNamespace,
  userId: string
): Promise<RegChallengeRecord | null> {
  const key = regChallengeKey(userId);
  const raw = await kv.get(key);
  if (!raw) return null;
  await kv.delete(key);
  try {
    return JSON.parse(raw) as RegChallengeRecord;
  } catch (error) {
    console.error('consumeRegChallenge: failed to parse record', error);
    return null;
  }
}

export async function storeAuthChallenge(
  kv: KVNamespace,
  sessionId: string,
  record: AuthChallengeRecord
): Promise<void> {
  await kv.put(authChallengeKey(sessionId), JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS,
  });
}

export async function consumeAuthChallenge(
  kv: KVNamespace,
  sessionId: string
): Promise<AuthChallengeRecord | null> {
  const key = authChallengeKey(sessionId);
  const raw = await kv.get(key);
  if (!raw) return null;
  await kv.delete(key);
  try {
    return JSON.parse(raw) as AuthChallengeRecord;
  } catch (error) {
    console.error('consumeAuthChallenge: failed to parse record', error);
    return null;
  }
}

export async function saveCredential(
  kv: KVNamespace,
  record: CredentialRecord
): Promise<void> {
  await kv.put(credentialKey(record.credentialId), JSON.stringify(record));

  const indexRaw = await kv.get(userIndexKey(record.userId));
  const index: UserCredentialIndex = indexRaw
    ? (JSON.parse(indexRaw) as UserCredentialIndex)
    : { credentialIds: [] };

  if (!index.credentialIds.includes(record.credentialId)) {
    index.credentialIds.push(record.credentialId);
    await kv.put(userIndexKey(record.userId), JSON.stringify(index));
  }
}

export async function getCredential(
  kv: KVNamespace,
  credentialId: string
): Promise<CredentialRecord | null> {
  const raw = await kv.get(credentialKey(credentialId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as CredentialRecord;
  } catch (error) {
    console.error('getCredential: failed to parse record', error);
    return null;
  }
}

export async function updateCredentialCounter(
  kv: KVNamespace,
  credentialId: string,
  newCounter: number,
  lastUsedAt: number
): Promise<boolean> {
  const existing = await getCredential(kv, credentialId);
  if (!existing) return false;

  const updated: CredentialRecord = {
    ...existing,
    counter: newCounter,
    lastUsedAt,
  };
  await kv.put(credentialKey(credentialId), JSON.stringify(updated));
  return true;
}

export async function listUserCredentials(
  kv: KVNamespace,
  userId: string
): Promise<CredentialRecord[]> {
  const indexRaw = await kv.get(userIndexKey(userId));
  if (!indexRaw) return [];

  let index: UserCredentialIndex;
  try {
    index = JSON.parse(indexRaw) as UserCredentialIndex;
  } catch (error) {
    console.error('listUserCredentials: failed to parse index', error);
    return [];
  }

  const records = await Promise.all(
    index.credentialIds.map((id) => getCredential(kv, id))
  );
  return records.filter((r): r is CredentialRecord => r !== null);
}

export async function deleteCredential(
  kv: KVNamespace,
  userId: string,
  credentialId: string
): Promise<boolean> {
  const existing = await getCredential(kv, credentialId);
  if (!existing || existing.userId !== userId) return false;

  await kv.delete(credentialKey(credentialId));

  const indexRaw = await kv.get(userIndexKey(userId));
  if (indexRaw) {
    try {
      const index = JSON.parse(indexRaw) as UserCredentialIndex;
      const filtered = index.credentialIds.filter((id) => id !== credentialId);
      await kv.put(userIndexKey(userId), JSON.stringify({ credentialIds: filtered }));
    } catch (error) {
      console.error('deleteCredential: failed to update index', error);
    }
  }

  return true;
}
