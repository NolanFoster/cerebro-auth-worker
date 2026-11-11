/**
 * Passkey (WebAuthn) storage utilities backed by the shared OTP_KV namespace.
 *
 * Key layout (prefixed so it cannot collide with OTP entries):
 *   pk:chal:reg:{userId}            — short-lived registration challenge (TTL 300s)
 *   pk:chal:auth:{sessionId}        — short-lived authentication challenge (TTL 300s)
 *   pk:cred:{credentialId}          — credential record (no TTL)
 *   pk:user:{userId}:creds          — index of credentials belonging to a user (no TTL)
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

export interface CredentialHint {
  credentialId: string;
  transports: AuthenticatorTransportFuture[];
}

export interface UserCredentialIndex {
  credentialIds: string[];
  /**
   * Inline transport hints stored alongside `credentialIds` so registration and
   * email-scoped authentication options only require a single KV read instead
   * of an N+1 fan-out across `pk:cred:{id}`. Optional for backward compatibility
   * with legacy index entries that only stored `credentialIds`.
   */
  credentials?: CredentialHint[];
}

const CHALLENGE_TTL_SECONDS = 300;
const MAX_TRACKED_CLAIMS = 10_000;

const regChallengeKey = (userId: string) => `pk:chal:reg:${userId}`;
const authChallengeKey = (sessionId: string) => `pk:chal:auth:${sessionId}`;
const credentialKey = (credentialId: string) => `pk:cred:${credentialId}`;
const userIndexKey = (userId: string) => `pk:user:${userId}:creds`;

// Per-KV-instance synchronous claim sets and per-credential write queues so
// concurrent requests on the same Worker isolate cannot double-consume a
// challenge or roll back a WebAuthn sign counter with an out-of-order snapshot.
const claimedRegChallengesByKv = new WeakMap<KVNamespace, Set<string>>();
const claimedAuthSessionsByKv = new WeakMap<KVNamespace, Set<string>>();
const credentialWriteQueuesByKv = new WeakMap<KVNamespace, Map<string, Promise<unknown>>>();
const credentialHighWaterByKv = new WeakMap<
  KVNamespace,
  Map<string, { counter: number; lastUsedAt: number }>
>();

function getClaimSet(
  map: WeakMap<KVNamespace, Set<string>>,
  kv: KVNamespace
): Set<string> {
  let set = map.get(kv);
  if (!set) {
    set = new Set<string>();
    map.set(kv, set);
  } else if (set.size >= MAX_TRACKED_CLAIMS) {
    const oldest = set.values().next().value;
    if (oldest !== undefined) set.delete(oldest);
  }
  return set;
}

function getHighWaterMap(
  kv: KVNamespace
): Map<string, { counter: number; lastUsedAt: number }> {
  let map = credentialHighWaterByKv.get(kv);
  if (!map) {
    map = new Map();
    credentialHighWaterByKv.set(kv, map);
  }
  return map;
}

function enqueueCredentialWrite<T>(
  kv: KVNamespace,
  credentialId: string,
  op: () => Promise<T>
): Promise<T> {
  let queues = credentialWriteQueuesByKv.get(kv);
  if (!queues) {
    queues = new Map();
    credentialWriteQueuesByKv.set(kv, queues);
  }
  const previous = queues.get(credentialId) ?? Promise.resolve();
  const next = previous.catch(() => undefined).then(op);
  const tracked = next.finally(() => {
    if (queues?.get(credentialId) === tracked) {
      queues.delete(credentialId);
    }
  });
  queues.set(credentialId, tracked);
  return next;
}

export async function storeRegChallenge(
  kv: KVNamespace,
  record: RegChallengeRecord
): Promise<void> {
  getClaimSet(claimedRegChallengesByKv, kv).delete(record.userId);
  await kv.put(regChallengeKey(record.userId), JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS,
  });
}

export async function consumeRegChallenge(
  kv: KVNamespace,
  userId: string
): Promise<RegChallengeRecord | null> {
  const claimed = getClaimSet(claimedRegChallengesByKv, kv);
  if (claimed.has(userId)) return null;
  claimed.add(userId);

  const key = regChallengeKey(userId);
  try {
    const raw = await kv.get(key);
    if (!raw) {
      claimed.delete(userId);
      return null;
    }
    await kv.delete(key);
    return JSON.parse(raw) as RegChallengeRecord;
  } catch (error) {
    console.error('consumeRegChallenge: failed to consume record', error);
    return null;
  }
}

export async function storeAuthChallenge(
  kv: KVNamespace,
  sessionId: string,
  record: AuthChallengeRecord
): Promise<void> {
  getClaimSet(claimedAuthSessionsByKv, kv).delete(sessionId);
  await kv.put(authChallengeKey(sessionId), JSON.stringify(record), {
    expirationTtl: CHALLENGE_TTL_SECONDS,
  });
}

export async function consumeAuthChallenge(
  kv: KVNamespace,
  sessionId: string
): Promise<AuthChallengeRecord | null> {
  const claimed = getClaimSet(claimedAuthSessionsByKv, kv);
  if (claimed.has(sessionId)) return null;
  claimed.add(sessionId);

  const key = authChallengeKey(sessionId);
  try {
    const raw = await kv.get(key);
    if (!raw) {
      claimed.delete(sessionId);
      return null;
    }
    await kv.delete(key);
    return JSON.parse(raw) as AuthChallengeRecord;
  } catch (error) {
    console.error('consumeAuthChallenge: failed to consume record', error);
    return null;
  }
}

export async function saveCredential(
  kv: KVNamespace,
  record: CredentialRecord
): Promise<void> {
  await enqueueCredentialWrite(kv, record.credentialId, async () => {
    getHighWaterMap(kv).set(record.credentialId, {
      counter: record.counter,
      lastUsedAt: record.lastUsedAt ?? 0,
    });

    const [, indexRaw] = await Promise.all([
      kv.put(credentialKey(record.credentialId), JSON.stringify(record)),
      kv.get(userIndexKey(record.userId)),
    ]);

    let index: UserCredentialIndex = { credentialIds: [], credentials: [] };
    if (indexRaw) {
      try {
        const parsed = JSON.parse(indexRaw) as UserCredentialIndex;
        index = {
          credentialIds: Array.isArray(parsed.credentialIds) ? [...parsed.credentialIds] : [],
          credentials: Array.isArray(parsed.credentials) ? [...parsed.credentials] : [],
        };
      } catch (error) {
        console.error('saveCredential: failed to parse existing index', error);
      }
    }

    let changed = false;
    if (!index.credentialIds.includes(record.credentialId)) {
      index.credentialIds.push(record.credentialId);
      changed = true;
    }

    const hint: CredentialHint = {
      credentialId: record.credentialId,
      transports: record.transports,
    };
    const existingHintIdx = index.credentials!.findIndex(
      (c) => c.credentialId === record.credentialId
    );
    if (existingHintIdx === -1) {
      index.credentials!.push(hint);
      changed = true;
    } else if (
      JSON.stringify(index.credentials![existingHintIdx].transports) !==
      JSON.stringify(hint.transports)
    ) {
      index.credentials![existingHintIdx] = hint;
      changed = true;
    }

    if (changed) {
      await kv.put(userIndexKey(record.userId), JSON.stringify(index));
    }
  });
}

export async function getCredential(
  kv: KVNamespace,
  credentialId: string
): Promise<CredentialRecord | null> {
  const raw = await kv.get(credentialKey(credentialId));
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as CredentialRecord;
    const highWater = getHighWaterMap(kv).get(credentialId);
    if (highWater) {
      return {
        ...parsed,
        counter: Math.max(parsed.counter, highWater.counter),
        lastUsedAt:
          parsed.lastUsedAt !== undefined || highWater.lastUsedAt > 0
            ? Math.max(parsed.lastUsedAt ?? 0, highWater.lastUsedAt)
            : undefined,
      };
    }
    return parsed;
  } catch (error) {
    console.error('getCredential: failed to parse record', error);
    return null;
  }
}

export async function saveCredentialCounter(
  kv: KVNamespace,
  existing: CredentialRecord,
  newCounter: number,
  lastUsedAt: number
): Promise<CredentialRecord> {
  return enqueueCredentialWrite(kv, existing.credentialId, async () => {
    const highWaterMap = getHighWaterMap(kv);
    const prevHighWater = highWaterMap.get(existing.credentialId);
    const monotonicCounter = Math.max(
      existing.counter,
      prevHighWater?.counter ?? 0,
      newCounter
    );
    const monotonicLastUsedAt = Math.max(
      existing.lastUsedAt ?? 0,
      prevHighWater?.lastUsedAt ?? 0,
      lastUsedAt
    );

    highWaterMap.set(existing.credentialId, {
      counter: monotonicCounter,
      lastUsedAt: monotonicLastUsedAt,
    });

    const updated: CredentialRecord = {
      ...existing,
      counter: monotonicCounter,
      lastUsedAt: monotonicLastUsedAt,
    };
    await kv.put(credentialKey(existing.credentialId), JSON.stringify(updated));
    return updated;
  });
}

export async function updateCredentialCounter(
  kv: KVNamespace,
  credentialId: string,
  newCounter: number,
  lastUsedAt: number
): Promise<boolean> {
  const existing = await getCredential(kv, credentialId);
  if (!existing) return false;
  await saveCredentialCounter(kv, existing, newCounter, lastUsedAt);
  return true;
}

export async function listUserCredentialHints(
  kv: KVNamespace,
  userId: string
): Promise<CredentialHint[]> {
  const indexRaw = await kv.get(userIndexKey(userId));
  if (!indexRaw) return [];

  let index: UserCredentialIndex;
  try {
    index = JSON.parse(indexRaw) as UserCredentialIndex;
  } catch (error) {
    console.error('listUserCredentialHints: failed to parse index', error);
    return [];
  }

  const ids = Array.isArray(index.credentialIds) ? index.credentialIds : [];
  if (ids.length === 0) return [];

  const hintsById = new Map<string, CredentialHint>();
  if (Array.isArray(index.credentials)) {
    for (const hint of index.credentials) {
      if (hint && typeof hint.credentialId === 'string') {
        hintsById.set(hint.credentialId, {
          credentialId: hint.credentialId,
          transports: Array.isArray(hint.transports) ? hint.transports : [],
        });
      }
    }
  }

  const missingIds = ids.filter((id) => !hintsById.has(id));
  if (missingIds.length > 0) {
    const legacyRecords = await Promise.all(
      missingIds.map((id) => getCredential(kv, id))
    );
    for (const rec of legacyRecords) {
      if (rec) {
        hintsById.set(rec.credentialId, {
          credentialId: rec.credentialId,
          transports: rec.transports,
        });
      }
    }
  }

  return ids
    .map((id) => hintsById.get(id))
    .filter((hint): hint is CredentialHint => hint !== undefined);
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
  return enqueueCredentialWrite(kv, credentialId, async () => {
    const existing = await getCredential(kv, credentialId);
    if (!existing || existing.userId !== userId) return false;

    getHighWaterMap(kv).delete(credentialId);

    const [, indexRaw] = await Promise.all([
      kv.delete(credentialKey(credentialId)),
      kv.get(userIndexKey(userId)),
    ]);

    if (indexRaw) {
      try {
        const index = JSON.parse(indexRaw) as UserCredentialIndex;
        const filteredIds = (index.credentialIds ?? []).filter((id) => id !== credentialId);
        const nextIndex: UserCredentialIndex = { credentialIds: filteredIds };
        if (Array.isArray(index.credentials)) {
          nextIndex.credentials = index.credentials.filter(
            (c) => c.credentialId !== credentialId
          );
        }
        await kv.put(userIndexKey(userId), JSON.stringify(nextIndex));
      } catch (error) {
        console.error('deleteCredential: failed to update index', error);
      }
    }

    return true;
  });
}
