import { Flaggly } from '@flaggly/sdk';
import { Env } from '../types/env';

export type CerebroFlags = {
  'allowed-users': { type: 'boolean' };
};

/** Returns a configured Flaggly client, or null if FLAGGLY_URL/FLAGGLY_API_KEY are not set. */
export function createFlaggly(env: Env): Flaggly<CerebroFlags> | null {
  const url = env.FLAGGLY_URL?.trim();
  const apiKey = env.FLAGGLY_API_KEY?.trim();
  if (!url || !apiKey) return null;

  if (env.FLAGGLY_SERVICE) {
    return new Flaggly<CerebroFlags>({
      url,
      apiKey,
      workerFetch: env.FLAGGLY_SERVICE.fetch.bind(env.FLAGGLY_SERVICE),
    });
  }
  return new Flaggly<CerebroFlags>({ url, apiKey });
}

/**
 * Fire-and-forget: identify the authenticated user in Flaggly.
 * Errors are logged but never propagate — Flaggly outages must not affect auth.
 */
export async function identifyUser(env: Env, userId: string, email: string): Promise<void> {
  const flaggly = createFlaggly(env);
  if (!flaggly) return;
  try {
    await flaggly.identify(userId, { email });
  } catch (err) {
    console.error('Flaggly identify failed (non-fatal):', err);
  }
}
