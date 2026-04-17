/**
 * User management worker sync: creates users on first login and records
 * login history. Shared between OTP and passkey flows so both paths report
 * consistent telemetry.
 */

import type { Env } from '../types/env';

export type LoginMethod = 'OTP' | 'PASSKEY';

export interface RecordLoginInput {
  userId: string;
  email: string;
  method: LoginMethod;
  ipAddress?: string;
  userAgent?: string;
}

export async function recordLogin(env: Env, input: RecordLoginInput): Promise<void> {
  const syncUrl = env.USER_MANAGEMENT_WORKER_URL?.trim();
  if (!syncUrl) return;

  try {
    if (!input.userId) {
      console.error('recordLogin: missing userId');
      return;
    }

    const userResponse = await fetch(`${syncUrl}/users/email/${input.userId}`);

    if (!userResponse.ok) {
      const createUserResponse = await fetch(`${syncUrl}/users`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email_hash: input.userId,
          account_type: 'FREE',
        }),
      });

      if (!createUserResponse.ok) {
        console.error('Failed to create user in User Management Worker');
      }
    }

    const loginResponse = await fetch(`${syncUrl}/login-history`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: input.userId,
        login_method: input.method,
        success: true,
        ip_address: input.ipAddress,
        user_agent: input.userAgent,
      }),
    });

    if (!loginResponse.ok) {
      console.error('Failed to record login history');
    }
  } catch (error) {
    console.error('Error managing user data:', error);
  }
}
