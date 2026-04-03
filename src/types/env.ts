import type { EmailMessage } from 'cloudflare:email';

export interface SendEmailBinding {
  send(message: EmailMessage): Promise<void>;
}

export interface Env {
  OTP_KV: KVNamespace;

  ENVIRONMENT: 'development' | 'preview' | 'staging' | 'production';

  /** If set, post-verify hooks call this worker (user CRUD + login history). Omit for standalone OTP+JWT. */
  USER_MANAGEMENT_WORKER_URL?: string;

  send_email: SendEmailBinding;
  FROM_EMAIL?: string;

  /** Shown in verification email subject and body */
  APP_NAME?: string;
  SUPPORT_EMAIL?: string;

  /** Comma-separated origins for CORS; omit or empty = reflect request origin (permissive). */
  CORS_ORIGINS?: string;

  /** Service binding to the Flaggly worker (production). */
  FLAGGLY_SERVICE?: Fetcher;
  /** Base URL for Flaggly API — set in Cloudflare dashboard. */
  FLAGGLY_URL?: string;
  /** API key / JWT for Flaggly — set in Cloudflare dashboard or via `wrangler secret put FLAGGLY_API_KEY`. */
  FLAGGLY_API_KEY?: string;

  JWT_SECRET: string;
  JWT_ISSUER: string;
  JWT_AUDIENCE: string;
}