#!/usr/bin/env node
/**
 * Smoke-test the deployed worker's /email/send-verification endpoint.
 * Used by run-tests.js. Requires a running worker (e.g. wrangler dev).
 *
 * Usage: AUTH_WORKER_BASE_URL=https://... node test-email.js <email> <otp> [expiryMinutes]
 */

async function main() {
  const email = process.argv[2];
  const otp = process.argv[3];
  const expiryMinutes = Number(process.argv[4] || 10);
  const base = process.env.AUTH_WORKER_BASE_URL || 'http://127.0.0.1:8787';

  if (!email || !otp) {
    console.error('Usage: node test-email.js <email> <otp> [expiryMinutes]');
    process.exit(1);
  }

  const res = await fetch(`${base.replace(/\/$/, '')}/email/send-verification`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, otp, expiryMinutes })
  });

  const text = await res.text();
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${text}`);
  }
  console.log(text);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
