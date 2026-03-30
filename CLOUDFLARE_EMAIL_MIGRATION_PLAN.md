# Auth Worker Migration Plan: AWS SES -> Cloudflare Email Workers

This runbook documents the migration of `auth-worker` OTP emails from AWS SES to Cloudflare Email Workers (`send_email` binding), including Cloudflare Dashboard steps.

## 1) What changed in code

- Email provider service moved from `SESService` to `EmailService`.
- Outbound sends now use:
  - `EmailMessage` from `cloudflare:email`
  - `env.send_email.send(message)` binding
  - raw MIME body generation in `EmailService`
- Health check changed from `services.ses` to `services.email`.
- AWS SDK dependencies were removed.

## 2) Cloudflare Dashboard setup steps

Do these once before deploying the new worker config.

### A. Enable Email Routing for your domain

1. Open **Cloudflare Dashboard** -> select your zone (the domain you send from).
2. Go to **Email** -> **Email Routing**.
3. Click **Get started** / **Enable Email Routing**.
4. Follow prompts to apply required DNS records (MX/SPF) and wait for status to become active.

### B. Verify at least one destination mailbox

1. In **Email Routing**, open **Destination addresses**.
2. Add a destination mailbox you control (for example, an engineering mailbox).
3. Complete verification from the confirmation email.

### C. Add Worker email-send binding

For each worker environment (preview/staging/production):

1. Open **Workers & Pages** -> `auth-worker` (or `auth-worker-preview`, etc.).
2. Open **Settings** -> **Bindings**.
3. Add binding type **Send email**.
4. Set binding name: `send_email`.
5. Optionally configure sender restrictions to match `FROM_EMAIL` if your Wrangler/plan supports this field in config.
6. Save binding and deploy.

### D. Keep sender address aligned

Ensure `FROM_EMAIL` in worker vars matches your Cloudflare Email Routing sender policy.

## 3) Wrangler configuration required

`wrangler.toml` should include `send_email` for default + each env:

- `[[send_email]]`
- `[[env.preview.send_email]]`
- `[[env.staging.send_email]]`
- `[[env.production.send_email]]`

Current config uses:

- `name = "send_email"`

## 4) Rollout plan by environment

### Preview

1. Deploy:
   - `npm run deploy:preview`
2. Smoke test:
   - `GET /health` -> `services.email` should be `healthy`
   - `POST /email/send-verification` with a test payload

### Staging

1. Deploy:
   - `npm run deploy:staging`
2. Repeat smoke tests and OTP flow:
   - `POST /otp/generate`
   - verify `emailSent: true`

### Production

1. Deploy:
   - `npm run deploy:production`
2. Monitor:
   - Worker logs (`wrangler tail --env production`)
   - `/health`
   - OTP conversion and failure rates

## 5) Verification checklist

- [ ] `send_email` binding exists in all deployed environments.
- [ ] `FROM_EMAIL` is configured and allowed by binding restrictions.
- [ ] `/health` returns `services.email = healthy`.
- [ ] Manual verification email endpoint succeeds.
- [ ] OTP generate path succeeds and reports `emailSent: true`.
- [ ] No AWS SES credentials remain in worker secret usage.

## 6) Rollback plan

If production failures spike after cutover:

1. Revert to the previous SES commit on this branch.
2. Redeploy previous worker version.
3. Re-enable old AWS vars/secrets if removed.
4. Confirm `/health` and OTP sends recover.

## 7) Important product constraint

Cloudflare Email Workers `send_email` may restrict recipients to verified destination addresses depending on your binding/policy setup. If your OTP flow must send to arbitrary end-user addresses, validate this behavior in preview before full rollout. If restricted, use a provider that supports unrestricted transactional delivery (or a different Cloudflare-compatible transactional path) before production cutover.
