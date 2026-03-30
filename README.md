# Auth worker (Cloudflare)

OTP over email + JWT session tokens on [Cloudflare Workers](https://developers.cloudflare.com/workers/), using [KV](https://developers.cloudflare.com/kv/) for OTP state and the [`send_email`](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/) binding for outbound mail.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nolanfoster/cloudflare-otp-auth-worker)

## Features

- `POST /otp/generate` — create OTP, store in KV, send code by email  
- `POST /otp/verify` — verify OTP, return JWT  
- `POST /auth/validate`, `POST /auth/refresh` — JWT helpers  
- Optional `USER_MANAGEMENT_WORKER_URL` — after verify, create user + login history (your backend)  
- Optional `CORS_ORIGINS` — comma-separated allowlist; if unset, CORS reflects the request origin (fine for local dev, tighten for production)

## Quick start (CLI)

```bash
npm install
cp .dev.vars.example .dev.vars
# Edit .dev.vars — set JWT_SECRET

wrangler kv namespace create OTP_KV
# Put the namespace id in wrangler.toml under [[kv_namespaces]] → id

wrangler secret put JWT_SECRET

npm run dev
```

Configure [Email Routing / send_email](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/) so `FROM_EMAIL` is authorized for your zone.

After the first deploy, set `JWT_ISSUER` in `[vars]` to your real worker URL (e.g. `https://auth-worker.account.workers.dev`) so issued tokens validate correctly.

## Configuration

| Binding / var | Required | Notes |
|---------------|----------|--------|
| `OTP_KV` | yes | KV namespace |
| `send_email` | yes | Cloudflare Email Workers binding |
| `JWT_SECRET` | yes | Secret; `wrangler secret put JWT_SECRET` |
| `JWT_ISSUER` | yes | Usually your worker’s HTTPS URL |
| `JWT_AUDIENCE` | yes | Your app name; clients should expect this `aud` |
| `FROM_EMAIL` | recommended | Verified sender |
| `APP_NAME`, `SUPPORT_EMAIL` | optional | Email copy |
| `USER_MANAGEMENT_WORKER_URL` | optional | See below |
| `CORS_ORIGINS` | optional | e.g. `https://app.example.com,http://localhost:5173` |

### Optional user-management sync

If `USER_MANAGEMENT_WORKER_URL` is set, after a successful OTP verify the worker calls:

- `GET {URL}/users/email/{email_hash}` — if not found, `POST {URL}/users` with `{ email_hash, account_type: "FREE" }`  
- `POST {URL}/login-history` with OTP login metadata  

If the variable is unset, auth still works; only this sync is skipped. `/health` reports `user_management: "skipped"`.

## Scripts

- `npm run dev` — `wrangler dev`  
- `npm run deploy` — `wrangler deploy`  
- `npm run test:run` — Vitest  
- `npm run deploy:test` — deploy + smoke `test-email.js` (set `AUTH_WORKER_BASE_URL` for a remote worker)

## Standalone repository

This directory is a **full project root** (not a monorepo subfolder). It includes `.github/workflows/ci.yml`: Node **18.x** and **20.x**, lint, typecheck, `test:coverage`, and **≥80%** coverage gates (same intent as the recipe-app `auth-worker-tests.yml`, without a `shared/` package).

```bash
cd /path/to/cloudflare-otp-auth-worker
git init
git add .
git commit -m "Initial commit"
gh repo create nolanfoster/cloudflare-otp-auth-worker --public --source=. --push
```

## License

MIT — see [LICENSE](LICENSE).
