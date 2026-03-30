# Cloudflare Email Workers Setup for Auth Worker

This document explains how to configure outbound verification emails for `auth-worker` using the Cloudflare Email Workers `send_email` binding.

## Current Email Stack

- Provider: Cloudflare Email Workers
- Worker binding: `send_email`
- Sender variable: `FROM_EMAIL`
- Email format: MIME (text + HTML parts)

## Prerequisites

1. Domain configured in Cloudflare.
2. Email Routing enabled for that domain.
3. Sender address (`FROM_EMAIL`) belongs to the configured domain.
4. `auth-worker` has a `send_email` binding in each environment (`preview`, `staging`, `production`).

## Wrangler Configuration

`wrangler.toml` should include:

```toml
[vars]
FROM_EMAIL = "noreply@yourdomain.com"

[[send_email]]
name = "send_email"
```

Repeat the same binding under each environment (`[[env.preview.send_email]]`, `[[env.staging.send_email]]`, `[[env.production.send_email]]`).

## Deploy & Test

```bash
# Preview
npm run deploy:preview

# Staging
npm run deploy:staging

# Production
npm run deploy:production
```

To test manual send path:

```bash
curl -X POST "https://<auth-worker-domain>/email/send-verification" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","otp":"123456","expiryMinutes":10}'
```

## Health Check

The `/health` endpoint now reports email service status under:

```json
{
  "services": {
    "email": "healthy"
  }
}
```

## Troubleshooting

1. **`send_email` binding missing**
   - Ensure binding exists in the deployed environment block.
2. **Sender rejected**
   - Ensure `FROM_EMAIL` matches your Cloudflare Email Routing sender policy.
3. **No email delivered**
   - Verify Email Routing domain setup and destination configuration in Cloudflare.
