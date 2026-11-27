# Security policy

This is a prototype (see README → Known limitations). Do not expose it to the internet without
reading them and without your own review.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's *Report a vulnerability* (Security tab →
private vulnerability reporting) on this repository. I aim to answer within 7 days.

## Scope notes

- Secrets are configured only through environment variables; the app refuses to start without `SOC_SECRET_KEY`.
- API keys are stored as SHA-256 hashes (keys are 256-bit random, so a fast hash is adequate); passwords use Werkzeug's salted hashes.
- Sessions are signed cookies (HttpOnly, SameSite=Lax, Secure behind HTTPS) and cannot be revoked server-side.
- `SOC_TRUSTED_PROXIES` must equal the number of reverse proxies in front of the app; with a value > 0 and no proxy, `X-Forwarded-For` can be spoofed and weakens login throttling.
- `SOC_DEMO_MODE=1` lets an operator forge events; never enable it for real data.
