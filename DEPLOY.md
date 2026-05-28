# Deploying the Vaultwarden Worker port

This is the runbook for taking the in-tree code and pushing it to a real
Cloudflare account so Bitwarden clients can talk to it. Local development is
covered by `wrangler dev` + `npm run test:e2e` (see `tests/e2e/`); this doc
focuses on the staging deploy.

## Prerequisites

- Cloudflare account, **Workers Paid plan** (Durable Objects + analytics
  require it).
- `wrangler` ≥ 4.84 (`npm install` from this repo gives you the right one).
- `openssl`, `jq`, `sed`, `curl` on your PATH.
- A Rust toolchain with `wasm32-unknown-unknown` (`rustup target add wasm32-unknown-unknown`).

```sh
npx wrangler login
npx wrangler whoami        # sanity check
```

## What gets created

The deploy script provisions, in this order:

| Resource | Binding | Notes |
|---|---|---|
| D1 database `vaultwarden` | `DB` | All 56 migrations applied to `--remote` |
| R2 buckets | `ATTACHMENTS`, `SENDS`, `ICONS`, `WEB_VAULT` | Names hard-coded in `wrangler.jsonc` |
| KV namespaces | `CONFIG_KV`, `RATELIMIT_KV`, `SSO_CACHE_KV` | IDs patched into `wrangler.jsonc` |
| Durable Object class | `USER_NOTIFICATIONS`, `ANON_NOTIFICATIONS` | Declared in `wrangler.jsonc` migrations |
| Cron triggers | `*/5 * * * *`, `0 * * * *`, `0 0 * * *` | Send purge / cipher purge / daily |
| Secrets | `JWT_RSA_PRIVATE_KEY`, `JWT_RSA_PUBLIC_KEY`, `ADMIN_TOKEN` | Generated locally, pushed via wrangler |

## Run it

```sh
# Dry run first — no network mutations, prints what would happen.
DRY_RUN=1 ./scripts/deploy-staging.sh

# Real deploy.
./scripts/deploy-staging.sh
```

The script is idempotent. Re-running on an already-provisioned account skips
existing resources and re-deploys the latest code. `wrangler.jsonc` is
patched in place: the `REPLACE_WITH_D1_ID` and `REPLACE_WITH_KV_ID`
placeholders become real IDs after the first run, and stay that way.

The `ADMIN_TOKEN` is generated with `openssl rand -hex 24` if not already set.
The script prints it once on first deploy. Set it via env to use your own:

```sh
ADMIN_TOKEN="my-explicit-token" ./scripts/deploy-staging.sh
```

## Optional: configure email

The default mail provider is `LogProvider` — every send is logged via
`console.log` and never delivered. To send real email:

```sh
# Option A: Resend (HTTP API, simple)
echo -n "re_xxxxxxxxxx" | npx wrangler secret put RESEND_API_KEY

# Option B: MailChannels (free for CF Workers, requires DKIM)
echo -n "vault.example.com" | npx wrangler secret put MAILCHANNELS_DKIM_DOMAIN
echo -n "mailchannels"      | npx wrangler secret put MAILCHANNELS_DKIM_SELECTOR
cat dkim-private.pem        | npx wrangler secret put MAILCHANNELS_DKIM_PRIVATE_KEY

# Either option: from address shown in the email
npx wrangler secret put SMTP_FROM       # e.g. noreply@vault.example.com
npx wrangler secret put SMTP_FROM_NAME  # e.g. Vaultwarden
```

`mail::provider_from_env` checks Resend first, falls back to MailChannels,
then `LogProvider` — no code change needed to switch.

## Optional: Analytics Engine

Add an `analytics_engine_datasets` binding named `ANALYTICS` to
`wrangler.jsonc` to enable structured event ingestion. The
`observability::Telemetry` module no-ops when the binding is absent.

```jsonc
"analytics_engine_datasets": [
  { "binding": "ANALYTICS", "dataset": "vaultwarden_events" }
]
```

## Post-deploy validation

The deploy script ends with curl examples. Run them against the real domain:

```sh
WORKER_URL=https://vaultwarden.<your-account>.workers.dev

curl "$WORKER_URL/alive"          # → "2026-..."
curl "$WORKER_URL/api/config"     # → {"object":"config",...}
curl -I "$WORKER_URL/admin"       # → 200, content-type: text/html
```

Run the full e2e suite against the deployed Worker:

```sh
WORKER_URL=$WORKER_URL npm run test:e2e
```

Note: a few tests assume the dev `ADMIN_TOKEN` (`vw-test-admin-token-…`) and
will fail on a real deploy with a fresh secret. They're for local dev — skip
them or align the secret.

## Connecting Bitwarden clients

In the official web vault / mobile app, set the **server URL** (not just
`api`) to your Worker's hostname:

```
https://vaultwarden.<your-account>.workers.dev
```

The Worker speaks the same paths the upstream server does
(`/identity/connect/token`, `/api/sync`, `/notifications/hub`, …) so clients
need no other configuration. Custom domains can be attached in the
Cloudflare dashboard under Workers Routes; remember to update `DOMAIN` in
`wrangler.jsonc` so JWT issuers and email URLs match.

## Rollback

```sh
npx wrangler deployments list                   # find previous version id
npx wrangler rollback <version-id>              # instant
```

Storage (D1, R2, KV) is not rolled back — only the worker code. If a release
needs schema changes reverted, write the down-migration manually and apply
with `wrangler d1 execute DB --remote --file=down.sql`.

## Tearing down

```sh
npx wrangler delete                              # delete the Worker
npx wrangler d1 delete vaultwarden               # ⚠ irreversible — drops all data
for b in vaultwarden-{attachments,sends,icons,web-vault}; do
  npx wrangler r2 bucket delete "$b"
done
# KV namespaces: copy ids from wrangler.jsonc and:
# npx wrangler kv namespace delete --namespace-id <id>
```

## What this deploy doesn't do

Things you'd want before going beyond a personal-use deployment:

- **Custom domain.** Attach via dashboard → Workers → Routes; CORS already
  trusts any origin.
- **Web vault upload.** The `WEB_VAULT` R2 bucket is provisioned but empty.
  Upload the static Bitwarden web client to that bucket if you want to serve
  it directly; otherwise users hit the Worker via the official mobile/desktop
  apps or a separately-hosted web vault.
- **Hardware-key WebAuthn.** TOTP works; FIDO/WebAuthn is parked pending the
  `passkey-rs` substitution for `webauthn-rs` (a Phase 0 finding).
- **SSO / OIDC.** Schema and routes are scaffolded but not wired to a real
  provider in Phase 5.
- **iOS/Android end-to-end check.** The HTTP API surface matches upstream;
  the response shapes pass our 93 e2e tests, but real mobile clients haven't
  been driven against a deployed Worker URL.
