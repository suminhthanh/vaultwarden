# Cloudflare Workers port — runbook for the next upstream release

This file lives at the repo root so future agents working on this fork (or
humans) can pick up where we left off when a new upstream Vaultwarden release
needs porting. It is **not** a generated artifact — keep it updated as the port
diverges.

The deploy mechanics live in [`DEPLOY.md`](./DEPLOY.md). This doc focuses on
**how to merge new upstream code into the Worker port** without breaking the
shipped staging build.

---

## Layout — what's here

```
.                                 ← upstream Vaultwarden (Rocket + Diesel) — left intact
├── src/                          ← upstream code; reference only, do NOT deploy
├── migrations/sqlite/            ← upstream migrations — authoritative for schema
├── worker/                       ← the Cloudflare Workers port (compiles to wasm32)
│   ├── src/
│   │   ├── api/                  ← HTTP handlers; one module per upstream `src/api/core/*` slice
│   │   ├── db/models/            ← D1-backed model methods, mirroring `src/db/models/*`
│   │   ├── auth.rs               ← JWT issuance + Headers extractor (replaces request guards)
│   │   ├── mail.rs               ← Provider trait: Resend / MailChannels / Log
│   │   ├── ratelimit.rs          ← KV-backed sliding window
│   │   ├── notifications.rs      ← UserNotificationDO + AnonymousNotificationDO
│   │   ├── templates.rs          ← Handlebars (compiled to wasm), `include_str!` templates
│   │   ├── config.rs             ← KV-backed admin overrides on top of compile-time defaults
│   │   └── lib.rs                ← `#[event(fetch)]` + `#[event(scheduled)]` entry points
│   ├── migrations/               ← *Copies* of `migrations/sqlite/*` — applied to D1 by wrangler
│   └── ...
├── tests/e2e/                    ← vitest harness — boots wrangler dev, must stay green
├── wrangler.jsonc                ← bindings (D1, R2 ×4, KV ×3, DO ×2, cron ×3)
├── DEPLOY.md                     ← deploy script + secrets walkthrough
├── scripts/deploy-staging.sh     ← idempotent provisioner
└── CLAUDE.md                     ← this file
```

D1 is SQLite, so `migrations/sqlite/*.sql` is the schema source of truth. The
copies under `worker/migrations/` exist because wrangler reads from a single
`migrations_dir` declared in `wrangler.jsonc`.

---

## What survived from upstream, what didn't

| Layer | Upstream | Worker port |
|---|---|---|
| HTTP framework | Rocket 0.5 + fairings | `axum` 0.8 on `workers-rs` 0.8 |
| Async runtime | tokio multi-thread | workers-rs single-threaded (`#[worker::send]` everywhere) |
| DB | Diesel + r2d2 | `worker::D1Database` + hand-written SQL + per-row `serde::Deserialize` structs |
| Migrations | `embed_migrations!` at boot | `wrangler d1 migrations apply --remote` in CI |
| WebSocket fan-out | in-process `DashMap<UserId, Vec<Conn>>` | Durable Object per user, `notify::notify_user` / `notify::notify_org` helpers |
| Background jobs | OS thread + `job_scheduler_ng` | Cron Triggers (`*/5`, `0 *`, `0 0`) → `#[event(scheduled)]` |
| Attachments / Sends / icons | OpenDAL | R2 bindings (direct PUT/GET, presigned URL via short-lived JWT) |
| Email | lettre SMTP | HTTP API: Resend → MailChannels → Log fallback (`mail::Provider`) |
| Web vault static files | `web-vault/` dir | R2 bucket `WEB_VAULT`, served by `api/web_vault.rs` |
| RSA JWT key | `data/rsa_key.pem` | Workers Secret (`JWT_RSA_PRIVATE_KEY` / `JWT_RSA_PUBLIC_KEY`) |
| Config JSON | `data/config.json` | KV namespace `CONFIG_KV` + compile-time defaults |
| Templates | Handlebars from disk + `reload_templates` | `include_str!` at compile time; reload removed |
| Rate limiters | `governor` (process-local) | KV-backed sliding window (`ratelimit.rs`) |
| OIDC `moka` cache | process-local | KV `SSO_CACHE_KV` |

Domain logic survives: the methods on each model (validation, state
transitions, JWT claims) are mostly mechanical translations of the upstream
implementation. The HTTP contract that Bitwarden clients speak is identical.

---

## Routes that are still stubbed (deliberately deferred)

- `/api/sso/prevalidate`, `/api/connect/oidc-signin`, `/api/connect/authorize`,
  `/api/organizations/domain/sso/verified` — full SSO/OIDC end-to-end. Login
  works for password + 2FA + auth-request + api-key grants; SSO grant is the
  only one missing.
- `/api/two-factor/get-duo` returns the stub shape so the UI doesn't error;
  the Duo OIDC ceremony itself isn't wired (`get_duo_stub`, `duo_unsupported`
  in `worker/src/api/two_factor.rs`).
- WebAuthn registration accepts the client's credential blob as-is — we
  don't cryptographically verify the attestation. TOTP + email + YubiKey are
  fully audited; WebAuthn is enrolment-only.

Everything else (vault sync, ciphers, folders, collections, sends, attachments,
emergency access, organizations, groups, policies, events, admin panel, push
relay, real-time sync via Durable Objects, all crons) is fully ported.

If you start chipping at one of those stubs, leave a `TODO(stub):` comment
referencing this list so we can prune it.

---

## Porting a new upstream release — the playbook

When a new upstream Vaultwarden release comes out, follow this in order:

### 1. Read the upstream diff first

```sh
# Whichever ref you're catching up to:
git fetch upstream
git log --oneline HEAD..upstream/main -- src/ migrations/ Cargo.toml | head -50
```

Bucket the changes in your head:

- **Migrations** (`migrations/sqlite/*.sql`) — hard requirement, port verbatim.
- **Model methods** (`src/db/models/*.rs`) — port to `worker/src/db/models/*`.
- **Route handlers** (`src/api/core/*.rs`, `src/api/identity.rs`,
  `src/api/notifications.rs`, `src/api/admin.rs`) — port to
  `worker/src/api/*`.
- **Crypto / JWT / auth** (`src/auth.rs`, `src/crypto.rs`) — careful, must
  stay byte-compatible with existing tokens. See "Crypto compatibility" below.
- **Templates** (`src/static/templates/email/*`) — copy to
  `worker/src/static/templates/email/` and re-`include_str!`.
- **Static admin UI** (`src/static/templates/admin/*`, `src/static/scripts/*`,
  CSS) — copy to `worker/src/static/`.
- **Frontend (web-vault)** — outside our scope; we serve whatever's in R2.

### 2. Apply migrations first

```sh
# 1. Copy any new SQL files into the Worker tree.
diff -q migrations/sqlite worker/migrations
cp migrations/sqlite/0057_*.sql worker/migrations/

# 2. Eyeball the SQL — D1 supports SQLite syntax but watch for:
#    - WITHOUT ROWID (allowed)
#    - virtual tables / FTS (allowed but rare in upstream)
#    - triggers (allowed)
#    - foreign keys: D1 doesn't enforce them — your app code must clean up.
#    Search for "DELETE FROM" in worker/src/api/admin.rs / accounts.rs /
#    organizations.rs delete-* handlers to see how we hand-cascade.

# 3. Apply locally (--local), then re-run e2e to confirm nothing broke.
rm -rf .wrangler/state
npx wrangler d1 migrations apply DB --local --env ''
npm run test:e2e

# 4. After the code change lands and the deploy script runs, --remote does
#    the same against the real D1 in CI.
```

If the migration adds a new column referenced by upstream model code, you
**must** also bump the matching `serde::Deserialize` struct in
`worker/src/db/models/<model>.rs` *before* the e2e tests will pass — D1
column-to-field mapping is by name, and missing columns surface as
`SQLITE_ERROR: no such column`.

### 3. Port model methods

Each model file is a near-mechanical translation. Keep method signatures as
close to upstream as possible so the API handlers translate cleanly. Pattern:

```rust
// upstream:  pub async fn find_by_user(&self, user_uuid: &str, conn: &DbConn) -> Vec<Self>
// worker:    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>>

pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
    let stmt = db
        .prepare("SELECT * FROM <table> WHERE user_uuid = ?1")
        .bind(&[JsValue::from_str(user_uuid)])?;
    Ok(stmt.all().await?.results::<Self>()?)
}
```

D1 quirks to watch for:

- **Booleans are `i32`** (0/1). Don't use `bool` in `serde::Deserialize`
  structs — it deserializes inconsistently across worker-rs versions.
- **Timestamps are RFC3339-Micros strings**:
  `chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)`.
- **BLOBs** are stored as hex strings — the upstream `BLOB` columns we kept
  use `hex(col)` on read; check `event.rs` for the pattern.
- **Lints**: workspace lints reject `let _ = future`. Use `let _named = ...`
  or `.is_ok()` / `.is_err()`. Use `drop(value)` if you need to discard
  early.
- **2024 edition tail-expression drop order** — see the early-`let` pattern
  in `purge_user_ciphers` (org-scoped branch).
- **Token comparisons**: always `subtle::ConstantTimeEq`, never `==`.

### 4. Port route handlers

`worker/src/api/<module>.rs` mirrors `src/api/core/<module>.rs`. Pattern:

```rust
// upstream:
//   #[post("/api/foo", data = "<data>")]
//   async fn post_foo(data: Json<FooData>, headers: Headers, conn: DbConn) -> JsonResult { ... }
//
// worker:
//   pub fn routes() -> Router<AppState> {
//       Router::new().route("/api/foo", post(post_foo))
//   }
//
//   #[worker::send]
//   async fn post_foo(
//       AxumState(state): AxumState<AppState>,
//       headers: Headers,                 // our extractor; lives in auth.rs
//       Json(body): Json<FooData>,
//   ) -> impl IntoResponse { ... }
```

After the handler lands:

1. **Wire the audit event** — every mutation handler emits one of the events
   in `events::event_type::*`. Match upstream's `EventType` enum value
   exactly; the numeric IDs surface raw to the admin audit log.
2. **Wire notifications** — vault-mutating handlers call
   `notify::notify_user(state, user_uuid, kind, payload_id)`. Org-shared
   ciphers/collections also fan out via `notify::notify_org(state, org_uuid,
   kind, payload_id)` so every confirmed member's clients refresh live.
   `notify::kind::*` mirrors Bitwarden's `Type` enum.
3. **Rate-limit anything that sends email or accepts unauthenticated
   probes** — `ratelimit::check(state.ratelimit_kv, &LIMIT, key)`. See
   `accounts.rs::register`, `accounts.rs::password_hint`,
   `auth_requests.rs::create_request` for the pattern.
4. **Force LOG_OUT after security-stamp rotation** — every handler that
   regenerates `user.security_stamp` (password change, KDF change, email
   change, recover, takeover-password, admin deauth) must follow with
   `notify_user(.., LOG_OUT, ..)` so existing access tokens stop working
   on every device immediately.

### 5. Crypto compatibility — DO NOT BREAK EXISTING TOKENS

The JWT signing key (`JWT_RSA_PRIVATE_KEY` secret) is shared across deploys.
Existing tokens out in the wild keep working as long as:

- The issuer string for each claim type stays the same. Every claim type has
  its own issuer suffix (e.g. `<host>|login`, `<host>|delete`,
  `<host>|send_file`); these are derived in `auth.rs::Claims::*::issuer`.
  Keep them stable.
- Argon2 parameters in `password_hash::set_password` stay backwards
  compatible. The migration to a new format must be opportunistic on next
  login (read old, write new), never wholesale.
- KDF iteration counts default to `client_kdf_iter` from the user row, not
  a moving constant.

If upstream changes the crypto layer, mirror the change but verify the
existing rsa_key.pem in production still issues / verifies correctly before
rolling out.

### 6. Run the verification ladder

For every change:

```sh
cargo check -p vaultwarden-worker --target wasm32-unknown-unknown   # clippy lints + types
rm -rf .wrangler/state/v3/kv                                         # reset rate-limit + KV state
npm run test:e2e                                                      # 28 files / 117 tests
CLOUDFLARE_ACCOUNT_ID=8232c573eb53020220aa0eb1a3909ce2 npx wrangler deploy
```

`cargo check` must be clean. `npm run test:e2e` must be 117/117. The deploy
should print a fresh Version ID; the worker URL is
`https://vaultwarden.senlyzer.vn`.

If e2e flakes with rate-limit 429s on retry, that's KV state from the
previous run — `rm -rf .wrangler/state/v3/kv` and re-run.

If e2e flakes with `unreachable` panics in the wasm bundle, the most likely
cause is an axum `Router` route conflict (e.g. two modules registering the
same path). Delete the duplicate and re-deploy.

If wrangler dev dies during boot with `no such table`, the local D1 was
re-created without migrations. Re-run
`npx wrangler d1 migrations apply DB --local --env ''`.

### 7. Update this file

When the new upstream release adds something we couldn't port (typically
because it depends on a Rust crate that doesn't build for wasm32 — see
`wasm-audit/` for the audit harness), document it in the "still stubbed"
section above so the next porter knows it's a known gap, not a bug.

---

## Crates audited for wasm32 (as of last port pass)

✅ Built cleanly: `jsonwebtoken` 10.4 (rust_crypto), `argon2` 0.5,
`totp-lite` 2.0, `rsa`, `sha2`, `aes-gcm`, `passkey-types` +
`passkey-authenticator` 0.5, `chrono`, `uuid`, `subtle`, `getrandom("js")`.

❌ Does NOT build: `webauthn-rs` 0.5.5 (transitively pulls `openssl-sys`).
That's why our WebAuthn flow uses a hand-rolled credential blob round-trip
instead of full attestation verification — replacing it would mean swapping
to the `passkey-rs` crate family or porting the COSE / CBOR parsing
ourselves.

When upstream bumps a security-relevant dep, re-run the audit:

```sh
cd wasm-audit
cargo check --target wasm32-unknown-unknown
```

`wasm-audit/Cargo.toml` is checked in so future dep bumps fail fast.

---

## Things to never do during a port

- **Do not skip `worker::send`.** Every async route handler in
  `worker/src/api/` needs `#[worker::send]`. Compiler errors on this look
  like `the trait Send is not implemented` and are easy to miss.
- **Do not remove the `#[allow(dead_code)]` from `events::event_type` or
  `notify::kind`.** They're API surface for future modules; constants we
  haven't emit-sited yet shouldn't fail clippy.
- **Do not push to main without an e2e green run.** The 117-test suite is
  load-bearing — it covers register/login/sync/cipher CRUD/2FA/admin/JWT
  round-trip/mail rendering. A change that breaks any one is almost always
  breaking a Bitwarden client.
- **Do not change `wrangler.jsonc` binding names.** The names map to runtime
  state. `DB`, `ATTACHMENTS`, `SENDS`, `ICONS`, `WEB_VAULT`, `CONFIG_KV`,
  `RATELIMIT_KV`, `SSO_CACHE_KV`, `USER_NOTIFICATIONS`, `ANON_NOTIFICATIONS`
  — leave them alone. If a new binding is needed, add it; don't rename.
- **Do not remove `tests/e2e/setup.ts`'s wrangler-dev boot.** The harness
  starts a real Worker against the local D1 and runs HTTP against it —
  there is no faster substitute that catches what it catches.

---

## Quick reference — common one-liners

```sh
# Full local cycle:
cargo check -p vaultwarden-worker --target wasm32-unknown-unknown && \
  rm -rf .wrangler/state/v3/kv && \
  npm run test:e2e && \
  CLOUDFLARE_ACCOUNT_ID=8232c573eb53020220aa0eb1a3909ce2 npx wrangler deploy

# Reset everything (when a migration changes shape):
pkill -f wrangler; rm -rf .wrangler/state && \
  npx wrangler d1 migrations apply DB --local --env '' && \
  npm run test:e2e

# Tail live logs after deploy:
npx wrangler tail vaultwarden --format pretty

# Inspect a remote D1 row:
npx wrangler d1 execute DB --remote --command "SELECT count(*) FROM users"
```

---

## Where to look when something breaks

| Symptom | First place to look |
|---|---|
| `unreachable` panic in wasm | `axum::Router::merge` panics on duplicate routes — search both `api/<mod>.rs` and `api/meta.rs` for the same path |
| 401 on a route that worked yesterday | `worker/src/auth.rs::Headers` extractor — the JWT verifier rejected the token; check security_stamp |
| 500 on first request after deploy | D1 migration not applied; run `wrangler d1 migrations apply DB --remote` |
| 429 in dev only | KV rate-limit state from prior run — `rm -rf .wrangler/state/v3/kv` |
| Email not delivered | `mail::provider_from_env` selected `Log`; set `RESEND_API_KEY` or `MAILCHANNELS_*` secrets |
| WebSocket sync stops | Durable Object class binding mismatch in `wrangler.jsonc` — check `migrations:` block |
| Cron not firing | `[triggers]` block in `wrangler.jsonc`; verify with `wrangler tail` during the next slot |
| Bundle over budget | `wrangler deploy --dry-run` prints the size; we're under 600 KiB upload last I checked |

---

Last full porting pass: 2026-05-27, against upstream `d626ea81` (Apple
app site association, post-edition-2024 cleanup). 117/117 e2e green;
audit-event coverage at 70 emit sites; deployed live at
`https://vaultwarden.senlyzer.vn`.
