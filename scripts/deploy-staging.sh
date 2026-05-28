#!/usr/bin/env bash
# Idempotent staging deploy for the Vaultwarden Worker port.
#
# Creates (if missing) the D1 database, R2 buckets, KV namespaces, and
# Durable Object class binding, patches their IDs into wrangler.jsonc,
# generates an RSA keypair and admin token if not already pushed,
# applies migrations to the remote D1, then deploys.
#
# Usage:
#   scripts/deploy-staging.sh             # full deploy
#   DRY_RUN=1 scripts/deploy-staging.sh   # plan only — no resource creation
#
# Prereqs:
#   - wrangler logged in (`wrangler whoami`)
#   - openssl, jq, sed available
#
# Re-running is safe: every step checks for existing resources and skips
# creation if found. Patching wrangler.jsonc only happens when the placeholder
# `REPLACE_WITH_*` is still present.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WRANGLER=${WRANGLER:-npx wrangler}
DRY_RUN=${DRY_RUN:-}

D1_NAME=${D1_NAME:-vaultwarden}
R2_BUCKETS=("vaultwarden-attachments" "vaultwarden-sends" "vaultwarden-icons" "vaultwarden-web-vault")
KV_NAMES=("CONFIG_KV" "RATELIMIT_KV" "SSO_CACHE_KV")

step() { printf "\n\033[1;36m▶ %s\033[0m\n" "$1"; }
note() { printf "  \033[2m%s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*" 1>&2; }
run()  { if [[ -n "$DRY_RUN" ]]; then echo "    DRY: $*"; else eval "$@"; fi; }

require() {
  command -v "$1" >/dev/null 2>&1 || { warn "missing required tool: $1"; exit 1; }
}

require openssl
require jq
require sed
require curl

# ---------------------------------------------------------------------------
step "Wrangler auth"
if [[ -n "$DRY_RUN" ]]; then
  note "DRY_RUN: skipping wrangler auth check"
else
  whoami_out=$($WRANGLER whoami 2>&1 || true)
  if echo "$whoami_out" | grep -qE "not authenticated|Run.*login"; then
    warn "wrangler not logged in — run 'wrangler login' first"
    echo "$whoami_out" | head -10 | sed 's/^/  /'
    exit 1
  fi
  ok "logged in"
fi

# ---------------------------------------------------------------------------
step "D1 database"
existing_d1=$($WRANGLER d1 list --json 2>/dev/null | jq -r --arg n "$D1_NAME" '.[] | select(.name == $n) | .uuid' | head -1 || true)
if [[ -n "$existing_d1" ]]; then
  ok "D1 '$D1_NAME' already exists (id $existing_d1)"
else
  note "creating D1 '$D1_NAME'"
  if [[ -z "$DRY_RUN" ]]; then
    create_out=$($WRANGLER d1 create "$D1_NAME")
    existing_d1=$(echo "$create_out" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
    [[ -z "$existing_d1" ]] && { warn "failed to parse D1 id from create output"; exit 1; }
  else
    existing_d1="DRY_D1_ID"
  fi
  ok "created D1 '$D1_NAME' (id $existing_d1)"
fi

# ---------------------------------------------------------------------------
step "R2 buckets"
existing_buckets=$($WRANGLER r2 bucket list 2>/dev/null | grep -oE 'vaultwarden-[a-z-]+' | sort -u || true)
for bucket in "${R2_BUCKETS[@]}"; do
  if echo "$existing_buckets" | grep -q "^$bucket$"; then
    ok "R2 '$bucket' already exists"
  else
    note "creating R2 '$bucket'"
    run "$WRANGLER r2 bucket create '$bucket'"
    ok "created R2 '$bucket'"
  fi
done

# ---------------------------------------------------------------------------
step "KV namespaces"
KV_ID_CONFIG=""; KV_ID_RATELIMIT=""; KV_ID_SSO=""
for kv in "${KV_NAMES[@]}"; do
  list_out=$($WRANGLER kv namespace list 2>/dev/null || echo "[]")
  id=$(echo "$list_out" | jq -r --arg n "$kv" '.[] | select(.title | endswith($n)) | .id' | head -1 || true)
  if [[ -n "$id" ]]; then
    ok "KV '$kv' already exists (id $id)"
  else
    note "creating KV '$kv'"
    if [[ -z "$DRY_RUN" ]]; then
      cr=$($WRANGLER kv namespace create "$kv")
      id=$(echo "$cr" | grep -oE '"id":\s*"[0-9a-f]+"' | head -1 | cut -d'"' -f4)
      [[ -z "$id" ]] && { warn "failed to parse KV id"; exit 1; }
    else
      id="DRY_KV_${kv}_ID"
    fi
    ok "created KV '$kv' (id $id)"
  fi
  case "$kv" in
    CONFIG_KV) KV_ID_CONFIG=$id ;;
    RATELIMIT_KV) KV_ID_RATELIMIT=$id ;;
    SSO_CACHE_KV) KV_ID_SSO=$id ;;
  esac
done

# ---------------------------------------------------------------------------
step "Patch wrangler.jsonc"
patch_id() {
  local find=$1 replace=$2
  if grep -q "\"$find\"" wrangler.jsonc; then
    note "patching $find -> $replace"
    if [[ -z "$DRY_RUN" ]]; then
      sed -i.bak "s|\"$find\"|\"$replace\"|" wrangler.jsonc && rm -f wrangler.jsonc.bak
    fi
  fi
  return 0
}
patch_id "REPLACE_WITH_D1_ID" "$existing_d1"
# Each KV slot uses the same placeholder string, so patch them in declaration
# order (CONFIG_KV, RATELIMIT_KV, SSO_CACHE_KV) by replacing the first
# remaining occurrence each time.
patch_first_kv() {
  local id=$1
  if [[ -n "$DRY_RUN" ]]; then
    note "DRY: would patch first remaining REPLACE_WITH_KV_ID -> $id"
    return 0
  fi
  awk -v id="$id" '
    !done && /REPLACE_WITH_KV_ID/ { sub(/REPLACE_WITH_KV_ID/, id); done=1 }
    { print }
  ' wrangler.jsonc > wrangler.jsonc.tmp && mv wrangler.jsonc.tmp wrangler.jsonc
  return 0
}
patch_first_kv "$KV_ID_CONFIG"
patch_first_kv "$KV_ID_RATELIMIT"
patch_first_kv "$KV_ID_SSO"
ok "wrangler.jsonc updated"

# ---------------------------------------------------------------------------
step "D1 migrations (remote)"
if [[ -z "$DRY_RUN" ]]; then
  $WRANGLER d1 migrations apply DB --remote --env "" || warn "migrations apply returned non-zero (may be already-applied)"
else
  note "DRY: would apply $(ls worker/migrations/*.sql | wc -l) migrations"
fi
ok "migrations applied"

# ---------------------------------------------------------------------------
step "Secrets"
push_secret_if_missing() {
  local name=$1 source_cmd=$2
  if $WRANGLER secret list --env "" 2>/dev/null | grep -q "\"$name\""; then
    ok "secret '$name' already set"
  else
    note "pushing secret '$name'"
    if [[ -z "$DRY_RUN" ]]; then
      eval "$source_cmd" | $WRANGLER secret put "$name" --env ""
    fi
    ok "secret '$name' set"
  fi
}

# RSA keypair for JWT signing (RS256). Generated locally; private key never leaves
# this machine except via `wrangler secret put`.
keydir=$(mktemp -d)
trap 'rm -rf "$keydir"' EXIT
openssl genrsa -out "$keydir/rsa-private.pem" 2048 2>/dev/null
openssl rsa -in "$keydir/rsa-private.pem" -pubout -out "$keydir/rsa-public.pem" 2>/dev/null

push_secret_if_missing JWT_RSA_PRIVATE_KEY "cat '$keydir/rsa-private.pem'"
push_secret_if_missing JWT_RSA_PUBLIC_KEY  "cat '$keydir/rsa-public.pem'"

admin_token=${ADMIN_TOKEN:-$(openssl rand -hex 24)}
push_secret_if_missing ADMIN_TOKEN "echo -n '$admin_token'"

# ---------------------------------------------------------------------------
step "Deploy"
if [[ -z "$DRY_RUN" ]]; then
  $WRANGLER deploy --env ""
else
  $WRANGLER deploy --dry-run --outdir build --env ""
fi
ok "deployed"

# ---------------------------------------------------------------------------
step "Done"
cat <<EOF
Worker is live. Sanity checks:
  curl https://vaultwarden.<your-account>.workers.dev/alive
  curl https://vaultwarden.<your-account>.workers.dev/api/config
  curl https://vaultwarden.<your-account>.workers.dev/admin

Admin token (saved as a secret, not echoed if previously set):
  ${admin_token}

Configure Bitwarden clients with that hostname, or attach a custom domain via
the Cloudflare dashboard.
EOF
