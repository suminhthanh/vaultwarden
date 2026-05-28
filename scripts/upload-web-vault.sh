#!/usr/bin/env bash
# Download the dani-garcia/bw_web_builds release and upload it to the
# WEB_VAULT R2 bucket. Idempotent: safe to re-run; existing files get
# overwritten with the new release content.
#
# Usage:
#   scripts/upload-web-vault.sh                # latest release
#   WEB_VAULT_TAG=v2026.4.1 scripts/upload-web-vault.sh
#   DRY_RUN=1 scripts/upload-web-vault.sh      # plan only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WRANGLER=${WRANGLER:-npx wrangler}
DRY_RUN=${DRY_RUN:-}
BUCKET=${BUCKET:-vaultwarden-web-vault}
TAG=${WEB_VAULT_TAG:-}

step() { printf "\n\033[1;36m▶ %s\033[0m\n" "$1"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
note() { printf "  \033[2m%s\033[0m\n" "$*"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*" 1>&2; }

require() {
  command -v "$1" >/dev/null 2>&1 || { warn "missing tool: $1"; exit 1; }
}
require curl
require tar
require jq

if [[ -z "$TAG" ]]; then
  step "Resolving latest tag"
  TAG=$(curl -fsS https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest | jq -r .tag_name)
  ok "latest = $TAG"
fi

DOWNLOAD_URL="https://github.com/dani-garcia/bw_web_builds/releases/download/$TAG/bw_web_${TAG}.tar.gz"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

step "Download $TAG"
curl -fsSL --output "$WORKDIR/web-vault.tar.gz" "$DOWNLOAD_URL"
ok "downloaded $(du -h "$WORKDIR/web-vault.tar.gz" | cut -f1)"

step "Extract"
tar -xzf "$WORKDIR/web-vault.tar.gz" -C "$WORKDIR"
EXTRACTED="$WORKDIR/web-vault"
[[ -d "$EXTRACTED" ]] || { warn "expected $EXTRACTED after tar"; exit 1; }
file_count=$(find "$EXTRACTED" -type f | wc -l | tr -d ' ')
ok "extracted $file_count files"

step "Upload to R2 bucket '$BUCKET'"
uploaded=0
failed=0
upload_one() {
  local file=$1
  local rel="${file#$EXTRACTED/}"
  if [[ -n "$DRY_RUN" ]]; then
    note "DRY: would upload $rel"
    return 0
  fi
  if ! $WRANGLER r2 object put "$BUCKET/$rel" --file "$file" --remote >/tmp/r2-up.$$ 2>&1; then
    warn "upload failed for $rel"
    cat /tmp/r2-up.$$ | head -5 | sed 's/^/    /' >&2
    rm -f /tmp/r2-up.$$
    return 1
  fi
  rm -f /tmp/r2-up.$$
  return 0
}

while IFS= read -r -d '' file; do
  if upload_one "$file"; then
    uploaded=$((uploaded + 1))
  else
    failed=$((failed + 1))
  fi
  if (( (uploaded + failed) % 25 == 0 )); then
    note "$((uploaded + failed)) / $file_count processed (uploaded $uploaded, failed $failed)"
  fi
done < <(find "$EXTRACTED" -type f -print0)
ok "$uploaded uploaded, $failed failed"
[[ $failed -gt 0 ]] && warn "some uploads failed — re-run to retry; R2 puts are idempotent"

step "Done"
cat <<EOF
Web vault $TAG is live at the worker root.

  curl -I https://vaultwarden.<account>.workers.dev/

To re-upload after a new release:
  WEB_VAULT_TAG=v2026.5.0 scripts/upload-web-vault.sh
EOF
