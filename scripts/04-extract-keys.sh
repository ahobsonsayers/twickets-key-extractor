#!/usr/bin/env bash
# Extract the 4 request keys from the frida output into keys.json.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

RAW="/tmp/ckraw.txt"
OUT="/data/output/keys.json"

# Extract the 4 keys from the first message bearing a real integrity token.
# -m1 avoids the head pipe (SIGPIPE kills this under pipefail/set -e).
# Early messages fire before the JWE is minted, so match a real token.
extract() {
  local msg api ua site token
  msg="$(
    grep -m1 -E "message: .*'type': 'keys'.*'x-prosopo-android-integrity-token': 'eyJ" "$RAW" |
      sed 's|.*message: ||; s| data: None$||; s|'"'"'|"|g'
  )"
  api="$(jq -r '.payload.payload.api_key' <<<"$msg")"
  ua="$(jq -r '.payload.payload["User-Agent"]' <<<"$msg")"
  site="$(jq -r '.payload.payload["x-prosopo-site-key"]' <<<"$msg")"
  token="$(jq -r '.payload.payload["x-prosopo-android-integrity-token"]' <<<"$msg")"
  [ -n "$api" ] && [ -n "$ua" ] && [ -n "$site" ] && [ -n "$token" ] || return 1
  API="$api"
  UA="$ua"
  SITE="$site"
  TOKEN="$token"
}

# Retry a couple of times: the JWE mints only after the app warms up.
for attempt in 1 2 3; do
  if extract; then
    break
  fi
  log "Keys not yet minted (attempt $attempt/3); retrying"
  sleep 5
done

if [ -z "${API:-}" ] || [ -z "${UA:-}" ] || [ -z "${SITE:-}" ] || [ -z "${TOKEN:-}" ]; then
  echo "ERROR: could not capture all 4 keys"
  echo "  api_key=${API:-}"
  echo "  User-Agent=${UA:-}"
  echo "  x-prosopo-site-key=${SITE:-}"
  echo "  x-prosopo-android-integrity-token=${TOKEN:-}"
  exit 1
fi

cat >"$OUT" <<EOF
{
  "api_key": "$API",
  "User-Agent": "$UA",
  "x-prosopo-site-key": "$SITE",
  "x-prosopo-android-integrity-token": "$TOKEN"
}
EOF

cat "$OUT"
log "Wrote $OUT"
