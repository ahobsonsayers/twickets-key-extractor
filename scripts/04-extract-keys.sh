#!/usr/bin/env bash
# Extract the 4 request keys from the frida output into keys.json.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

RAW="/tmp/ckraw.txt"
OUT="/data/output/keys.json"
TOKEN_PATTERN="x-prosopo-android-integrity-token': 'eyJ"

# Extract the 4 keys from the first message bearing a real integrity token.
# -m1 avoids the head pipe (SIGPIPE kills this under pipefail/set -e).
# Early messages fire before the JWE is minted, so match a real token.
# Retry a couple of times: the JWE mints only after the app warms up.
api=""
ua=""
site=""
token=""
for attempt in 1 2 3; do
  # The frida CLI prefixes each line with "[Remote::PID::NNNN ]-> message: ";
  # strip that prefix, the trailing " data: None", and single quotes (for JSON).
  # || msg="": grep returns 1 on no match; under set -e that would exit the script.
  msg="$(
    grep -m1 -E "message: .*'type': 'keys'.*$TOKEN_PATTERN" "$RAW" |
      sed 's|.*message: ||; s| data: None$||; s|'"'"'|"|g'
  )" || msg=""
  # jq prints "null" on empty input; skip parsing when there's no message.
  [ -n "$msg" ] || {
    log "Keys not yet minted (attempt $attempt/3); retrying"
    sleep 5
    continue
  }
  api="$(jq -r '.payload.payload.api_key // empty' <<<"$msg")" || api=""
  ua="$(jq -r '.payload.payload["User-Agent"] // empty' <<<"$msg")" || ua=""
  site="$(jq -r '.payload.payload["x-prosopo-site-key"] // empty' <<<"$msg")" || site=""
  token="$(jq -r '.payload.payload["x-prosopo-android-integrity-token"] // empty' <<<"$msg")" || token=""
  [ -n "$api" ] && [ -n "$ua" ] && [ -n "$site" ] && [ -n "$token" ] && break
  log "Keys not yet minted (attempt $attempt/3); retrying"
  sleep 5
done

if [ -z "$api" ] || [ -z "$ua" ] || [ -z "$site" ] || [ -z "$token" ]; then
  echo "ERROR: could not capture all 4 keys"
  echo "  api_key=$api"
  echo "  User-Agent=$ua"
  echo "  x-prosopo-site-key=$site"
  echo "  x-prosopo-android-integrity-token=$token"
  exit 1
fi

cat >"$OUT" <<EOF
{
  "api_key": "$api",
  "User-Agent": "$ua",
  "x-prosopo-site-key": "$site",
  "x-prosopo-android-integrity-token": "$token"
}
EOF

cat "$OUT"
log "Wrote $OUT"
