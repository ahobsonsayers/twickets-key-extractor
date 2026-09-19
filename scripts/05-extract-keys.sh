#!/usr/bin/env bash
# Extract the 4 request keys from the frida output into keys.json, folding
# in the attest key from 04 (if extracted). This is the pipeline's final gate.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

RAW="/tmp/ckraw.txt"
OUT="/data/output/keys.json"
ATTEST="/data/output/attest.json"
TMP="/data/output/keys.json.tmp"
TOKEN_PATTERN="x-prosopo-android-integrity-token': 'eyJ"

# 03 marks a rejected stream here. Publishing keys from a rejected run
# would hand out a token the server already refuses — even for the app
# itself. Do not write keys.json in that case.
if [ -f /data/output/render-failed.txt ]; then
  echo "ERROR: $(cat /data/output/render-failed.txt)"
  echo "  The Find stream did not render content. If a token was captured"
  echo "  anyway, the server is rejecting the app's own requests — the"
  echo "  keybox/IP is likely BLOCKED (see LEARNINGS.md)."
  echo "  Do NOT retry or re-extract; wait or change IP/keybox."
  exit 1
fi

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

cat >"$TMP" <<EOF
{
  "api_key": "$api",
  "User-Agent": "$ua",
  "x-prosopo-site-key": "$site",
  "x-prosopo-android-integrity-token": "$token"
}
EOF

# Written via mv: CI polls for keys.json and must never see it half-built.
if jq -e '.attest.key_pem' "$ATTEST" >/dev/null 2>&1; then
  jq --slurpfile a "$ATTEST" '. + {attest: $a[0].attest}' "$TMP" >"$TMP.2" && mv "$TMP.2" "$TMP"
else
  log "WARN: no valid attest.json — publishing keys.json without the attest section"
fi
mv "$TMP" "$OUT"

cat "$OUT"
log "Wrote $OUT"
