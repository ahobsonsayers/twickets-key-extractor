#!/usr/bin/env bash
# Attach a frida hook to keystore2 BEFORE the app's first launch so the
# generate-time path can capture the attest key's PKCS8 at the moment
# TEESimulator creates it (fresh AVD => keygen fires at 03's first launch).
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

DEVICE=${DEVICE:-emulator-5554}
RAW=/tmp/attest-hook.log
OUT=/data/output/attest-raw.txt

adb() { "$ADB" -s "$DEVICE" "$@"; }

ks_pid="$(adb shell pidof keystore2 | tr -d '\r\n')"
if [ -z "$ks_pid" ]; then
  log "WARN: keystore2 not running — skipping generate-hook (04 will report)"
  exit 0
fi

rm -f "$RAW" "$OUT"
log "Attaching attest generate-hook to keystore2 (pid $ks_pid)"
nohup uv tool run --from frida-tools frida -H 127.0.0.1:27042 -p "$ks_pid" \
  -l /opt/scripts/hook-attest-key.js >"$RAW" 2>&1 &
HOOK_PID=$!

# Wait for either the b64 PKCS8 payload or the 90s deadline. The keygen
# fires when 03 launches the app for the first time.
deadline=$((SECONDS + 90))
captured=0
while [ "$SECONDS" -lt "$deadline" ]; do
  if grep -q "'type': 'attest'" "$RAW" 2>/dev/null; then
    sleep 2
    b64="$(grep -m1 "'type': 'attest'" "$RAW" | grep -o "payload': '[A-Za-z0-9+/=]*'" | cut -d"'" -f3 || true)"
    if [ -n "$b64" ]; then
      printf '%s' "$b64" >"$OUT"
      log "Attest key captured at generate time"
      captured=1
    fi
    break
  fi
  sleep 2
done

kill -9 "$HOOK_PID" 2>/dev/null || true
pkill -9 -f hook-attest-key.js 2>/dev/null || true
[ "$captured" -eq 1 ] || log "WARN: no attest key captured (keygen may have already happened) — 04 will decide"
