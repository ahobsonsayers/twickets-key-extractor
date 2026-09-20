#!/usr/bin/env bash
# Attach a frida hook to the TEESimulator daemon BEFORE the app's first
# launch so the generate-time path can capture the attest key's PKCS8 the
# moment it creates the key (fresh AVD => keygen fires at 04's first launch).
# NOTE: keystore2 itself has no Java bridge — TEESimulator's Java keygen
# code runs in its own daemon process.
#
# The hook stays attached in the background — 04-open-twickets.sh launches
# the app later, and 05-extract-attest.sh greps the hook log afterwards.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

DEVICE=${DEVICE:-emulator-5554}
RAW=/tmp/attest-hook.log
OUT=/data/output/attest-raw.txt

adb() { "$ADB" -s "$DEVICE" "$@"; }

tee_pid="$(adb shell pidof TEESimulator | tr -d '\r\n')"
if [ -z "$tee_pid" ]; then
  log "WARN: TEESimulator daemon not running — skipping generate-hook (05 will report)"
  exit 0
fi

rm -f "$RAW" "$OUT"
log "Attaching attest generate-hook to TEESimulator (pid $tee_pid)"
nohup uv tool run --from frida-tools frida -H 127.0.0.1:27042 -p "$tee_pid" \
  -l /opt/scripts/hook-attest-key.js >"$RAW" 2>&1 &
HOOK_PID=$!

# Arm the hook and confirm, then hand off: capture is asynchronous and
# happens when 04 launches the app (keygen fires at first launch).
armed=0
deadline=$((SECONDS + 30))
while [ "$SECONDS" -lt "$deadline" ]; do
  if grep -qE "hook armed on (GeneratedKeyInfo|Signer)" "$RAW" 2>/dev/null; then
    armed=1
    break
  fi
  sleep 1
done

if [ "$armed" -eq 0 ]; then
  log "WARN: hook did not attach within 30s — killing it (05 will report)"
  kill -9 "$HOOK_PID" 2>/dev/null || true
  pkill -9 -f hook-attest-key.js 2>/dev/null || true
  exit 0
fi

log "Attest generate-hook armed; waiting for 04's first app launch to mint the key"
