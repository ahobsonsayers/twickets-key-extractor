#!/usr/bin/env bash
# Extract the v3.20 attestation signing key. REQUIRED — 05 refuses to publish
# without it. Two bases, two capture points:
#  - TEESimulator base: the generate-time hook (03) captured inside the
#    daemon → extract-attest-key.py greps its log.
#  - TrickyStore-oss base: the daemon keeps keys ONLY in its RAM maps
#    (SecurityLevelInterceptor.keyPairs/.keys); walk them via frida's Java
#    bridge and take the PKCS8s — no op-waiting, no taps.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh
DEVICE="${DEVICE:-emulator-5554}"

LOG=/data/output/attest-extract.log

tee_pid="$("$ADB" -s "$DEVICE" shell pidof TEESimulator 2>/dev/null | tr -d '\r\n' || true)"
if [ -n "$tee_pid" ]; then
  if timeout 300 python3 -u /opt/scripts/extract-attest-key.py 2>&1 | tee "$LOG"; then
    log "Attest key extracted (TEESimulator generate-hook)"
    exit 0
  fi
  log "TEESimulator path failed; trying the TrickyStoreOSS path"
fi

ts_pid="$("$ADB" -s "$DEVICE" shell pidof TrickyStoreOSS 2>/dev/null | tr -d '\r\n' | awk '{print $1}' || true)"
if [ -z "$ts_pid" ]; then
  log "ERROR: neither TEESimulator nor TrickyStoreOSS daemon found"
  exit 1
fi

log "TrickyStoreOSS base: walking key maps on daemon pid $ts_pid"
rm -f /tmp/mapwalk.log /data/output/pkcs8.b64
timeout 120 uv tool run --from frida-tools frida -H 127.0.0.1:27042 -p "$ts_pid" \
  -l /opt/scripts/hook-map.js > /tmp/mapwalk.log 2>&1 || true

grep -a -o "PKCS8:[A-Za-z0-9+/=]*" /tmp/mapwalk.log 2>/dev/null |
  sed 's/^PKCS8://' > /data/output/pkcs8.b64 || true

if [ ! -s /data/output/pkcs8.b64 ]; then
  log "ERROR: no EC keys in the TrickyStoreOSS maps (walk log tail below)"
  tail -n 10 /tmp/mapwalk.log || true
  exit 1
fi

if timeout 120 python3 -u /opt/scripts/attest-tsoss.py 2>&1 | tee "$LOG"; then
  log "Attest key extracted (TrickyStoreOSS map walk)"
else
  log "ERROR: attest key verification failed"
  exit 1
fi