#!/usr/bin/env bash
# Start frida-server and forward its port. Does not touch the app.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

DEVICE="emulator-5554"

log "Ensuring frida-server is running"

# Push baked binary if missing (fresh /data).
if ! "$ADB" -s "$DEVICE" shell 'su -c "[ -x /data/local/tmp/frida-server ]"' 2>/dev/null; then
  "$ADB" -s "$DEVICE" push /opt/tools/frida-server /data/local/tmp/frida-server >/dev/null
  "$ADB" -s "$DEVICE" shell chmod 755 /data/local/tmp/frida-server
fi

# Start it if not already running, then forward the port.
"$ADB" -s "$DEVICE" shell 'su -c "pgrep frida-server >/dev/null || (nohup /data/local/tmp/frida-server >/dev/null 2>&1 &)"' || true
"$ADB" -s "$DEVICE" forward tcp:27042 tcp:27042 || true
mkdir -p /data/output

sleep 2

log "frida-server ready"
