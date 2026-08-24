#!/usr/bin/env bash
# Install Twickets via gplaydl + the official dispenser (GPLAYDL_CONFIG), then reboot so BetterKnownInstalled marks it a Play Store install.
# shellcheck source=scripts/common.sh
set -euo pipefail
source /opt/scripts/common.sh

TWICKETS="co.twickets.droid"
OUT="/tmp/gplaydl-twickets"

# Skip if already present.
if is_installed "$TWICKETS"; then
  log "Twickets already installed"
  exit 0
fi

# arm64: x86_64 AVD runs ARM apps via NDK translation.
# gplaydl authenticates against dispenser.gplaydl.com via a config file. The
# full config JSON is injected as GPLAYDL_CONFIG and written to the config
# path so the tool reads it natively. See README for how to get a key.
CONFIG_FILE="/root/.config/gplaydl/config.json"

if [ -z "${GPLAYDL_CONFIG:-}" ]; then
  log "ERROR: GPLAYDL_CONFIG is not set. See README for how to get one."
  exit 1
fi

mkdir -p "$(dirname "$CONFIG_FILE")"
cat >"$CONFIG_FILE" <<EOF
$GPLAYDL_CONFIG
EOF
chmod 600 "$CONFIG_FILE"

log "Downloading latest $TWICKETS from Play via gplaydl"
rm -rf "$OUT"
mkdir -p "$OUT"

# The dispenser can be transiently rate-limited, so retry with a 60s backoff.
for attempt in 1 2 3 4 5; do
  if uv tool run gplaydl download "$TWICKETS" -a arm64 -o "$OUT"; then
    break
  fi
  log "gplaydl download failed (attempt $attempt/5); waiting 60s"
  sleep 60
done

# Confirm the APKs are actually present (dispenser may 403 inside the tool).
if ! ls "$OUT"/*.apk >/dev/null 2>&1; then
  log "ERROR: no APKs downloaded after 5 attempts"
  exit 1
fi

# Output dir has base APK plus splits; install them all.
log "Installing $TWICKETS"
"$ADB" install-multiple "$OUT"/*.apk

# BetterKnownInstalled marks it a Play Store install after a reboot.
log "Rebooting so BetterKnownInstalled marks $TWICKETS as Play Store-installed"
"$ADB" reboot
"$ADB" wait-for-device

# shellcheck disable=SC2016
"$ADB" shell 'timeout 360 sh -c '\''while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 1; done'\'''

log "Twickets install finished"
