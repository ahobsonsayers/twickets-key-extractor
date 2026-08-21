#!/usr/bin/env bash
# Install Twickets via gplaydl + anonymous Aurora dispenser, then reboot so BetterKnownInstalled marks it a Play Store install.
# shellcheck source=scripts/common.sh
set -euo pipefail
source /opt/scripts/common.sh

TWICKETS="co.twickets.droid"
DISPENSER="https://auroraoss.com/api/auth"
OUT="/tmp/gplaydl-twickets"

# Skip if already present.
if is_installed "$TWICKETS"; then
  log "Twickets already installed"
  exit 0
fi

# arm64: x86_64 AVD runs ARM apps via NDK translation.
log "Downloading latest $TWICKETS from Play Store via gplaydl"
rm -rf "$OUT"
mkdir -p "$OUT"
uv tool run gplaydl download "$TWICKETS" -a arm64 -d "$DISPENSER" -o "$OUT"

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
