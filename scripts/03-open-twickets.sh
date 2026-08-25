#!/usr/bin/env bash
# Launch Twickets normally, then attach frida and open the "Find" ticket stream.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

TWICKETS="co.twickets.droid"
HOOK="/opt/scripts/capture-keys.js"
RAW="/tmp/ckraw.txt"
DEVICE="emulator-5554"
TOKEN_PATTERN="x-prosopo-android-integrity-token': 'eyJ"

# Dismiss a System-UI ANR dialog (reappears during cold boot).
dismiss_anr() {
  if ui_dump && ui_center "isn't responding" >/dev/null 2>&1; then
    log "Dismissing System-UI ANR dialog"
    tap 'Wait' || true
  fi
}

mkdir -p /data/output

# Launch the app, let it settle, then attach frida. Attaching too early at a
# cold boot crashes the app under NDK translation, so we wait and retry the
# whole cycle if the attached app dies before the token mints.
dismiss_anr
log "Launching $TWICKETS"
token_seen=""
for attempt in 1 2 3; do
  log "Attempt $attempt: launch + settle + attach"
  "$ADB" -s "$DEVICE" shell am force-stop "$TWICKETS" || true
  sleep 2
  "$ADB" -s "$DEVICE" shell am start -n "$TWICKETS"/.splash.SplashActivity >/dev/null 2>&1 || true
  # Wait for the bottom-nav to appear (app fully up on a tabbed screen).
  nav_seen=""
  for _ in $(seq 1 40); do
    dismiss_anr
    if ui_dump && ui_center '^Account$' >/dev/null 2>&1 && ui_center '^Find$' >/dev/null 2>&1; then
      nav_seen=1
      break
    fi
    sleep 1
  done
  if [ -z "$nav_seen" ]; then
    log "WARN: app did not reach the tabbed screen"
    continue
  fi

  # Let the app settle before instrumenting it.
  sleep 8

  PID="$("$ADB" -s "$DEVICE" shell pidof "$TWICKETS" | tr -d '\r' | awk '{print $1}')"
  if [ -z "$PID" ]; then
    log "WARN: no pid (app died before attach)"
    continue
  fi
  log "Attaching frida to pid $PID"
  rm -f "$RAW"
  nohup uv tool run --from frida-tools frida -H 127.0.0.1:27042 \
    -p "$PID" -l "$HOOK" >"$RAW" 2>&1 &
  sleep 4

  # Open Find and keep driving requests until the token mints into $RAW.
  log "Opening Find (ticket stream)"
  tap '^Find$' || true
  sleep 6
  "$ADB" -s "$DEVICE" shell input swipe 540 1400 540 500 400 || true
  sleep 3
  for _ in $(seq 1 40); do
    if grep -qE "$TOKEN_PATTERN" "$RAW" 2>/dev/null; then
      token_seen=1
      break
    fi
    # Drive the app to keep catalogue requests firing until the token mints.
    if ui_dump; then
      if ui_center 'Something went wrong' >/dev/null 2>&1; then
        # Stream error screen has a "Try again" button; re-tap it.
        tap 'Try again' || true
      else
        # Find tab may land on its Explore landing page or the ticket stream;
        # re-tap Find and scroll to provoke more catalogue requests.
        tap '^Find$' || true
        "$ADB" -s "$DEVICE" shell input swipe 540 1400 540 500 400 || true
      fi
    fi
    sleep 1
  done

  # Clean up the attached frida for this attempt.
  pkill -f "capture-keys.js" 2>/dev/null || true

  if [ -n "$token_seen" ]; then
    log "Ticket stream rendered (integrity token captured)"
    break
  fi
  log "Token not captured on attempt $attempt"
done

if [ -z "$token_seen" ]; then
  log "WARN: integrity token not minted after $attempt attempts"
  "$ADB" -s "$DEVICE" exec-out screencap -p >/data/output/stream-failure.png 2>/dev/null || true
  log "Screenshot: /data/output/stream-failure.png"
  ui_flat || true
  # Dump the raw frida log so we can see if the hook attached or errored.
  log "=== raw frida output ($RAW) ==="
  cat "$RAW" 2>/dev/null || log "(no raw file)"
  log "=== end raw frida output ==="
fi
