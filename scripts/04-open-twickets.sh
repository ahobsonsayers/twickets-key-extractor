#!/usr/bin/env bash
# Launch Twickets normally, then attach frida and open the "Find" ticket
# stream once. Success = the integrity JWE appearing in a captured request;
# the server's response (even a 403 screen) is irrelevant, since the keys
# are minted client-side and stay usable on unblocked IPs.
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

TWICKETS="co.twickets.droid"
HOOK="/opt/scripts/capture-keys.js"
RAW="/tmp/ckraw.txt"
DEVICE="emulator-5554"
TOKEN_PATTERN="x-prosopo-android-integrity-token': 'eyJ"
FRIDA_PID=""

# The attached CLI must not outlive this script: a leaked session blocks 04's
# attach (and its process tree OOM-kills the CI runner).
cleanup() {
  [ -n "$FRIDA_PID" ] && kill -9 "$FRIDA_PID" 2>/dev/null || true
  pkill -9 -f "capture-keys.js" 2>/dev/null || true
}
trap cleanup EXIT

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
  # A flagged IP can make the app's own launch API calls fail, leaving its
  # "Something went wrong, please try again" screen. Bounded recovery: tap
  # Try again up to 3 times with breathing room — hammering while the
  # server 403s is what got our IP flagged (AGENTS.md).
  nav_seen=""
  launch_probes=0

  for _ in $(seq 1 40); do
    dismiss_anr

    if ui_dump && ui_center '^Account$' >/dev/null 2>&1 && ui_center '^Find$' >/dev/null 2>&1; then
      nav_seen=1
      break
    fi

    if [ "$launch_probes" -lt 3 ] && ui_dump && ui_center 'Try again' >/dev/null 2>&1; then
      log "Launch-failure screen; tapping Try again ($((launch_probes + 1))/3)"
      tap 'Try again' || true
      launch_probes=$((launch_probes + 1))
      sleep 4
      continue
    fi

    sleep 1
  done

  if [ -z "$nav_seen" ]; then
    if ui_dump && ui_center 'Something went wrong' >/dev/null 2>&1; then
      log "WARN: app launch failed after 3 Try-again taps — server is rejecting this IP's launch requests"
    else
      log "WARN: app did not reach the tabbed screen"
    fi
    continue
  fi

  # Let the app settle before instrumenting it.
  sleep 10

  PID="$("$ADB" -s "$DEVICE" shell pidof "$TWICKETS" | tr -d '\r' | awk '{print $1}')" || PID=""

  if [ -z "$PID" ]; then
    log "WARN: no pid (app died before attach)"
    continue
  fi

  log "Attaching frida to pid $PID"
  rm -f "$RAW"
  nohup uv tool run --from frida-tools frida -H 127.0.0.1:27042 \
    -p "$PID" -l "$HOOK" >"$RAW" 2>&1 &
  FRIDA_PID=$!

  # Give frida time to attach and the hook to load before driving the app.
  sleep 10

  # Open Find and keep driving requests until the token mints into $RAW.
  log "Opening Find (ticket stream)"

  tap '^Find$' || true

  sleep 20

  "$ADB" -s "$DEVICE" shell input swipe 540 1400 540 500 400 || true

  sleep 3

  # Every tap below refires a catalogue request. Three probes with breathing
  # room, then stop tapping — hammering is what got our IP flagged
  # (AGENTS.md). We don't care how the server responds; we only need one
  # request to carry a minted JWE. If the token still hasn't appeared, the
  # outer attempt loop force-stops and relaunches the app for a fresh
  # window.
  probes=0
  for _ in $(seq 1 40); do
    if grep -qE "$TOKEN_PATTERN" "$RAW" 2>/dev/null; then
      token_seen=1
      break
    fi

    if [ "$probes" -ge 3 ]; then
      # Cap reached; just wait out the loop for the in-flight request.
      sleep 5
      continue
    fi

    # Drive the app to keep catalogue requests firing until the JWE appears.
    if ui_dump; then
      if ui_center 'Something went wrong' >/dev/null 2>&1; then
        # Stream error screen has a "Try again" button; re-tap it.
        tap 'Try again' || true
        probes=$((probes + 1))
      else
        # If the app is already warm and sitting on a loaded Find stream, tapping
        # Find does nothing and no new request fires. Re-entering the tab via
        # Home->Find forces a fresh catalogue fetch, which carries the token.
        tap '^Home$' || true
        sleep 5
        tap '^Find$' || true
        probes=$((probes + 1))
      fi
    fi

    sleep 5
  done

  # Clean up the attached frida for this attempt.
  cleanup

  if [ -n "$token_seen" ]; then
    # Hand the attest leaf cert to 04 while our session is still warm: the
    # hook sends it one-shot alongside the keys. 04 then never needs its own
    # frida attach.
    leaf_b64="$(grep -m1 "type': 'leaf'" "$RAW" |
      grep -o "payload': '[A-Za-z0-9+/=]*'" | cut -d"'" -f3)" || leaf_b64=""

    if [ -n "$leaf_b64" ]; then
      printf '%s' "$leaf_b64" >/data/output/leaf.json
      log "Leaf cert captured for 04"
    else
      rm -f /data/output/leaf.json
    fi

    log "Integrity token captured; keys are minted client-side regardless of server response"
    break
  else
    log "Token not captured on attempt $attempt"
  fi
done

if [ -z "$token_seen" ]; then
  log "Integrity token never appeared in a captured request"

  "$ADB" -s "$DEVICE" exec-out screencap -p >/data/output/stream-failure.png 2>/dev/null || true
  log "Screenshot: /data/output/stream-failure.png"

  ui_flat || true

  # Dump the raw frida log so we can see if the hook attached or errored.
  log "=== raw frida output ($RAW) ==="
  cat "$RAW" 2>/dev/null || log "(no raw file)"
  log "=== end raw frida output ==="

  echo "token never captured" >/data/output/token-failed.txt
fi
