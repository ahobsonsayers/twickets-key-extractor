#!/usr/bin/env bash
# Shared helpers. Library — source it, don't execute it.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "This is a library. Source it from another script." >&2
  exit 0
fi

set -euo pipefail

ADB="${ADB:-/opt/android-sdk/platform-tools/adb}"
PY="${PY:-python3}"
LOCAL_DUMP=/tmp/ui.xml

# Timestamped log line.
log() {
  printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"
}

# Dump UI hierarchy into $LOCAL_DUMP; prints 0 on success.
ui_dump() {
  "$ADB" shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1 || return 1

  "$ADB" shell cat /sdcard/ui.xml >"$LOCAL_DUMP" 2>/dev/null || return 1
  [ -s "$LOCAL_DUMP" ] || return 1
}

# Print flat node list ("text=.. desc=.. x,y x,y") for agent debugging.
ui_flat() {
  "$PY" - <<'PYEOF'
import xml.etree.ElementTree as ET
try:
    root = ET.parse('/tmp/ui.xml').getroot()
except Exception:
    print("no ui dump")
    raise SystemExit
for el in root.iter('node'):
    t = (el.get('text') or '').strip()
    d = (el.get('content-desc') or '').strip()
    if t or d:
        print(f"text={t!r} desc={d!r} bounds={el.get('bounds')}")
PYEOF
}

# Print center "x y" of first node matching regex $x; empty if no match.
ui_center() {
  "$PY" - "$1" <<'PYEOF'
import re, sys
pat = sys.argv[1]
try:
    import xml.etree.ElementTree as ET
    root = ET.parse('/tmp/ui.xml').getroot()
except Exception:
    sys.exit(0)
rx = re.compile(pat, re.I)


def center(el):
    b = el.get('bounds')
    m = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', b or '')
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


def matches(el):
    text = el.get('text') or ''
    desc = el.get('content-desc') or ''
    return bool(rx.search(text) or rx.search(desc))


# Prefer the clickable node (the actual button) over a matching label.
for el in root.iter('node'):
    if matches(el) and el.get('clickable') == 'true':
        c = center(el)
        if c:
            print(*c)
            sys.exit(0)
for el in root.iter('node'):
    if matches(el):
        c = center(el)
        if c:
            print(*c)
            sys.exit(0)
sys.exit(0)
PYEOF
}

# Tap center of first node matching regex $1; returns 0 if tapped.
tap() {
  local coord
  coord=$(ui_center "$1")
  [ -n "$coord" ] || return 1

  # shellcheck disable=SC2086
  "$ADB" shell input tap $coord
  sleep 1
}

# Wait up to ~$2 seconds for a node matching regex $1.
wait_text() {
  for _ in $(seq 1 "${2:-30}"); do
    if ui_dump && [ -n "$(ui_center "$1")" ]; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# Type text into focused field (spaces escaped for adb input).
type_text() {
  "$ADB" shell input text "${1// /%s}"
  sleep 1
}

keyevent() {
  "$ADB" shell input keyevent "$1"
  sleep 1
}

is_installed() {
  "$ADB" shell pm path "$1" >/dev/null 2>&1
}

launch() {
  "$ADB" shell monkey -p "$1" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
  sleep 3
}

open_url() {
  "$ADB" shell am start -a android.intent.action.VIEW -d "$1" >/dev/null 2>&1
  sleep 3
}
