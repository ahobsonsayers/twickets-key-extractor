#!/usr/bin/env python3
"""Extract the Twickets prosopo_attest_key private key from the emulator.

v3.20 signs every main-API request with the EC key stored in AndroidKeyStore
alias `prosopo_attest_key` (see LEARNINGS.md). On this emulator the "TEE" is
software (TrickyStore/TEESimulator), so the private key exists as bytes
somewhere we can reach with root. With key + key_id we can mint signatures
off-device (examples/replay-catalogue.py).

This script makes ZERO requests to Twickets servers. Ever. It only reads
device-local state (prefs and the hook's capture files).

Run INSIDE the container (the image's 05-extract-attest.sh does this
automatically; it drives the container's adb and needs `cryptography`):

    05-extract-attest.sh   # part of the numbered pipeline

Prereqs: the pipeline ran 03 (hook armed) and 04 (app attested — key_id in
prefs; keygen fires at 04's first launch and the hook catches it). Do NOT
clear prosopo_protect prefs — a fresh attestation generates a NEW key and
orphans this one.

Output: writes an `attest` object {key_pem, key_id, source, extracted_at}
to /data/output/attest.json (env-overridable via OUT_FILE); 06-extract-keys.sh
folds it into keys.json.
"""

import base64
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ADB = os.environ.get(
    "ADB",
    "/opt/android-sdk/platform-tools/adb"
    if os.path.exists("/opt/android-sdk/platform-tools/adb")
    else "adb",
)
SERIAL = os.environ.get("ADB_SERIAL", "emulator-5554")
APP = "co.twickets.droid"
ALIAS = "prosopo_attest_key"
PREFS = "/data/data/co.twickets.droid/shared_prefs/prosopo_protect.xml"
OUT_FILE = os.environ.get("OUT_FILE", "/data/output/attest.json")


def die(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)


def adb(*args, check=True):
    """adb shell command; returns stdout (CRs stripped)."""
    cmd = [ADB, "-s", SERIAL, *args]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if check and r.returncode != 0:
        die(f"adb {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.replace("\r", "")


def adb_shell(sh):
    """Run a shell snippet as root via the proven su-0-sh-c pattern."""
    return adb("shell", f'su 0 sh -c {sh!r}', check=False)


def root_read(path):
    out = adb_shell(f"cat {path}")
    if not out.strip():
        die(f"could not read {path} as root (is the emulator up? plain output empty = not rooted?)")
    return out


# ---------------------------------------------------------------- prefs/key_id

def read_key_id():
    xml = root_read(PREFS)
    m = re.search(r'<string name="key_attest_key_id">([^<]+)</string>', xml)
    if not m:
        die(
            "no key_attest_key_id in prefs — the app has not attested.\n"
            "Run the pipeline through 03 so the app passes key-attest,\n"
            "then re-run this. Force-stop + ONE relaunch re-attests if needed.\n"
            "Do NOT spam relaunches — see the anti-block rules in AGENTS.md."
        )
    return m.group(1)


# ---------------------------------------------------------------- leaf pubkey

LEAF_FILE = os.environ.get("LEAF_FILE", "/data/output/leaf.json")


def leaf_from_03():
    """Fast path: 03's capture session already sent the leaf cert; a second
    frida attach here is what OOM-killed the CI runner."""
    try:
        with open(LEAF_FILE) as f:
            b64 = f.read().strip()
        cert = x509.load_der_x509_certificate(base64.b64decode(b64))
        print(f"  leaf pubkey from 03's capture ({LEAF_FILE})")
        return cert.public_key()
    except Exception:
        return None


def pub_bytes(key):
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


# ---------------------------------------------------------------- main

RAW_FILE = os.environ.get("RAW_FILE", "/data/output/attest-raw.txt")
HOOK_LOG = "/tmp/attest-hook.log"


def key_from_hook(leaf_pub):
    """Primary path: the generate-time hook (03, still attached in the
    background) captured the PKCS8 at keygen. The capture can land any
    moment after 04's first launch, so poll the hook log briefly."""
    deadline = 60
    print(f"  waiting up to {deadline}s for the hook's capture ...")
    while deadline > 0:
        b64 = ""
        if os.path.exists(RAW_FILE) and os.path.getsize(RAW_FILE) > 0:
            b64 = open(RAW_FILE).read().strip()
        elif os.path.exists(HOOK_LOG):
            line = ""
            with open(HOOK_LOG, errors="replace") as f:
                for l in f:
                    if "'type': 'attest'" in l:
                        line = l
                        break
            if line:
                m = re.search(r"payload': '([A-Za-z0-9+/=]+)'", line)
                if m:
                    b64 = m.group(1)
        if b64:
            try:
                key = serialization.load_der_private_key(
                    base64.b64decode(b64), password=None
                )
                return key
            except Exception as e:
                print(f"  generate-hook capture unreadable: {e}")
                return None
        time.sleep(2)
        deadline -= 2
    return None


def hook_forensics():
    """Why did the hook never produce a capture? Show its log tail + liveness."""
    if os.path.exists(HOOK_LOG):
        print("--- hook log tail (/tmp/attest-hook.log) ---")
        tail = open(HOOK_LOG, errors="replace").read().splitlines()[-20:]
        for line in tail:
            print("  " + line)
    else:
        print("--- hook log missing entirely ---")
    r = subprocess.run(["pgrep", "-af", "hook-attest-key.js"], capture_output=True, text=True)
    alive = r.stdout.strip()
    print(f"hook process: {alive if alive else 'NOT RUNNING'}")


def main():
    print("Reading prefs for key_id ...")
    key_id = read_key_id()
    print(f"  key_attest_key_id = {key_id}")

    print("Reading leaf cert from 03's capture ...")
    leaf_key = leaf_from_03()
    if leaf_key is None:
        die(
            f"no leaf cert from 03's capture ({LEAF_FILE} missing or "
            "unreadable) — skipping attest extraction (frida fallback removed)"
        )
    leaf_pub = pub_bytes(leaf_key)
    print(f"  leaf pubkey (uncompressed) = {leaf_pub.hex()[:24]}...")

    # Primary: the generate-time hook (03) captured the PKCS8 at keygen.
    print("Checking generate-hook capture ...")
    k = key_from_hook(leaf_pub)
    if k:
        if pub_bytes(k.public_key()) == leaf_pub:
            print("  MATCH: generate-time capture matches the leaf cert")
            return emit(k, key_id, "generate-hook", leaf_pub)
        print("  captured key does NOT match the leaf cert — ignoring")

    hook_forensics()
    die(
        f"generate-hook capture missing or does not match the leaf cert.\n"
        "03-hook-attest.sh keeps the hook attached in the background while\n"
        "04 launches the app (keygen fires at first launch); the hook log\n"
        "is /tmp/attest-hook.log, capture file /data/output/attest-raw.txt."
    )


def emit(key, key_id, source, leaf_pub):
    if pub_bytes(key.public_key()) != leaf_pub:
        die("internal error: key does not match leaf cert")
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    keys = {"attest": {
        "key_pem": pem,
        "key_id": key_id,
        "source": source,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
    }}
    with open(OUT_FILE, "w") as f:
        json.dump(keys, f, indent=2)
    print(f"\nWrote {OUT_FILE} (source: {source})")
    print("06-extract-keys.sh folds this into keys.json; use that with")
    print("examples/replay-catalogue.py — and follow the AGENTS.md anti-block")
    print("rules: ONE replay per session.")


if __name__ == "__main__":
    main()