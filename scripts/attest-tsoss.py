#!/usr/bin/env python3
"""Verify a map-walk PKCS8 against the leaf cert and write attest.json for
the TrickyStore-oss base. Reads /data/output/pkcs8.b64 (written by 05).

The walk emits more keys than the app's attest key (the daemon also holds
the Play-integrity key), so the leaf-cert match is the discriminator. Zero
Twickets traffic."""

import base64
import json
import re
import subprocess
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

ADB = "/opt/android-sdk/platform-tools/adb"
SERIAL = "emulator-5554"
LEAF = "/data/output/leaf.json"

try:
    b64s = [
        line.strip()
        for line in open("/data/output/pkcs8.b64").read().splitlines()
        if line.strip()
    ]
except FileNotFoundError:
    print("ERROR: /data/output/pkcs8.b64 missing — the map walk never captured keys")
    raise SystemExit(1)

leaf_pub = None
try:
    cert = x509.load_der_x509_certificate(base64.b64decode(open(LEAF).read().strip()))
    leaf_pub = cert.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
except FileNotFoundError:
    print("no leaf cert captured")

match = None
for i, b64 in enumerate(b64s):
    try:
        key = serialization.load_der_private_key(base64.b64decode(b64), password=None)
        assert key.curve.name == "secp256r1", key.curve.name
    except Exception as e:
        print(f"candidate[{i}] unreadable: {e}")
        continue
    pub = key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    print(f"candidate[{i}] secp256r1, pub={pub.hex()[:24]}")
    if leaf_pub and pub == leaf_pub:
        print(f"candidate[{i}] MATCHES the leaf cert pubkey — verified")
        match = key
        break
if match is None:
    if leaf_pub:
        print("ERROR: no candidate matches the leaf cert pubkey")
        raise SystemExit(1)
    # No leaf to discriminate against: the map walk emits the prosopo key last.
    match = serialization.load_der_private_key(
        base64.b64decode(b64s[-1]),
        password=None,
    )
    print("no leaf cert — trusting the last candidate (prosopo alias)")

key_pem = match.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)

r = subprocess.run(
    [
        ADB,
        "-s",
        SERIAL,
        "shell",
        "su 0 sh -c 'cat /data/data/co.twickets.droid/shared_prefs/prosopo_protect.xml'",
    ],
    capture_output=True,
)
m = re.search(b'<string name="key_attest_key_id">([^<]+)</', r.stdout)
assert m, "no key_attest_key_id in prefs — app has not attested"
json.dump(
    {
        "attest": {
            "key_pem": key_pem.decode(),
            "key_id": m.group(1).decode(),
            "source": "map-walk",
            "extracted_at": datetime.now(timezone.utc).isoformat(),
        }
    },
    open("/data/output/attest.json", "w"),
    indent=2,
)
print("key_id:", m.group(1).decode())
print("WROTE /data/output/attest.json")
