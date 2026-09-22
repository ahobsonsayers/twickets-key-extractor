#!/usr/bin/env python3
"""SUPER basic off-device Twickets catalogue request (v3.20).

Gets a challenge, signs client_data with the extracted attest key, sends one
catalogue request, prints the response. That's it.

    pip install curl_cffi cryptography
    python3 replay-catalogue.py keys.json

Anti-block rules (AGENTS.md) — read them first. Short version:
- ONE run per session. No loops, no retries. A 403 means STOP, not retry.
- Only run this on user's explicit go-ahead, and never while the IP
  is flagged (if the app's own requests 403, you are flagged — wait).

keys.json comes from the pipeline (/data/output/keys.json): the 4 catalogue
keys plus the `attest` section extracted by 04 and folded in by 05.
"""

import base64
import json
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from curl_cffi import requests

SDK_VERSION = "1.0.2"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    keys = json.load(open(sys.argv[1]))
    attest = keys["attest"]

    ua = keys["User-Agent"]
    site_key = keys["x-prosopo-site-key"]
    jwe = keys["x-prosopo-android-integrity-token"]
    api_key = keys["api_key"]
    key_id = attest["key_id"]
    key = load_pem_private_key(attest["key_pem"].encode(), password=None)

    # 1. Get a fresh challenge (one request).
    r = requests.get(
        "https://protect.twickets.live/api/android/key-challenge",
        headers={
            "User-Agent": ua,
            "x-prosopo-site-key": site_key,
            "x-prosopo-android-sdk-version": SDK_VERSION,
        },
        impersonate="chrome131_android",  # Android Chrome TLS; plain curl is WAF-blocked
    )
    print("challenge:", r.status_code, r.text[:80])
    challenge = r.json()["challenge"]

    # 2. Sign client_data exactly the way the app does (c60/p.java + ia0/q.b):
    #    compact JSON, this key order, path INCLUDING query (q.b() = URL
    #    substring from the first '/' to '?'/#'), UTC ISO timestamp.
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = "/services/catalogue?count=10&q=countryCode=GB"
    client_data = (
        '{"method":"GET","path":"'
        + path
        + f'","challenge":"{challenge}","timestamp":"{ts}"}}'
    )
    sig = key.sign(client_data.encode(), ec.ECDSA(hashes.SHA256()))  # DER

    # 3. Send the catalogue request (one request) — same URL we signed.
    r = requests.get(
        "https://www.twickets.live" + path,
        headers={
            "User-Agent": ua,
            "x-prosopo-site-key": site_key,
            "x-prosopo-android-integrity-token": jwe,
            "x-prosopo-android-sdk-version": SDK_VERSION,
            "x-prosopo-android-key-id": key_id,
            "x-prosopo-android-assertion": base64.b64encode(sig).decode(),
            "x-prosopo-android-client-data": base64.b64encode(client_data.encode()).decode(),
            "x-prosopo-android-challenge": challenge,
        },
        impersonate="chrome131_android",
    )

    # 4. Done. Whatever it says, STOP here — never retry a 403.
    print("catalogue:", r.status_code)
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text)
    if r.status_code == 403:
        print("\n403 = STOP. Diagnose offline (AGENTS.md): compare client_data")
        print("byte-for-byte against a harvested one, check key_id/key freshness.")
        sys.exit(1)


if __name__ == "__main__":
    main()