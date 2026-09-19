#!/usr/bin/env python3
"""Extract the Twickets prosopo_attest_key private key from the emulator.

v3.20 signs every main-API request with the EC key stored in AndroidKeyStore
alias `prosopo_attest_key` (see LEARNINGS.md). On this emulator the "TEE" is
software (TrickyStore/TEESimulator), so the private key exists as bytes
somewhere we can reach with root. With key + key_id we can mint signatures
off-device (examples/replay-catalogue.py).

This script makes ZERO requests to Twickets servers. Ever. It only reads
device-local state (prefs, keybox, process memory).

Run INSIDE the container (the image's 04-extract-attest.sh does this
automatically; it drives the container's adb and needs `cryptography`):

    04-extract-attest.sh   # part of the numbered pipeline

Prereqs: the app is attested (key_id in prefs — run the pipeline up to 03
first) and the app has been relaunched recently (keygen happens once at app
start, so key material is freshest in memory right after a launch). Do NOT
clear prosopo_protect prefs — a fresh attestation generates a NEW key and
orphans this one.

Output: writes an `attest` object {key_pem, key_id, source, extracted_at}
to /data/output/attest.json (env-overridable via OUT_FILE); 05-extract-keys.sh
folds it into keys.json.
"""

import ast
import base64
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ADB = os.environ.get(
    "ADB",
    "/opt/android-sdk/platform-tools/adb"
    if os.path.exists("/opt/android-sdk/platform-tools/adb")
    else "adb",
)
SERIAL = os.environ.get("ADB_SERIAL", "emulator-5554")
FRIDA_CMD = os.environ.get("FRIDA_CMD", "frida")
FRIDA_HOST = os.environ.get("FRIDA_HOST", "127.0.0.1:27042")
APP = "co.twickets.droid"
ALIAS = "prosopo_attest_key"
PREFS = "/data/data/co.twickets.droid/shared_prefs/prosopo_protect.xml"
KEYBOX = "/data/adb/tricky_store/keybox.xml"
DUMP_DIR = "/data/local/tmp/attestdump"
OUT_FILE = os.environ.get("OUT_FILE", "/data/output/attest.json")
P256_OID = b"\x2a\x86\x48\xce\x3d\x03\x01\x07"  # 1.2.840.10045.3.1.7


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

LEAF_JS = r"""
Java.perform(function () {
  try {
    var ks = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
    ks.load(null, null);
    var chain = ks.getCertificateChain('prosopo_attest_key');
    if (!chain || chain.length === 0) { send({type:'err', payload:'alias not found'}); return; }
    var b64 = Java.use('android.util.Base64').encodeToString(chain[0].getEncoded(), 2);
    send({type:'leaf', payload: b64});
  } catch (e) { send({type:'err', payload: String(e)}); }
});
"""


def get_leaf_pubkey():
    """Attach frida to the running app, read the leaf cert's public key."""
    # Leaked frida CLI sessions (e.g. 03's still-attached hook, or a previous
    # 04 run) block a new attach indefinitely. The CLIs run in THIS container
    # (uv/frida), not on the device, so kill them here; frida-server (on
    # device, different cmdline) survives.
    subprocess.run(
        ["pkill", "-9", "-f", "frida .*-H 127.0.0.1:27042"], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)

    # pidof exits 1 with no output when the app is dead (03's frida pkill
    # can take the app down); one relaunch is safe — prefs make the app
    # short-circuit attestation, so no new key gets minted.
    out = adb("shell", f"pidof {APP}", check=False).strip()
    if not out:
        adb("shell", "am start -n co.twickets.droid/.splash.SplashActivity", check=False)
        time.sleep(15)
        out = adb("shell", f"pidof {APP}", check=False).strip()
    if not out:
        die(f"{APP} is not running — launch it once, wait ~15s, re-run this.")
    pid = out.split()[0]

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(LEAF_JS)
        js = f.name

    cmd = f"{FRIDA_CMD} -H {FRIDA_HOST} -p {pid} -l {js}".split()
    try:
        # Unbuffered binary pipe: select() watches the raw fd, so a buffered
        # text wrapper could hide already-arrived lines from it.
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    except FileNotFoundError:
        die(f"frida CLI not found ({FRIDA_CMD.split()[0]}) — set FRIDA_CMD to a working frida")

    leaf_b64 = None
    deadline = time.time() + 90
    try:
        import select

        fd = p.stdout.fileno()
        buf = b""
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 1.0)
            if r:
                chunk = os.read(fd, 65536)
                if chunk:
                    buf += chunk
            if p.poll() is not None and not r:
                break
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode(errors="replace")
                if "message: " not in text:
                    continue
                payload = text.split("message: ", 1)[1].replace(" data: None", "").strip()
                try:
                    inner = ast.literal_eval(payload)["payload"]
                except Exception:
                    continue
                if not isinstance(inner, dict):
                    continue
                if inner.get("type") == "leaf":
                    leaf_b64 = inner["payload"]
                    break
                if inner.get("type") == "err":
                    die(f"frida could not read the keychain: {inner['payload']}")
            if leaf_b64:
                break
    finally:
        p.kill()
        os.unlink(js)

    if not leaf_b64:
        die("no leaf cert captured from frida (app died? attach too early?)")
    cert = x509.load_der_x509_certificate(base64.b64decode(leaf_b64))
    return cert.public_key()


def pub_bytes(key):
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


# ---------------------------------------------------------------- keybox check

def load_keybox_ec_keys():
    """All EC private keys found in TrickyStore's keybox.xml (hypothesis A)."""
    xml = root_read(KEYBOX)
    keys = []
    for m in re.finditer(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", xml, re.S):
        try:
            k = load_pem_private_key(m.group(0).encode(), password=None)
        except Exception:
            continue
        if isinstance(k, ec.EllipticCurvePrivateKey):
            keys.append(k)
    return keys


# ---------------------------------------------------------------- memory scan

def dump_candidates():
    """Dump readable memory of keystore/keymint-ish processes. Returns
    [(pid, name, [(file_offset_base, bytes)])]."""
    ps = adb_shell("ps -A -o PID,NAME 2>/dev/null || ps -A")
    wanted = ("keystore", "keymint", "keymaster", "tee", "tricky")
    procs = []
    for line in ps.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        pid, name = parts[0], parts[1]
        if not pid.isdigit():
            continue
        if any(w in name.lower() for w in wanted):
            procs.append((pid, name))
    if not procs:
        die("no keystore/keymint-like processes found")

    adb_shell(f"mkdir -p {DUMP_DIR}")
    results = []
    for pid, name in procs:
        maps = adb_shell(f"cat /proc/{pid}/maps")
        ranges = []
        total = 0
        for line in maps.splitlines():
            # 7f8b00000000-7f8b00200000 rw-p 00000000 00:00 0  [anon:...]
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (....) \S+ \S+ \S+\s*(\S*)", line)
            if not m:
                continue
            start, end, perms, path = int(m[1], 16), int(m[2], 16), m[3], m[4]
            if "r" not in perms:
                continue
            if path and not (path.startswith("[heap]") or path.startswith("[anon:") or path.startswith("[stack")):
                continue
            size = end - start
            # Round down to page multiple: dd skip/count are in pages, so a
            # non-multiple range silently dumps the wrong window.
            size -= size % 4096
            if size <= 0:
                continue
            # Giant ranges OOM-kill the emulator (CI exit 1 at 04).
            if size > 64 * 1024 * 1024:
                continue
            ranges.append((start, size))
        # Deterministic: scan the biggest ranges first (key material lives in
        # heap pools, not the dozens of tiny guard regions).
        ranges.sort(key=lambda r: -r[1])
        total = 0
        kept = []
        for r in ranges:
            if len(kept) >= 32:  # cap total work
                break
            if total + r[1] > 256 * 1024 * 1024:
                continue
            total += r[1]
            kept.append(r)
        ranges = kept

        dumps = []
        for idx, (start, size) in enumerate(ranges):
            dst = f"{DUMP_DIR}/dk_{pid}_{idx}.bin"
            adb_shell(
                f"dd if=/proc/{pid}/mem ibs=4096 obs=1048576 "
                f"skip=$(( {start} / 4096 )) count=$(( {size} / 4096 )) "
                f"2>/dev/null > {dst}"
            )
            adb_shell(f"chmod 644 {dst}")
            adb("pull", dst, "/tmp/attest-local.bin", check=False)
            try:
                with open("/tmp/attest-local.bin", "rb") as f:
                    data = f.read()
                if data:
                    dumps.append((start, data))
            except OSError:
                pass
            adb_shell(f"rm -f {dst} /tmp/attest-local.bin")
        if dumps:
            results.append((pid, name, dumps))
    return results


P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def try_scalar(s_int, leaf_pub):
    """Does integer s derive the leaf public key?"""
    if s_int <= 1 or s_int >= P256_ORDER:
        return None
    try:
        k = ec.derive_private_key(s_int, ec.SECP256R1())
    except Exception:
        return None
    return k if pub_bytes(k.public_key()) == leaf_pub else None


def scan_dump(start, data, leaf_pub):
    """Find the P-256 scalar in one dump; returns a private key or None."""

    # (a) DER-encoded EC private keys (SEC1 / PKCS8 fragments)
    i = data.find(P256_OID)
    while i != -1:
        # SEC1: 02 01 01 04 20 <S32> a0 0a 06 08 <OID>
        if data[i - 38 : i - 36] == b"\x04\x20" and data[i - 4 : i] == b"\xa0\x0a\x06\x08":
            k = try_scalar(int.from_bytes(data[i - 36 : i - 4], "big"), leaf_pub)
            if k:
                return k
        # PKCS8: 06 08 <OID> 04 22 04 20 <S32>
        if data[i + 9 : i + 13] == b"\x04\x22\x04\x20":
            k = try_scalar(int.from_bytes(data[i + 13 : i + 45], "big"), leaf_pub)
            if k:
                return k
        i = data.find(P256_OID, i + 1)

    # (b) BoringSSL BIGNUM: {d ptr, width=4, dmax=4, flags}; d points to 4 LE
    # u64 limbs, least-significant limb first.
    j = data.find(b"\x04\x00\x00\x00\x04\x00\x00\x00")
    while j != -1:
        if j >= 8:
            ptr = struct.unpack_from("<Q", data, j - 8)[0]
            # ptr is absolute in the process; convert to this dump's offset.
            cand_off = ptr - start if start <= ptr < start + len(data) else None
            for off in (cand_off, ptr):  # absolute, or raw offset if unmapped
                if off is None or not 0 <= off <= len(data) - 32:
                    continue
                s_le = struct.unpack_from("<4Q", data, off)
                s_bytes = b"".join(x.to_bytes(8, "little") for x in s_le)
                k = try_scalar(int.from_bytes(s_bytes, "little"), leaf_pub)
                if k:
                    return k
        j = data.find(b"\x04\x00\x00\x00\x04\x00\x00\x00", j + 1)

    # (c) brute: every 32-byte window, big-endian (last resort, expensive)
    if "--brute" in sys.argv:
        for off in range(0, min(len(data) - 32, 32 * 1024 * 1024)):
            k = try_scalar(int.from_bytes(data[off : off + 32], "big"), leaf_pub)
            if k:
                return k
    return None


# ---------------------------------------------------------------- main

def main():
    print("Reading prefs for key_id ...")
    key_id = read_key_id()
    print(f"  key_attest_key_id = {key_id}")

    print("Attaching frida to read the leaf cert's public key ...")
    leaf_key = get_leaf_pubkey()
    leaf_pub = pub_bytes(leaf_key)
    print(f"  leaf pubkey (uncompressed) = {leaf_pub.hex()[:24]}...")

    # Hypothesis A: TrickyStore generate-mode hands the app the keybox key.
    print("Checking TrickyStore keybox for a matching key ...")
    for k in load_keybox_ec_keys():
        if pub_bytes(k.public_key()) == leaf_pub:
            print("  MATCH: the app's attest key IS a keybox key (hypothesis A)")
            return emit(k, key_id, "keybox", leaf_pub)

    # Hypothesis B: app-generated key; the scalar lives in keystore daemon memory.
    print("No keybox match — dumping keystore/keymint process memory ...")
    print("  (best right after a single app launch; keygen is once at start)")
    for pid, name, dumps in dump_candidates():
        for start, data in dumps:
            k = scan_dump(start, data, leaf_pub)
            if k:
                print(f"  FOUND in {name} (pid {pid})")
                return emit(k, key_id, f"memory:{pid}", leaf_pub)

    die(
        "key not found.\n"
        "Try once more right after a single app relaunch (key material is\n"
        "freshest then), or pass --brute as a last resort.\n"
        "Remember the anti-block rules (AGENTS.md): no request spam, one\n"
        "relaunch per session, never re-launch in a loop."
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
    print("05-extract-keys.sh folds this into keys.json; use that with")
    print("examples/replay-catalogue.py — and follow the AGENTS.md anti-block")
    print("rules: ONE replay per session.")


if __name__ == "__main__":
    main()