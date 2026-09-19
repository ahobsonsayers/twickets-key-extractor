# Twickets catalogue API on a rooted x86_64 AVD — learnings

Extending `ghcr.io/ahobsonsayers/androotu` so a fresh boot installs Twickets
(`co.twickets.droid`) and captures the 4 keys needed to call its catalogue
endpoint outside the app. The distilled record — read before touching this
stack.

## What the image does (fresh `/data` boot)

1. AVD create → boot → modules (Integrity Box, KSU-Next, SUSFS, ReZygisk,
   TEESimulator, **BetterKnownInstalled**) → Supreme profile → verify.
2. `01-install-twickets.sh`: installs latest Twickets from Google Play via
   **gplaydl** using the **official dispenser** (`dispenser.gplaydl.com`,
   authenticated by a per-machine API key supplied as the `GPLAYDL_CONFIG`
   secret), then reboots so **BetterKnownInstalled** re-marks it as a Play
   Store install.
3. `02-start-frida.sh`: ensures frida-server is running and forwards its port.
4. `03-open-twickets.sh`: launches the app normally, waits for it to settle,
   **attaches** frida (`-p`, not spawn — spawn crashes under translation), taps
   the **Find** bottom tab, and drives requests until the JWE token mints.
5. `04-extract-attest.sh`: best-effort extraction of the v3.20 attestation
   signing key (runs `extract-attest-key.py`, zero Twickets traffic) into
   `attest.json`. Failure is non-fatal — the 4 catalogue keys still publish.
6. `05-extract-keys.sh`: extracts the 4 request keys from the hook output,
   folds `attest.json` in, and writes `/data/output/keys.json`. The final
   gate — fails if any of the 4 keys is missing.

**Status under v3.20**: the capture works end-to-end (all 4 keys land in
keys.json) and — with the TrickyStore fix in `01` — the app itself passes key
attestation again and its requests return 200. The JWE still doesn't replay
**off-device**: v3.20 also signs every request with per-request
hardware-attestation headers, which can't be reproduced outside the app (see
the v3.20 section). The pipeline remains useful for the 3 static keys, the
JWE, and for verifying what the live app sends.

## The 4 catalogue keys (`/data/output/keys.json`)

| key | value | kind |
|---|---|---|
| `api_key` | `3aaf0790-5e80-4ebc-b2e3-349b35e06656` | static (query param) |
| `User-Agent` | `Twickets/3.20 (Android/16)` | static (header) |
| `x-prosopo-site-key` | `5EZVvsHMrKCFKp5NYNoTyDjTjetoVo1Z4UNNbTwJf1GfN6Xm` | static (header) |
| `x-prosopo-android-integrity-token` | dynamic JWE `eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0...` | dynamic per-launch (header) |

Replay (no cookie needed) → HTTP 200 — **true through v3.19 only**. Under
v3.20 every request also needs a valid per-request attestation signature
that can't be captured-and-replayed from outside the app (see the v3.20
section below):

```sh
curl 'https://www.twickets.live/services/catalogue?count=10&q=countryCode%3DGB&api_key=<KEY>' \
  -H 'User-Agent: Twickets/3.20 (Android/16)' \
  -H 'x-prosopo-site-key: 5EZVvsHMrKCFKp5NYNoTyDjTjetoVo1Z4UNNbTwJf1GfN6Xm' \
  -H 'x-prosopo-android-integrity-token: <JWE>'
```

The "play jwe" is `x-prosopo-android-integrity-token` (JWE `{alg:A256KW,
enc:A256GCM}`). The "proposer session" is `x-prosopo-site-key`. The JWE is
minted only after the app warms up — never present on the very first request
after launch. It needs the Play-Integrity and `protect/init` steps of the
v3.20 handshake, which **do** complete on this emulator — the key-attestation
step never does (below), but that doesn't block the mint.

The client would re-mint it only every ~22h (79200000 ms, `c60/f.java`),
but the **server** rejects it within minutes — verified live: a token that
returned 200 came back 403 minutes later, and a stale-but-format-valid JWE
is also 403. Only minutes-old tokens replay. So re-extract **per session**,
not per day; the daily 06:00 workflow run is a ceiling, not a cadence.

## v3.20 (versionCode 189): what changed — and what it breaks

Google Play now serves v3.20, and the [decompile
repo](https://github.com/ahobsonsayers/twickets-decompile) documents it
(source-only; its live checks were against v3.19):

- **Every main-API request now also carries** `x-prosopo-android-sdk-version:
  1.0.2` (static) plus four **hardware-backed key-attestation headers**:
  `x-prosopo-android-key-id`, `-assertion` (base64 ECDSA-SHA256 over
  `-client-data`), `-client-data` (base64 JSON `{method, path, challenge,
  timestamp}`), `-challenge`. The signing key lives in AndroidKeyStore
  (`prosopo_attest_key`) and the signature is bound to each request, so
  these are **not statically reproducible** and are not captured.
- **The pre-JWE handshake on `protect.twickets.live`**: `GET
  /api/android/key-challenge` → `POST /api/android/key-attest` (stores
  `key_id` in prefs `prosopo_protect`), then `GET
  /api/android/integrity-nonce` feeds the Play-Integrity `POST
  /api/android/integrity`; `POST /api/protect/init` mints the JWE.
- The JWE itself is still stored in SharedPreferences
  `prosopo_protect/integrity_token` (root-readable without Frida, if ever
  needed as a fallback capture path).
- keys.json still ships the 4 replay keys; the hook additionally
  logs `x-prosopo-android-sdk-version` for visibility.

### Key-attestation enforcement is LIVE — the fix is TrickyStore

Verified live on v3.20 (2026-09-18): with the stock module setup the app's
**own** catalogue requests return **403** on this emulator. Traced with a
diagnostic Frida hook over the app's real classes (`c60.c` attestation,
guard OkHttp client, prefs writes):

1. The app runs key attestation **once at startup** (`c60.o` ctor →
   `f(…, 1)` → `c.a()` → `c.c()`), guarded by prefs+`AtomicBoolean`, with
   **catch-all swallows** — a failure is never retried and never logged.
2. It gets all the way to a successful TEE keygen (`TEESimulator` keymint
   works: keypair generated with the server's challenge) — then
   `POST /api/android/key-attest` returns **403** with the body
   `{"error":"Attestation Failed","message":"invalid certificate
   chain: root is not a pinned Google attestation root"}`.
3. The endpoint pins **Google's hardware-attestation root**. The emulator's
   own software keymint issues chains rooted in its simulated root, so the
   attestation can never pass. `key_id` stays null forever → the guard
   interceptor `c60.p` signs nothing → every main-API request 403s.
4. Server-side validation order (probed via curl): DER/base64 decode →
   challenge single-use consumption → cert-chain parse → **root pin**. A
   rejected attestation consumes the challenge, so retries need a fresh
   `key-challenge` GET each time.

**The fix**: the base image already ships **TrickyStore** with a keybox whose
root cert is a byte-exact match for Google's published *Key Attestation CA1*
root — but Twickets wasn't in its target list, so its keygen was never
intercepted. Adding `co.twickets.droid` to `/data/adb/tricky_store/target.txt`
(`01-install-twickets.sh` does this now) makes TrickyStore generate the
attestation chain from the keybox → the key-attest POST passes the root pin →
`key_id` is issued and stored in prefs `prosopo_protect/key_attest_key_id` →
the app signs and its catalogue requests return 200 again (verified live:
Find tab renders real listings; the JWE even replayed at 32h old while
signed by the app).

### Off-device replay: still dead under v3.20

Even with the app itself fixed, a captured set cannot be replayed from
outside — verified by harvesting a **fresh, unconsumed** signed request via
a hook that aborts it before it leaves the device, then replaying it from
the host 0.7s later, byte-identical, with the session cookie added:

- full header set (4 keys + all attestation headers + cookie) → **403**
  `{"error":"Android key attestation verification failed"}`
- without the attestation headers → 403 "Android integrity verification
  failed" (the JWE gate); keys-only → same. Two distinct gates stack.
- **not** a TLS-fingerprint gate: `curl_cffi` (chrome131 impersonation)
  gets past the CloudFront WAF that blocks system curl and reaches the
  origin checker — still the attestation 403. `tls-client` okhttp profiles
  behave the same.
- So the signature verifies against server-side state beyond the request
  bytes (challenge binding/issuance heuristics we can't see). Don't burn
  time on transport impersonation: replay is dead until enforcement
  changes.

### Off-device signing (experimental, built 2026-09-19, UNTESTED)

If replay is dead but the app can sign, the remaining escape is to **get
the private key itself** and sign requests ourselves. On this emulator
that's possible in principle: the "TEE" is software (TrickyStore's
keymint), so the private key exists as bytes somewhere root can reach.
On a real phone it isn't (the key never leaves the chip).

Two hypotheses for where the key lives:

- **A: TrickyStore hands the app a keybox key.** In generate mode
  TrickyStore may sign with the keybox's own EC private key — then the
  extractable key is sitting in `/data/adb/tricky_store/keybox.xml`
  (root-readable).
- **B: the app generated its own key**, which lives as plaintext/bignum
  state in the keystore/keymint daemon's memory. Dump those processes
  right after an app launch (keygen is once at start) and scan for the
  P-256 scalar (DER EC fragments, BoringSSL `bignum_st` shape, or
  `--brute` windows), verifying candidates against the leaf cert's
  public key.

Built (in `scripts/`, wired into the pipeline as `04-extract-attest.sh`;
neither makes any request unless run):

- `extract-attest-key.py` — reads `key_id` from prefs + leaf pubkey via a
  frida attach, checks the keybox first (A), falls back to a memory
  dump+scan (B). Zero Twickets traffic. Writes the result as an `attest`
  section to `attest.json`; `05-extract-keys.sh` folds it into `keys.json`
  (one file, all keys).
- `examples/replay-catalogue.py` — the super-basic prover: one
  key-challenge GET → sign `client_data` → one catalogue GET → print.
  Uses `curl_cffi` chrome131_android (plain curl/urllib get
  WAF-blocked). Takes the single `keys.json`.

Runbook for the first live test (ONLY with the user's go-ahead, and only
once unflagged — fresh boot / new IP first):

1. Pipeline once (`01`–`05` → `keys.json`, attest included). Don't clear
   `prosopo_protect` prefs afterwards — a re-attestation generates a new
   key and orphans the extracted one.
2. (04 already extracted the attest key — zero requests.)
3. Run `examples/replay-catalogue.py` **once**. Read the verdict. STOP.
4. If 403 "Android key attestation verification failed": compare our
   `client_data` byte-for-byte against a real harvested one (passive
   hook) — compact JSON, this exact key order, path without query,
   `timestamp` `%Y-%m-%dT%H:%M:%SZ` UTC; signature is DER (Java
   `SHA256withECDSA`), base64 with padding (= Java `NO_WRAP`).

Escalation path if signing alone still 403s (v2, NOT built): full
off-device attestation — mint our own leaf cert carrying the pubkey plus
a KeyDescription attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
with a fresh challenge, signed by the keybox leaf key, chain
`[our_leaf, keybox_leaf, Droid CA3, Droid CA2, root]`, and `POST
/api/android/key-attest` from the host for our own `key_id`. The endpoint
is callable off-device and TrickyStore chains pass its root pin — the
risk is unknown server strictness on chain signatures, basicConstraints
and attestation-record fields.

### Don't probe-farm the server

**Read `AGENTS.md` first — its rules are binding, not advice.** The short
version: never loop/retry/batch against Twickets servers; at most ONE
catalogue request (+ its one key-challenge GET) per session and only with
the user's go-ahead; one app relaunch per session; if a live test fails,
diagnose offline and wait.

What happened (2026-09-18/19): the keybox identity (or the host IP — both
share the NAT address baked into `session_jwt`) got flagged after ~1 hour of
probe traffic: ~4 rapid `key_id` mints plus a stream of failed-verify
replays. Afterwards **even the app's own requests 403**, fresh `key_id` or
not, and it did **not** recover after **10+ idle hours** (re-checked
2026-09-19: key-challenge GETs 200, catalogue 403 — block at verify, not
issuance). The key-attest endpoint kept issuing new `key_id`s to the
flagged keybox the whole time. Extraction runs should be gentle: launch,
drive the app once, extract, done.

## Licensing: why Twickets was self-exiting

- Twickets v3.19 ships **Play Automatic Integrity Protection**
  (`com.pairip.licensecheck.LicenseActivity`). If the Play Integrity
  `appLicensingVerdict` isn't `LICENSED`, it calls `System.exit(0)` and dies.
- Installed via Aurora/anonymous adb, the device Play session is unlicensed →
  v3.19 exits. v3.18 (versionCode 178) doesn't enforce it.
- **BetterKnownInstalled** (a KSU module in the base image) patches
  `packages.xml` to present every app as Play Store-installed → AIP/licensing
  checks pass → v3.19 runs. This was the fix.

## Frida: the capture mechanism

Hook the OkHttp `Chain.proceed(request)` of the live request. When
`req.toString()` carries `x-prosopo-android-integrity-token`, emit the 4
keys.

- **Never hardcode the obfuscated chain class name.** R8 re-obfuscates it
  every release: the v3.19 chain was `ha0.i.f(mz.p2)`, and v3.20 renamed it
  out of existence — 5 straight workflow failures
  (`ClassNotFoundException: Didn't find class "ha0.i"`, runs 34910907993 →
  35332903860) until the hook was made version-agnostic. The fix boots from
  the app's own **un-obfuscated** interceptors
  (`co.twickets.droid.networking.interceptor.ApiKeyInterceptor` /
  `UseAgentInterceptor`, kept by R8 v3.19 → v3.20): hook their 1-param
  `intercept(chain)`, take the live chain object, read its runtime class
  (`chain.$className`), then hook that class's proceed-shaped methods
  (instance, 1 param, non-void) via `getDeclaredMethods`. No obfuscated
  name is ever referenced by the hook.
- The `c60.p` (v3.20) guard interceptor itself is also renamed every
  release (v3.19: `w50.i`) — grep header *literals*, not class names.
- **Use the Frida CLI, not the Python API.** `frida.bindings` / `frida` python
  raised `ReferenceError: Java is not defined` on this x86_64/NDK-translation
  device; `uv tool run --from frida-tools frida -H 127.0.0.1:27042 ...` works.
- **Attach (`-p <pid>`) after the app settles, don't spawn (`-f`).** Spawning
  at cold boot intermittently SIGSEGVs the arm64-under-translation process and
  lands on a search sub-screen. Launch normally, wait for the bottom-nav, then
  attach. Even attach can kill the app if done too early, so `03` retries the
  whole launch→settle→attach→Find cycle (up to 3 attempts).
- In **attach** mode the CLI prefixes each line with `[Remote::PID::NNNN ]-> `
  — strip everything up to `message: ` (`sed 's|.*message: ||'`), not just the
  leading `message: `.
- OkHttp `toString()` **redacts `Cookie:` to `██`** — but no cookie is needed
  for replay, so it's fine.
- The first catalogue call has only `api_key` + `User-Agent`; the JWE appears
  later. Match on *any* request bearing the token, not the catalogue URL.

### The two parser formats that bit us

The hook emitted structured dict payloads (`'User-Agent': '...'`, nested
`_url`), but the shell parser kept grepping the old `headers=[...]` text — so
it parsed nothing while the raw log had the token. The parser is now
line-based scalar regex (`x-prosopo-android-integrity-token': '([^']*)'`,
skipping empty) — never a JSON parse, because the nested-brace `_url` breaks
JSON/regex.

## Cold-boot timing is the flake

- On a fresh boot the app needs warm-up before it mints the JWE and before the
  Find tab renders. Fixed sleeps (8s) fail. `03` **launches → waits for the
  bottom-nav → settles → attaches frida → opens Find**, then **polls** the raw
  Frida output until a non-empty token appears (tapping "Try again" to keep
  requests firing). The whole cycle retries up to 3 times because the attached
  app can crash at a cold boot under NDK translation.
- `03-open-twickets.sh` must not abort the chain (first-boot runs scripts under
  `set -e`, so a failing script stops before `touch /data/.first-boot-done`);
  `04` is the real gate for `keys.json`.
- **A token in a request is NOT success.** When the keybox/IP is flagged the
  app still sends its stored JWE — a token appears in the hook output while
  the server 403s every request. That's how a blocked run used to go green
  and publish dead keys. Since 2026-09-19 `03` also requires the Find
  stream to actually render (no "Something went wrong" screen); on failure
  it writes `/data/output/render-failed.txt` and `04` refuses to publish
  keys.json (CI fails fast on the marker too). A "token seen but stream
  rejected" failure is the signature of a server-side IP/keybox block —
  do not retry or re-extract; wait it out or change IP/keybox.

## Environment quirks (this host)

- Host `adb connect localhost:15555` is **UNAUTHORIZED** (`ro.adb.secure=1`).
  Always use the container's `/opt/android-sdk/platform-tools/adb -s
  emulator-5554`.
- App is arm64 running via NDK translation on the x86_64 core — hook at the
  ART/JVM layer (Frida), not native, to work under translation.
- `frida-server` must be baked into the image (`/opt/tools/frida-server`),
  else it doesn't survive a clean boot. The Dockerfile downloads it at build
  time (official GitHub release, `ARG FRIDA_VERSION`, `.xz` needs `xz-utils`
  which the base image lacks). Version must match the runtime frida client.
- The **anonymous** auroraoss.com dispenser is **rate-limited** (Google `1015`)
  and **permanently 403s GitHub Actions runner IPs** (datacenter addresses are
  blocked). For CI, use the **official gplaydl dispenser**
  (`dispenser.gplaydl.com`) with a per-machine API key. Get one via
  `uv tool run gplaydl link` (one-time pairing code from the gplaydl
  Authenticator app), which writes `~/.config/gplaydl/config.json`. Supply the
  **entire config file** as the `GPLAYDL_CONFIG` secret/env var; `01` writes it
  verbatim (cat heredoc) to `/root/.config/gplaydl/config.json` for gplaydl to
  read natively. Dispenser can still rate-limit transiently → 5×60s retry.

## Commands

```sh
adb -s emulator-5554 shell am force-stop co.twickets.droid
uv tool run --from frida-tools frida -H 127.0.0.1:27042 -p <pid> -l /opt/scripts/capture-keys.js   # attach, never spawn
adb -s emulator-5554 shell input tap 403 2274   # Find tab
python3 -c 'import json,urllib.request; ...'    # replay with /data/output/keys.json
```

## Artifacts

- `scripts/capture-keys.js` — Frida hook (emit the 4 keys).
- `scripts/02-start-frida.sh` — ensure frida-server is running, forward port.
- `scripts/03-open-twickets.sh` — launch app, settle, attach frida, drive Find + verify.
- `scripts/04-extract-attest.sh` — best-effort attest signing key → `attest.json`
  (runs `extract-attest-key.py`; failure is non-fatal).
- `scripts/05-extract-keys.sh` — extract the 4 keys + fold in `attest.json`,
  write `/data/output/keys.json` (the final gate).
- `scripts/01-install-twickets.sh` — gplaydl install + reboot (licensing
  bypass).
- `frida-server` — downloaded at build time to `/opt/tools/frida-server` (not
  committed).
- `/data/output/keys.json` — all keys for the boot it was captured on.

## FAQ

**Why does `/data/output/keys.json` have an empty token on the first boot?** Cold-boot
race — the JWE isn't minted yet. `03-open-twickets.sh` launches the app,
settles it, attaches frida, and re-taps until the token mints; `05-extract-keys.sh`
extracts it once present.

**Do I need the Cookie header?** No. Through v3.19 the 4 keys alone replayed
the catalogue endpoint with HTTP 200 (no cookie needed). Under v3.20 the
signature gate blocks replay from outside the app entirely (cookie or not,
see the v3.20 section); on-device the app itself works once TrickyStore
targets it.

**Why is the token empty sometimes in the raw log?** The first request(s)
carry `x-prosopo-android-integrity-token: ''`. The parser skips empty values
and keeps only lines with a real token.

## Base image: ModemSimulator and the app crash (RESOLVED)

Two earlier cold-boot instabilities — a **Radio HAL SIGABRT crash-loop**
(`android.hardware.radio-service.ranchu` / `AtChannel::requestLoop`, signal 6)
and the **Twickets app dying as fg TOP** — were investigated and are now
**resolved**:

- Commit `3faa358` added `-feature -ModemSimulator`, but commit **`21da964`
  reverted it**: *"stop disabling ModemSimulator (caused radio HAL crash-loop).
  `-feature -ModemSimulator` killed the host modem but the guest
  `android.hardware.radio-service.ranchu` still spawned and SIGABRTed every
  ~5s with no peer."* So disabling the modem **caused** the crash, and the
  published image correctly ships ModemSimulator **on** (plain defaults). A
  fresh boot on the current base shows **no** radio crash-loop and the app
  **survives** cold boot.
2. The residual flake is attaching frida too early at cold boot killing the
  app under NDK translation. `03` handles it by settling before attach and
  retrying the whole cycle.

Also recurring at cold boot: a **System-UI ANR dialog** ("System UI isn't
responding"). Dismiss it by tapping the **"Wait"** button (~540,1363), not by
a blind tap. The extension's `03` handles this.

The clean-boot capture is now **reliable end-to-end**: a fresh `/data` boot
produces `/data/output/keys.json` with all 4 keys.
