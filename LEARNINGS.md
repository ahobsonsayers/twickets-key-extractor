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
5. `04-extract-keys.sh`: extracts the 4 request keys from the hook output,
   writing `/data/output/keys.json`. Fails if any key is missing.

## The 4 catalogue keys (`/data/output/keys.json`)

| key | value | kind |
|---|---|---|
| `api_key` | `3aaf0790-5e80-4ebc-b2e3-349b35e06656` | static (query param) |
| `User-Agent` | `Twickets/3.19 (Android/16)` | static (header) |
| `x-prosopo-site-key` | `5EZVvsHMrKCFKp5NYNoTyDjTjetoVo1Z4UNNbTwJf1GfN6Xm` | static (header) |
| `x-prosopo-android-integrity-token` | dynamic JWE `eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0...` | dynamic per-launch (header) |

Replay (no cookie needed) → HTTP 200:

```sh
curl 'https://www.twickets.live/services/catalogue?count=10&q=countryCode%3DGB&api_key=<KEY>' \
  -H 'User-Agent: Twickets/3.19 (Android/16)' \
  -H 'x-prosopo-site-key: 5EZVvsHMrKCFKp5NYNoTyDjTjetoVo1Z4UNNbTwJf1GfN6Xm' \
  -H 'x-prosopo-android-integrity-token: <JWE>'
```

The "play jwe" is `x-prosopo-android-integrity-token` (JWE `{alg:A256KW,
enc:A256GCM}`). The "proposer session" is `x-prosopo-site-key`. It's minted
only after the app warms up — never present on the very first request after
launch.

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

Hook `ha0.i.f(mz.p2)` = R8-obfuscated OkHttp `Chain.proceed(finalRequest)`.
When `req.toString()` carries `x-prosopo-android-integrity-token`, emit the 4
keys.

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
uv tool run --from frida-tools frida -H 127.0.0.1:27042 -f co.twickets.droid -l /opt/scripts/capture-keys.js
adb -s emulator-5554 shell input tap 403 2274   # Find tab
python3 -c 'import json,urllib.request; ...'    # replay with /data/output/keys.json
```

## Artifacts

- `scripts/capture-keys.js` — Frida hook (emit the 4 keys).
- `scripts/02-start-frida.sh` — ensure frida-server is running, forward port.
- `scripts/03-open-twickets.sh` — launch app, settle, attach frida, drive Find + verify.
- `scripts/04-extract-keys.sh` — extract the 4 keys, write `/data/output/keys.json`.
- `scripts/01-install-twickets.sh` — gplaydl install + reboot (licensing
  bypass).
- `frida-server` — downloaded at build time to `/opt/tools/frida-server` (not
  committed).
- `/data/output/keys.json` — the 4 keys for the boot it was captured on.

## FAQ

**Why does `/data/output/keys.json` have an empty token on the first boot?** Cold-boot
race — the JWE isn't minted yet. `03-open-twickets.sh` launches the app,
settles it, attaches frida, and re-taps until the token mints; `04-extract-keys.sh`
extracts it once present.

**Do I need the Cookie header?** No. The 4 keys replay the catalogue endpoint
with HTTP 200.

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
