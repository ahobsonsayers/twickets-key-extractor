# twickets-key-extractor

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Run workflow](https://github.com/ahobsonsayers/twickets-key-extractor/actions/workflows/run.yml/badge.svg)](https://github.com/ahobsonsayers/twickets-key-extractor/actions/workflows/run.yml)

> [!TIP]
> **tl;dr** — Fork the repo, add one secret (`GPLAYDL_CONFIG`), enable the
> scheduled Action. A rooted Android 16 emulator boots in CI, installs
> Twickets, and captures the 4 API keys its catalogue endpoint requires —
> including the dynamic Prosopo integrity JWE. Fresh keys land in a gist
> every day. No build step on your side; the image is already published.

Twickets secures its catalogue endpoint with a Prosopo integrity JWE that's
minted inside the app at runtime — you can't replay the request without it.
This project extracts that token (and the 3 static keys) by driving the real
app inside a rooted emulator with Frida, so the integrity flow runs exactly as
it does on a phone. A GitHub Action runs it on a schedule and publishes the
latest keys to a gist.

The image is published at
`ghcr.io/ahobsonsayers/twickets-key-extractor:latest` — you run it, you don't
build it. Fork the repo, add one secret, and the included Action keeps a gist
updated with fresh keys every day.

## The 4 keys

Each run writes `output/keys.json` with exactly these fields:

| key | kind |
|---|---|
| `api_key` | static (query param) |
| `User-Agent` | static (header) |
| `x-prosopo-site-key` | static (header) |
| `x-prosopo-android-integrity-token` | dynamic JWE, minted per launch (header) |

Replay them against the catalogue endpoint (no cookie needed):

```sh
curl 'https://www.twickets.live/services/catalogue?count=10&q=countryCode%3DGB&api_key=<KEY>' \
  -H 'User-Agent: Twickets/3.19 (Android/16)' \
  -H 'x-prosopo-site-key: 5EZVvsHMrKCFKp5NYNoTyDjTjetoVo1Z4UNNbTwJf1GfN6Xm' \
  -H 'x-prosopo-android-integrity-token: <JWE>'
```

## How it works

1. Boots `ghcr.io/ahobsonsayers/androotu` — a rooted Android 16 AVD whose
   modules (Integrity Box, KSU-Next, SUSFS, ReZygisk, TEESimulator,
   **BetterKnownInstalled**) make Play-installed apps pass integrity checks.
2. `01-install-twickets.sh` installs Twickets (`co.twickets.droid`) from Google
   Play via **gplaydl**, then reboots so **BetterKnownInstalled** re-marks it
   as a Play Store install — bypassing the app's Play Automatic Integrity
   Protection, which would otherwise `System.exit(0)` on an unlicensed device.
3. `02-start-frida.sh` ensures frida-server is running and forwards its port.
4. `03-open-twickets.sh` launches the app, waits for the bottom-nav to settle,
   attaches **Frida** (attach, not spawn — spawn SIGSEGVs under NDK
   translation), opens the Find tab, and drives requests until the Prosopo
   integrity JWE mints. Retries the whole cycle up to 3 times.
5. `04-extract-keys.sh` parses the Frida output and writes the 4 keys to
   `/data/output/keys.json`. Fails if any key is missing.

The Frida hook (`scripts/capture-keys.js`) intercepts OkHttp's
`Chain.proceed(request)` and emits the keys the moment a request carries the
integrity token — the signal that all 4 are ready.

## Run it (GitHub Actions, scheduled)

The repo ships a `run` workflow (`.github/workflows/run.yml`) that runs daily
at 06:00 UTC. It pulls the prebuilt image, boots the emulator on a
`ubuntu-latest` runner with KVM, and waits for `keys.json` to appear.

To set it up in a fork:

1. **Fork the repo.**
2. Update the image reference in `.github/workflows/run.yml` to point at your
   own GHCR namespace (the default is hard-coded to
   `ghcr.io/ahobsonsayers/twickets-key-extractor:latest`). The `build`
   workflow pushes to `ghcr.io/<owner>/twickets-key-extractor:latest` — trigger
   it once from the Actions tab to populate your namespace, then point `run`
   at it.
3. Add the **`GPLAYDL_CONFIG`** repository secret (see below).
4. (Optional) To publish keys to a gist: add a **`GIST_TOKEN`** secret and a
   **`GIST_ID`** repository variable. Without them the run still works — it
   just skips the gist step.

Trigger the workflow manually from the **Actions** tab to verify, or wait for
the next 06:00 UTC run.

## Run it (local)

Requires Docker, KVM, and [Task](https://taskfile.dev). Linux host with
`/dev/kvm` exposed.

```sh
cp .env.example .env   # then set GPLAYDL_CONFIG to the full config JSON in .env
task run               # boots the emulator and captures keys
```

Keys land in `output/keys.json`. Useful follow-ups:

```sh
task logs   # follow the container logs (watch for "Wrote /data/output/keys.json")
task shot   # capture a screenshot of the emulator to shot.png
task adb    # connect adb using the image's baked key
```

## Getting a gplaydl API key

> [!NOTE]
> This is the only secret you need. The whole setup takes ~2 minutes and
> costs nothing.

The run downloads the Twickets APK from gplaydl's official dispenser
(`dispenser.gplaydl.com`), which requires a per-machine **API key**. gplaydl
stores it (plus the dispenser URL) in `~/.config/gplaydl/config.json`. The
image writes the full config JSON — provided via the `GPLAYDL_CONFIG`
secret/env var — to that path so the tool authenticates natively.

1. Install the **gplaydl Authenticator** app on any Android phone from
   `https://dispenser.gplaydl.com`.
2. Sign in with a **spare Google account** — not your main one. Google may
   flag accounts used with unofficial clients, so use a throwaway.
3. Open **"Link gplaydl"** in the app and note the **one-time pairing code**
   (single-use, expires after ~10 minutes).
4. On any machine with [`uv`](https://docs.astral.sh/uv) installed, run it and
   paste the code:

   ```sh
   uv tool run gplaydl link
   ```

   This exchanges the code for your API key and writes
   `~/.config/gplaydl/config.json`, which looks like:

   ```json
   {
     "dispenser": "https://dispenser.gplaydl.com",
     "api_key": "your-key-here"
   }
   ```

5. Set `GPLAYDL_CONFIG` to the **full contents of that file**:
   - **GitHub Actions:** add a repository **secret** named `GPLAYDL_CONFIG`
     whose value is the whole JSON, under **Settings → Secrets and variables
     → Actions**.
   - **Local runs:** paste the JSON into `.env` as shown above; `task run`
     loads it automatically.

The key lets the dispenser issue the Google Play session token needed to
download the Twickets APK on each run.

## Notes

- The integrity token is a JWE (`{alg: A256KW, enc: A256GCM}`) minted only
  after the app warms up. It is **not** present on the very first request
  after launch — the scripts retry until it appears.
- The anonymous auroraoss.com dispenser is rate-limited and permanently 403s
  GitHub Actions runner IPs (datacenter addresses are blocked). Always use
  the official gplaydl dispenser with your own API key.
- Host `adb connect localhost:15555` is **UNAUTHORIZED** (`ro.adb.secure=1`).
  Use `task adb` (which supplies the container's baked key) or the container's
  own `adb` at `/opt/android-sdk/platform-tools/adb -s emulator-5554`.

## FAQ

**Why a whole emulator? Can't I just call the API?**
No. The Prosopo integrity token is a JWE minted inside the app at runtime
after it warms up — there's no way to request it out-of-band. You need the
real app running on a real (or emulated) Android device to trigger the
integrity flow that produces it.

**Why is the token different every run?**
It's a JWE whose contents are bound to the device state at mint time, with a
short lifetime. The other 3 keys are static, but the token must be captured
fresh.

**Why does the run sometimes take a while to start?**
On a fresh boot the app needs warm-up before the JWE mints and before the Find
tab renders. The scripts poll rather than sleep, and retry the whole
launch→attach→capture cycle up to 3 times because the attached app can crash
at cold boot under NDK translation.

**Do I need the Cookie header?**
No. The 4 keys replay the catalogue endpoint with HTTP 200 — no cookie needed.

**Can I run this on macOS / Windows?**
The container needs `/dev/kvm` (Linux KVM), so a Linux host is required for
local runs. GitHub Actions (`ubuntu-latest`) works out of the box.