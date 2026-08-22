# twickets-key-extractor

Builds a rooted Android 16 emulator image that installs Twickets, drives it to
the Find ticket stream, and captures the 4 catalogue API keys to
`/data/output/keys.json`. A GitHub Action runs it on a schedule and publishes
the latest keys to a gist.

## How it works

1. Boots `ghcr.io/ahobsonsayers/androotu` (rooted Play-Store Android 16 AVD).
2. `01-install-twickets.sh` installs Twickets (`co.twickets.droid`) from Google
   Play via **gplaydl**, then reboots so **BetterKnownInstalled** marks it a
   Play Store install (bypasses the app's licensing check).
3. `03-open-twickets.sh` launches the app, attaches **Frida**, opens the Find
   tab, and drives requests until the Prosopo integrity JWE token mints.
4. `04-extract-keys.sh` writes the 4 keys to `/data/output/keys.json`:
   - `api_key` (query param)
   - `User-Agent`
   - `x-prosopo-site-key`
   - `x-prosopo-android-integrity-token` (dynamic JWE)

## Getting a gplaydl API key

The run workflow downloads the Twickets APK from gplaydl's official dispenser
(`dispenser.gplaydl.com`). That dispenser requires a per-machine **API key**.
gplaydl stores it (plus the dispenser URL) in `~/.config/gplaydl/config.json`.
The image writes the full config JSON — provided via the `GPLAYDL_API_KEY`
secret/env var — to that path so the tool authenticates natively. Getting a
key takes about two minutes:

1. Install the **gplaydl Authenticator** app on any Android phone from
   `https://dispenser.gplaydl.com`.
2. In the app, sign in with a **spare Google account** (not your main one —
   Google may flag accounts used with unofficial clients, so use a throwaway).
3. Open **"Link gplaydl"** in the app and note the **one-time pairing code**
   (it is single-use and expires after ~10 minutes).
4. On any machine with `uv` installed, run and paste the code:

   ```sh
   uv tool run gplaydl link
   ```

   This exchanges the code for your own API key and writes
   `~/.config/gplaydl/config.json`, which looks like:

   ```json
   {"dispenser": "https://dispenser.gplaydl.com", "api_key": "your-key-here"}
   ```

5. The `GPLAYDL_API_KEY` env var (or GitHub secret) must contain **the full
   contents of that config file** — the JSON above, exactly as gplaydl wrote
   it. Paste it into:

   ```sh
   export GPLAYDL_API_KEY='{"dispenser":"https://dispenser.gplaydl.com","api_key":"your-key-here"}'
   ```

   For local runs, copy `.env.example` to `.env` and fill it in — `task run`
   loads it automatically:

   ```sh
   cp .env.example .env   # then set GPLAYDL_API_KEY to the full config JSON in .env
   ```

The key lets the dispenser issue the Google Play session token needed to
download the Twickets APK on each run.

## Local run

```sh
task build   # build the image
task run     # boot the emulator and capture keys
```

Keys land in `output/keys.json`.
