# twickets-key-extractor

[![Key Extraction](https://github.com/ahobsonsayers/twickets-key-extractor/actions/workflows/extract-keys.yaml/badge.svg)](https://github.com/ahobsonsayers/twickets-key-extractor/actions/workflows/extract-keys.yaml)
[![Artisan README - Not LLM](https://img.shields.io/static/v1?label=Artisan+README&message=Not+LLM&labelColor=37474F&color=EF6C00)](https://github.com/ahobsonsayers/twickets-key-extractor#arnl--artisan-readme-not-llm)

![banner](assets/banner.webp)

A docker image, which on run, extracts API keys (which constantly change) and other details required to allow users to call the Twickets API used by the android app directly.

It does this by running a rooted Android emulator in docker (using [androotu](https://github.com/ahobsonsayers/androotu)), launching Twickets and capturing & inspecting requests the app makes. See [how it works](#how-it-works) section for more info.

Leveraging [androotu](https://github.com/ahobsonsayers/androotu) allows us to work around all the protections put in place by Twickets to prevent this - but is now possible using magic ✨

### Why

Twickets recently introduced Prosopo bot protection to their site which makes it near impossible to now scrape or use APIs the website itself uses without being a human.

The Android app also has these anti-bot protections but via a different method - utilising Play Integrity rather than bot challenges.

By using a rooted emulator which passes Play Integrity, we can therefore extract the keys the app uses and therefore allow us to use the API the app uses.

### Running

By default, this image when run, will simply boot, extract the API keys the app uses to a json file and exit. 

A run can take a while ~10 mins on GitHub actions (see [FAQ](#faq) for why).

Sadly these API keys are short lived, and are minted regularly by the app. However if the extraction is run on a regular basis to obtain new keys, you can access the API without interruption.

## Setup

Before you can run this project, you will first need to set up gplaydl so that the Twickets app can be downloaded on start.

This is a one-time setup and is easy to do - but you will need an Android device. 

Follow instructions at gplaydl here:
https://github.com/rehmatworks/gplaydl

After running gplaydl and completing the process copy the contents of `~/.config/gplaydl/config.json` into the `GPLAYDL_CONFIG` environment variable in your .env (see [.env.example](.env.example)), docker run or GitHub workflow.

Get the contents with:

```bash
cat ~/.config/gplaydl/config.json
```

It will look like:

```json
{
    "dispenser": "https://dispenser.gplaydl.com",
    "api_key": "your-key-here"
}
```


# Running (GitHub Actions - Recommended)

The repo ships an [`extract-keys.yaml`](.github/workflows/extract-keys.yaml) workflow that runs daily at 06:00 UTC.

This workflow pulls the prebuilt image, boots the emulator, and extracts the keys and pushes them to a gist for use (if set up).

To run this yourself:

1. Fork the repo
2. Delete the [`docker-build-push.yaml`](.github/workflows/docker-build-push.yaml) workflow
3. Add the **`GPLAYDL_CONFIG`** repository secret (see below).
4. (Optional) Add **`GIST_ID`** repository variable and a **`GIST_TOKEN`** secret.
	The workflow will work without these, it just will not update a gist.
5. Trigger the workflow manually or wait for the next daily run.

## Running (Locally)

To run this project locally you will need
- Docker
- KVM installed (and a Linux machine with
`/dev/kvm` exposed)
- [Task](https://taskfile.dev)

First copy the .env.example to .env

```sh
cp .env.example .env
```

Then set GPLAYDL_CONFIG in the .env to the full config JSON

Then run the container (runs can take a bit of time)

```bash
task run
```

Or

```bash
docker compose up 
```

Keys land in `./output/keys.json`. 

Remember: as the JWE is short lived, you will need to run this on a regular, scheduled basis to get new keys to use.

**Other useful tasks:**

```sh
task logs        # see container logs
task adb         # connect to emulator using adb
task screenshot # capture a screenshot of the emulator
```


## The keys

Each run writes `output/keys.json` with exactly the fields below. These should be set on any request to the API (as a query param or header).

| key | set in | kind |
|---|---|---|
| `api_key` | query param | static |
| `User-Agent` | header | static |
| `x-prosopo-site-key` | header | static |
| `x-prosopo-android-integrity-token` | header | dynamic JWE, minted per launch |

You can use these against the catalogue endpoint for example, no cookie needed:

```sh
curl 'https://www.twickets.live/services/catalogue?count=10&q=countryCode%3DGB&api_key=<key>' \
  -H 'User-Agent: <user agent>' \
  -H 'x-prosopo-site-key: <key>' \
  -H 'x-prosopo-android-integrity-token: <token>'
```

## How it works

1. Boots `ghcr.io/ahobsonsayers/androotu`, a rooted Android 16 emulator with modules installed
   (Integrity Box, KSU-Next, SUSFS, ReZygisk, TEESimulator,
   **BetterKnownInstalled**) that make the emulator pass Play Integrity, and make apps appear as if installed from the Play Store.
2. `01-install-twickets.sh` downloads Twickets (`co.twickets.droid`) from Google
   Play via **gplaydl**, installs it, then reboots so the **BetterKnownInstalled** module re-marks it
   as a Play Store install - bypassing the app's Play Automatic Integrity
   Protection.
3. `02-start-frida.sh` ensures frida-server is running and forwards its port.
4. `03-open-twickets.sh` launches the app, waits for the bottom-nav to appear,
   attaches **Frida**, opens the Find tab, and retries the page until the Prosopo
   integrity JWE is minted. Retries the whole cycle up to 3 times.
5. `04-extract-keys.sh` parses the Frida output and writes the 4 keys to
   `/data/output/keys.json`. Fails if any key is missing.

The Frida hook (`scripts/capture-keys.js`) intercepts requests and emits the keys once a request carries the
JWE - which is what we use as the signal that all 4 keys are available.


## FAQ

**Why does the run sometimes take a while to start?**
On a fresh boot the app needs to "warm up" before the JWE mints and before the Find
tab works. The JWE is NOT present on the very first request after launch.

The scripts try the 
launch→attach→capture cycle up to 3 times to handle this.

**Can I run this on macOS / Windows?**
The container needs `/dev/kvm` (Linux KVM), so a Linux machine is required for
local runs. Use the provided GitHub Actions if you do not have a Linux machine accessible.

### AR;NL - Artisan Readme; Not LLM

In the age of LLMs and coding agents, code is now cheap - for better or for worse. Your time however, is not ⌛

Therefore this project, like most of my projects, uses a hand written "artisan" README to ensure it is clear, correct and concise. This makes it easy to read and in my opinion encourages reading and engagement - no one likes AI slop!

As someone wiser than me once told a colleague:

"if you can't be bothered to take the time to write these words, then why should I be bothered to read them"

Enjoy!
