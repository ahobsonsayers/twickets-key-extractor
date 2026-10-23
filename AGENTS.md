# AGENTS.md — working rules for this repo

Repo: `twickets-key-extractor` — rooted-emulator pipeline that boots an AVD,
installs Twickets, and captures the 4 catalogue API keys (see `LEARNINGS.md`
for the full picture, `README.md` for the pipeline).

Working agreements (carry over from the user's global AGENTS.md):

- **NEVER commit unless the user explicitly asks in that message.**
- Don't run the pipeline or make live requests unless the user asks.
- Root adb on the emulator: `adb shell su 0 sh -c '...'` (plain `su 0 cmd`
  returns empty output).

## NEVER probe-farm the Twickets servers

This is the most important section in this file. **Violation of any rule
below can get our IP permanently blocked.**

We learned this the hard way (2026-09-18/19): within roughly one hour of
rapid testing — ~4 quick `key_id` mints plus a stream of failed replay
probes — our NAT IP got **flagged server-side**.
Afterwards **even the app's own requests returned 403** (fresh `key_id` or
not), and the block **did not clear after 2+ idle hours**. The user had to
wait and let it expire. The key-attest endpoint kept issuing key_ids the
whole time — the block hits at *verify* time, so you won't see it at
issuance. We've repeatedly confirmed the block is **IP-level, not
keybox-level** (same keybox works from a clean IP; issuance never stops).

Rules:

1. **Never loop, retry, batch, or script requests** against
   `twickets.live` or `protect.twickets.live`. A 403 is a **STOP** signal,
   never a retry signal.
2. **Rate limit: at most ONE request to any Twickets endpoint per minute**
   (2026-10-23 user rule). The single replay test (its one key-challenge GET
   plus its one signed catalogue request) counts as one atomic unit — one
   unit per session, only with the user's explicit go-ahead.
3. **Never re-run the pipeline to "check something".** The pipeline is
   gentle by design: launch once, drive the app once, capture once,
   extract once. If it failed, diagnose offline (frida traces, logs,
   code) — not by re-launching the app repeatedly.
4. **Never run the replay example more than once per session, and never
   while flagged.** How to tell you're flagged: the **app's own** requests
   403 (check with a single passive frida trace, or just look for the
   "Something went wrong" screen). If flagged: stop everything, tell the
   user, wait.
5. **One app relaunch per session** when a relaunch is needed (re-attest,
   key extraction). Relaunching mints a fresh key_id — rapid mints are
   what triggered the original flag.
6. The **only** scheduled traffic is the existing 06:00 UTC CI cron — the
   user chose to keep it as-is. Never add another schedule, never trigger
   the workflow manually for testing without asking.
7. If a live test fails, **diagnose offline** and wait for the user.
   Offline = frida traces, raw logs, decompiled source, the twickets-
   decompile repo. Online = the thing that got us blocked.

## Running things on this machine (user-approved, HARD RULE: always `nice`)

- **Every** command executed on this host — local pipeline runs, docker
  builds/containers, emulator/AVD work, jadx/decompiler runs, any script —
  MUST be wrapped in `nice` (e.g. `nice -n 10 <command>`). The emulator is
  CPU-heavy and must never starve the host. No exceptions.
- Local diagnostic runs are allowed: `task build` then `task run` (wrapped in
  `nice`).
- **Wait at least 1 minute between tests.** One boot pipeline per test;
  never queue boots back-to-back, and never relaunch the app inside a run
  beyond what the pipeline's own bounded recovery does.

If you are ever unsure whether an action counts as probing: it does.
Don't do it.