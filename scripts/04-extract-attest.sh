#!/usr/bin/env bash
# Extract the v3.20 attestation signing key (best effort — failure here must
# not stop the pipeline; 05 still publishes the 4 catalogue keys).
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

# -u: unbuffered — early prints survive even if python is killed later.
# Output is captured so CI can see WHY extraction failed (frida deaths were
# invisible before).
LOG=/data/output/attest-extract.log
if timeout 300 python3 -u /opt/scripts/extract-attest-key.py 2>&1 | tee "$LOG"; then
  log "Attest key extracted"
else
  log "WARN: attest key extraction failed — full log below"
  cat "$LOG"
  rm -f /data/output/attest.json
fi
