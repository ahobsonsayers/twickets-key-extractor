#!/usr/bin/env bash
# Extract the v3.20 attestation signing key (best effort — failure here must
# not stop the pipeline; 05 still publishes the 4 catalogue keys).
set -euo pipefail
# shellcheck source=scripts/common.sh
source /opt/scripts/common.sh

if python3 /opt/scripts/extract-attest-key.py; then
  log "Attest key extracted"
else
  log "WARN: attest key extraction failed — continuing without it"
  rm -f /data/output/attest.json
fi
