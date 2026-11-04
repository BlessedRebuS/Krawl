#!/bin/bash
# Imports Krawl's attacker list into CrowdSec as ban decisions.
# CrowdSec owns enforcement, so Krawl only supplies the decisions and a duration.

# Configuration
KRAWL_URL="https://your-krawl-instance/your-dashboard-path"
CATEGORIES="attacker"
# Optional: also export IPs pulled from the configured upstream banlists
MERGE_BANLISTS="false"

OUT="$(mktemp /tmp/krawl_crowdsec.XXXXXX.json)"
trap 'rm -f "${OUT}"' EXIT

# Fetch CrowdSec decisions from the Krawl export API
curl -fsS "${KRAWL_URL}/api/export-ips?categories=${CATEGORIES}&fwtype=crowdsec&merge_banlists=${MERGE_BANLISTS}" -o "${OUT}"

if [ ! -s "${OUT}" ]; then
  echo "Error: Krawl returned nothing to import"
  exit 1
fi

# Import them. Decisions already present are skipped by CrowdSec.
if ! cscli decisions import -i "${OUT}" --format json; then
  echo "Error: cscli decisions import failed"
  exit 1
fi

echo "Krawl decisions imported into CrowdSec"
