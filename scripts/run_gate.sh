#!/usr/bin/env bash
#
# Local simulation of the CI deployment gate (the same logic as
# .github/workflows/security-scan-reusable.yml) run against the locally
# running scanner container. A GitHub-hosted runner cannot reach a localhost
# scanner, so this is how you demo the gate end-to-end on a personal repo
# without a public tunnel.
#
# Usage:
#   REPO_URL=https://github.com/Phrase-Sandbox/davidayo-sec-scan-test ./scripts/run_gate.sh [ref]
#
# Env:
#   SCANNER_URL        default http://localhost:8000
#   PHRASE_SCAN_TOKEN  default local-test-token
#   REPO_URL           required — the repo to gate (must be installed on the GitHub App)
#   ACTOR              default local-dev
#
# Exit code: 0 = allowed to proceed, 1 = BLOCKED (mirrors CI job failure).

set -euo pipefail

SCANNER_URL="${SCANNER_URL:-http://localhost:8000}"
TOKEN="${PHRASE_SCAN_TOKEN:-local-test-token}"
REPO_URL="${REPO_URL:?set REPO_URL=https://github.com/owner/repo}"
REF="${1:-${REF:-master}}"
ACTOR="${ACTOR:-local-dev}"

echo "==> POST ${SCANNER_URL}/agent/scan  repo=${REPO_URL} ref=${REF}"
resp="$(curl -sS --max-time 600 -X POST "${SCANNER_URL}/agent/scan" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"repo_url\":\"${REPO_URL}\",\"scan_target\":\"full_repo\",\"triggered_by\":\"${ACTOR}\",\"ref\":\"${REF}\"}")"

echo "${resp}" > /tmp/gate_scan.json

read -r decision crit high <<EOF
$(python3 - "$resp" <<'PY'
import json, sys
b = json.loads(sys.argv[1])
f = b.get("findings", [])
c = sum(1 for x in f if x["severity"] == "Critical")
h = sum(1 for x in f if x["severity"] == "High")
print(b.get("gate_decision", "scan_failed"), c, h)
PY
)
EOF

echo "==> Gate decision: ${decision} (${crit} Critical, ${high} High)"
case "${decision}" in
  blocked)
    echo "Security scan failed: ${crit} Critical, ${high} High findings. Deployment BLOCKED."
    exit 1 ;;
  bypassed)
    echo "Deployment gate bypassed — proceeding." ;;
  scan_failed|advisory)
    echo "Non-blocking (${decision}) — deployment allowed to proceed; review manually." ;;
  pass)
    echo "Security scan passed — proceeding to next CI/CD stage." ;;
  *)
    echo "Unknown decision '${decision}' — treating as non-blocking." ;;
esac
