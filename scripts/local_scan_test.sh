#!/usr/bin/env bash
#
# End-to-end local scan test. Brings up the test profile of docker-compose
# (LOCAL_TEST_MODE=true), posts a scan request to /agent/test-scan with a
# pre-seeded SQL-injection + hardcoded-API-key fixture, and asserts the
# pipeline produces the expected gate decision and findings.
#
# This makes a REAL Claude API call — set ANTHROPIC_API_KEY to a live key.
#
# Usage:
#   ANTHROPIC_API_KEY=sk-ant-... ./scripts/local_scan_test.sh
#
# Optional env overrides:
#   BASE_URL                 — default http://localhost:8001
#   PHRASE_SCAN_TOKEN        — default local-test-token (matches docker-compose default)
#   KEEP_RUNNING=1           — don't tear down the docker compose stack on exit
#   SKIP_COMPOSE=1           — assume service already running; don't start/stop docker

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
cd "${PROJECT_ROOT}"

# Auto-load .env.local so users can keep ANTHROPIC_API_KEY (and other
# overrides) in a single gitignored file rather than exporting on each run.
#
# We parse the file line-by-line instead of `source`-ing it. That way values
# containing characters bash treats specially (``<``, ``>``, ``$``, ``&``,
# unmatched quotes, etc.) don't break the script. Format: KEY=VALUE, one per
# line; lines starting with `#` and blank lines are skipped; surrounding
# single or double quotes are stripped.
if [[ -f "${PROJECT_ROOT}/.env.local" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// /}" ]] && continue
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
      if [[ "$value" =~ ^\"(.*)\"$ ]]; then
        value="${BASH_REMATCH[1]}"
      elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
        value="${BASH_REMATCH[1]}"
      fi
      export "$key=$value"
    fi
  done < "${PROJECT_ROOT}/.env.local"
fi

BASE_URL="${BASE_URL:-http://localhost:8001}"
TOKEN="${PHRASE_SCAN_TOKEN:-local-test-token}"
# Must be a valid-shaped Anthropic key for the BR-003 stripper to detect it:
# regex requires ≥20 chars after `sk-ant-`. (Obviously-fake test value.)
RAW_SECRET="sk-ant-api03-realistically-long-key-that-looks-genuine-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"

if [[ -z "${ANTHROPIC_API_KEY:-}" || "${ANTHROPIC_API_KEY}" == "test-key-placeholder" || "${ANTHROPIC_API_KEY}" == "sk-ant-..." ]]; then
  cat >&2 <<EOF
FAIL: ANTHROPIC_API_KEY is not set to a real value.

       This test makes a live Claude API call. To set the key:

         1. cp .env.local.example .env.local         # one-time
         2. Edit .env.local and replace 'sk-ant-...' with your real key
         3. Re-run this script

       The .env.local file is gitignored — it stays on this machine.
EOF
  exit 1
fi

cleanup() {
  if [[ "${SKIP_COMPOSE:-0}" == "1" ]]; then
    return
  fi
  if [[ "${KEEP_RUNNING:-0}" == "1" ]]; then
    echo ""
    echo "(KEEP_RUNNING=1 — leaving stack up. Tear down with:"
    echo "   docker compose --profile test down --remove-orphans)"
    return
  fi
  echo ""
  echo "==> Tearing down docker compose test profile..."
  docker compose --profile test down --remove-orphans 2>&1 | tail -3 || true
}
trap cleanup EXIT

# --- 1. Start service ---

if [[ "${SKIP_COMPOSE:-0}" != "1" ]]; then
  echo "==> Starting security-scanner-test (LOCAL_TEST_MODE=true)..."
  docker compose --profile test up -d --build security-scanner-test 2>&1 | tail -5
fi

# --- 2. Wait for /healthz ---

echo "==> Waiting up to 60s for ${BASE_URL}/healthz..."
for i in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    echo "  PASS: service is up"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "  FAIL: service did not become healthy" >&2
    docker compose --profile test logs security-scanner-test 2>&1 | tail -20
    exit 1
  fi
  sleep 2
done

# --- 3. Verify /agent/test-scan is mounted ---

echo "==> Verifying /agent/test-scan is mounted..."
preflight=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/agent/test-scan")
if [[ "${preflight}" == "404" ]]; then
  echo "  FAIL: /agent/test-scan returned 404 — LOCAL_TEST_MODE not active?" >&2
  exit 1
fi
echo "  PASS: route exists (HTTP ${preflight} on empty body)"

# --- 4. POST the test scan ---

echo "==> POSTing /agent/test-scan with SQL-injection + hardcoded-key fixtures..."
read -r -d '' BODY <<JSON || true
{
  "repo_url": "https://github.com/Phrase-Launchpad/local-test",
  "scan_target": "full_repo",
  "triggered_by": "local-smoke-test",
  "mock_files": {
    "src/handlers/query.py": "import sqlite3\n\ndef get_user(username):\n    conn = sqlite3.connect('app.db')\n    cur = conn.cursor()\n    query = f\"SELECT id, email FROM users WHERE name = '{username}'\"\n    cur.execute(query)\n    return cur.fetchone()\n",
    "config/settings.py": "ANTHROPIC_API_KEY = \"${RAW_SECRET}\"\nLOG_LEVEL = \"DEBUG\"\n"
  }
}
JSON

HTTP=$(curl -s -o /tmp/scan_response.json -w '%{http_code}' \
  -X POST "${BASE_URL}/agent/test-scan" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "${BODY}")

if [[ "${HTTP}" != "200" ]]; then
  echo "  FAIL: expected 200, got ${HTTP}" >&2
  echo "  Response body:" >&2
  cat /tmp/scan_response.json >&2 || true
  exit 1
fi
echo "  PASS: HTTP 200"

# --- 5. Assert on the response body ---

echo "==> Asserting on response body..."
PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

"${PYTHON_BIN}" - <<PY
import json
import sys

RAW_SECRET = "${RAW_SECRET}"

with open("/tmp/scan_response.json") as f:
    body = json.load(f)

errors = []
gate = body.get("gate_decision")
findings = body.get("findings", [])
vuln_ids = [f["vulnerability_id"] for f in findings]

if gate != "blocked":
    errors.append(f"gate_decision: expected 'blocked', got {gate!r}")

if "SECRET-001" not in vuln_ids:
    errors.append(f"SECRET-001 missing from findings — got {vuln_ids}")

# No raw secret should appear anywhere in the response JSON.
if RAW_SECRET in json.dumps(body):
    errors.append(f"raw secret '{RAW_SECRET}' leaked into response body")

if errors:
    print("ASSERTIONS FAILED:")
    for err in errors:
        print(f"  [FAIL] {err}")
    sys.exit(1)

print(f"  PASS: gate_decision == 'blocked'")
print(f"  PASS: SECRET-001 present ({len(findings)} findings total)")
print(f"  PASS: raw secret value does NOT appear in response body")
print()
print("=== FINDINGS ===")
for f in findings:
    lines = f.get("affected_lines") or "—"
    print(
        f"  - {f['vulnerability_id']:<14} "
        f"sev={f['severity']:<8} conf={f['confidence']:<6} "
        f"verif={f['verification_status']:<12} "
        f"{f['affected_file']}:{lines}"
    )

# Render the Markdown report (using the local venv if available).
try:
    from security_scanner.shared.models.scan_result import ScanResult
    from security_scanner.shared.reports.markdown import build_markdown_report
    result = ScanResult.model_validate(body)
    print()
    print("=== REPORT MARKDOWN ===")
    print(build_markdown_report(result))
except ImportError:
    print()
    print("(Markdown rendering skipped — venv not detected)")
PY

echo ""
echo "All local scan tests passed."
