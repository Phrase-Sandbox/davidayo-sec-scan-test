#!/usr/bin/env bash
#
# Local smoke test for the running service. Polls /healthz, then asserts
# /readyz and /metrics return what we expect.
#
# Usage:
#   docker compose --env-file .env.local up -d --build
#   ./scripts/smoke_test.sh
#   docker compose down
#
# Override the base URL with BASE_URL=http://… if running elsewhere.

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
HEALTHZ_TIMEOUT_SECONDS="${HEALTHZ_TIMEOUT_SECONDS:-30}"
POLL_INTERVAL_SECONDS=2

# --- 1. Wait for /healthz to return 200 (poll up to HEALTHZ_TIMEOUT_SECONDS) ---

echo "==> Waiting up to ${HEALTHZ_TIMEOUT_SECONDS}s for ${BASE_URL}/healthz..."
deadline=$(($(date +%s) + HEALTHZ_TIMEOUT_SECONDS))
healthy=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  status=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/healthz" || echo "000")
  if [ "$status" = "200" ]; then
    healthy=1
    break
  fi
  printf "  ...status=%s, retrying in %ss\n" "$status" "$POLL_INTERVAL_SECONDS"
  sleep "$POLL_INTERVAL_SECONDS"
done

if [ "$healthy" -ne 1 ]; then
  echo "FAIL: /healthz did not return 200 within ${HEALTHZ_TIMEOUT_SECONDS}s" >&2
  exit 1
fi
echo "  PASS: /healthz returned 200"

# --- 2. /readyz must return 200 ---

echo "==> Checking ${BASE_URL}/readyz..."
readyz_status=$(curl -s -o /tmp/readyz.body -w '%{http_code}' "${BASE_URL}/readyz")
if [ "$readyz_status" != "200" ]; then
  echo "FAIL: /readyz returned ${readyz_status}" >&2
  echo "  body: $(cat /tmp/readyz.body)" >&2
  exit 1
fi
echo "  PASS: /readyz returned 200 — body: $(cat /tmp/readyz.body)"

# --- 3. /metrics must contain our application's metric names ---

echo "==> Checking ${BASE_URL}/metrics for application metrics..."
metrics_body=$(curl -fsS "${BASE_URL}/metrics")
expected_metrics=(
  scan_requests_total
  scan_duration_seconds
  claude_api_calls_total
  github_api_calls_total
  secrets_found_total
  findings_total
)
missing=()
for metric in "${expected_metrics[@]}"; do
  if ! grep -q "^# HELP ${metric}" <<<"$metrics_body"; then
    missing+=("$metric")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo "FAIL: /metrics is missing application metrics: ${missing[*]}" >&2
  exit 1
fi
echo "  PASS: /metrics contains all ${#expected_metrics[@]} expected metrics"

echo ""
echo "All smoke tests passed."
