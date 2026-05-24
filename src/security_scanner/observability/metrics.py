"""Prometheus metrics for the ``/metrics`` endpoint.

Metric names follow the Prometheus naming convention (snake_case, _total
suffix for counters, _seconds for time histograms). The actual emission is
the caller's responsibility — modules across the pipeline call
``foo.labels(...).inc()`` / ``.observe(...)`` at the right moment.
"""

from __future__ import annotations

from fastapi import Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

scan_requests_total = Counter(
    "scan_requests_total",
    "Total scan requests handled by the service.",
    ["scan_type", "gate_decision"],
)

scan_duration_seconds = Histogram(
    "scan_duration_seconds",
    "End-to-end scan request duration in seconds.",
    ["scan_type"],
)

claude_api_calls_total = Counter(
    "claude_api_calls_total",
    "Calls made to the Anthropic Claude API.",
    ["path", "outcome"],
)

github_api_calls_total = Counter(
    "github_api_calls_total",
    "Calls made to the GitHub REST API.",
    ["outcome"],
)

secrets_found_total = Counter(
    "secrets_found_total",
    "Total secrets detected and stripped from source pre-analysis.",
)

findings_total = Counter(
    "findings_total",
    "Total vulnerability findings emitted across all scans.",
    ["severity"],
)

# /scan/local token-verify outcomes. Labels are deliberately coarse so the
# cardinality stays bounded — per-user identity goes in the audit log
# (audit_events.user_email/token_id), never on a Prometheus label.
#
# Outcomes:
#   ok               — registry-mode successful auth
#   unknown_token    — token prefix not in DB (registry mode)
#   revoked          — token revoked (registry mode)
#   bad_signature    — token prefix valid but suffix doesn't match (registry mode)
#   bad_format       — header missing or malformed (registry mode)
#   legacy_ok        — legacy LOCAL_SCAN_TOKEN matched (USE_TOKEN_REGISTRY=false)
#   legacy_unauthorized — legacy single-token mismatch / unset
local_scan_auth_outcomes_total = Counter(
    "local_scan_auth_outcomes_total",
    "Outcomes of /scan/local bearer-token verification.",
    ["outcome"],
)


# ---------------------------------------------------------------------------
# Multi-scanner Layer-1 metrics.
# ---------------------------------------------------------------------------

scanner_runs_total = Counter(
    "scanner_runs_total",
    "Total scanner tool invocations.",
    ["tool", "outcome"],  # outcome: success | timeout | error | skipped
)

scanner_duration_seconds = Histogram(
    "scanner_duration_seconds",
    "Duration of individual scanner tool runs in seconds.",
    ["tool"],
)

vuln_verifier_calls_total = Counter(
    "vuln_verifier_calls_total",
    "Total calls to the production-mode vulnerability verifier.",
    ["outcome"],  # outcome: real | false_positive | unverified | error
)

consensus_findings_total = Counter(
    "consensus_findings_total",
    "Total aggregated candidates produced by the consensus step, by voter count.",
    ["voter_count"],  # voter_count: "1", "2", "3", "4+"
)


def metrics_endpoint() -> Response:
    """Render the current metrics registry as Prometheus text format."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
