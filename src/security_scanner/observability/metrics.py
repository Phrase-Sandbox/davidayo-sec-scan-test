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


def metrics_endpoint() -> Response:
    """Render the current metrics registry as Prometheus text format."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
