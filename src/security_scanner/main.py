"""FastAPI application entry point.

Mounts the agent and skill routers, exposes the mandatory K8s health probes
(spec §11), the Prometheus ``/metrics`` endpoint (§12 institutional
knowledge), and validates configuration at startup so a misconfigured
deploy fails fast rather than serving 500s.

Graceful shutdown is handled by Uvicorn: on SIGTERM it stops accepting new
connections and waits for in-flight requests to drain (CLAUDE.md
"Disposability"). The Helm chart sets ``terminationGracePeriodSeconds`` so
this drain has time to complete.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response, status

from security_scanner.agent.api import router as agent_router
from security_scanner.agent.local_scan import router as local_scan_router
from security_scanner.observability.metrics import metrics_endpoint
from security_scanner.shared.config import get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.skill.api import router as skill_api_router
from security_scanner.skill.oauth import router as skill_oauth_router

log = get_logger(__name__)

VERSION = "0.1.0"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Validate config on startup; emit a single structured start/stop pair.

    Uvicorn handles SIGTERM by stopping the accept loop and awaiting the
    lifespan ``yield`` to return — that gives in-flight requests time to
    finish before the process exits.
    """
    try:
        settings = get_settings()
    except Exception as exc:  # noqa: BLE001 — broad on purpose, we exit
        log.error(
            "startup failed: invalid configuration",
            error=type(exc).__name__,
        )
        sys.exit(1)

    if _local_test_mode_enabled():
        log.warning(
            "LOCAL_TEST_MODE is ENABLED — /agent/test-scan endpoint mounted. "
            "This bypasses GitHub fetching with caller-supplied files and "
            "MUST NEVER be enabled in production.",
        )

    log.info(
        "service starting",
        version=VERSION,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL,
        local_test_mode=_local_test_mode_enabled(),
    )
    yield
    log.info("service shutting down", version=VERSION)


def _local_test_mode_enabled() -> bool:
    return os.getenv("LOCAL_TEST_MODE", "").lower() == "true"


app = FastAPI(
    title="Phrase Security Vulnerability Scanner",
    version=VERSION,
    lifespan=lifespan,
)


# --- Health probes (§11 MANDATORY) ----------------------------------------


@app.get("/healthz", tags=["health"])
async def healthz() -> dict[str, str]:
    """Liveness probe — returns 200 as long as the process is up."""
    return {"status": "ok"}


@app.get("/readyz", tags=["health"])
async def readyz(response: Response) -> dict[str, str]:
    """Readiness probe — 503 if required config is missing or invalid."""
    try:
        settings = get_settings()
    except Exception as exc:  # noqa: BLE001 — readiness must not raise
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not ready",
            "reason": f"config error: {type(exc).__name__}",
        }

    missing: list[str] = []
    if not settings.ANTHROPIC_API_KEY:
        missing.append("ANTHROPIC_API_KEY")
    if not settings.GITHUB_APP_ID:
        missing.append("GITHUB_APP_ID")
    if missing:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "not ready",
            "reason": f"missing required config: {', '.join(missing)}",
        }

    return {"status": "ready"}


# --- Observability --------------------------------------------------------


@app.get("/metrics", tags=["observability"])
async def metrics() -> Response:
    return metrics_endpoint()


# --- Routers --------------------------------------------------------------

app.include_router(agent_router)
app.include_router(skill_api_router)
app.include_router(skill_oauth_router)
# Local-advisory jurisdiction (Appendix D-12). Always mounted but
# self-disabling: every call 401s unless LOCAL_SCAN_TOKEN is configured, and
# it can never gate a deploy or open a PR (separate token, no gate_decision).
app.include_router(local_scan_router)

# LOCAL_TEST_MODE: conditional, non-production-only test endpoint that
# bypasses GitHub fetch with caller-supplied files. The env var is
# evaluated once at import time so the test surface is fully absent from
# production deploys.
if _local_test_mode_enabled():
    from security_scanner.agent.test_endpoint import router as test_router  # noqa: PLC0415
    app.include_router(test_router)
