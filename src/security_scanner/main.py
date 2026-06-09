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

import asyncio
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from security_scanner.agent.api import router as agent_router
from security_scanner.agent.local_scan import router as local_scan_router
from security_scanner.observability.metrics import metrics_endpoint
from security_scanner.shared.config import get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.tokens.admin_panel import router as admin_router
from security_scanner.tokens.okta import router as okta_router
from security_scanner.tokens.portal import router as portal_router

log = get_logger(__name__)

VERSION = "0.1.0"


_LOCAL_DB_HINTS = ("localhost", "postgres", "127.0.0.1", "sqlite")


def _check_admin_bypass_safety(settings) -> None:
    """Production safeguard: ADMIN_LOCAL_BYPASS must never be true with a non-local DB.

    Heuristic: the DB host must contain ``localhost`` or ``postgres`` (the
    compose service name) for the bypass to be allowed. Anything else means
    we are pointing at a real deploy and the bypass would erase auth.
    """
    if not settings.ADMIN_LOCAL_BYPASS:
        return
    db_url = settings.DATABASE_URL or ""
    if not any(host in db_url for host in _LOCAL_DB_HINTS):
        log.error(
            "startup refused: ADMIN_LOCAL_BYPASS=true with non-local DATABASE_URL",
            database_url_redacted=db_url.split("@")[-1] if "@" in db_url else "(unset)",
        )
        sys.exit(1)


def _check_local_password_safety(settings) -> None:
    """Production safeguard: LOCAL_PORTAL_PASSWORD must not be set with a non-local DB.

    The local password auth path is intended for local development only.
    Setting it in production bypasses Okta and allows anyone who knows the
    password to authenticate, which is insecure in a multi-tenant environment.
    """
    if not settings.LOCAL_PORTAL_PASSWORD:
        return
    db_url = settings.DATABASE_URL or ""
    if db_url and not any(host in db_url for host in _LOCAL_DB_HINTS):
        log.error(
            "startup refused: LOCAL_PORTAL_PASSWORD set with non-local DATABASE_URL — "
            "this env var is for local development only; production uses Okta auth",
            database_url_redacted=db_url.split("@")[-1] if "@" in db_url else "(unset)",
        )
        sys.exit(1)


def _check_db_ssl_safety(settings) -> None:
    """Warn if DATABASE_URL points at a remote host with no SSL directive.

    This is a *warning* only — not a hard exit — because some deployments
    use mutual TLS at the network layer (sidecar, VPN) that is not reflected
    in the connection string.  The warning prompts operators to investigate
    without rejecting valid configurations.

    SSL indicators checked: ``sslmode=``, ``ssl=true``, ``ssl_ca=``, ``tls=``.
    """
    url = settings.DATABASE_URL or ""
    if not url:
        return
    is_remote = not any(h in url for h in _LOCAL_DB_HINTS)
    has_ssl = any(s in url.lower() for s in ("sslmode=", "ssl=true", "ssl_ca=", "tls="))
    if is_remote and not has_ssl:
        log.warning(
            "DATABASE_URL appears to use a remote host without an explicit SSL "
            "directive (sslmode=require not found). Token hashes and encrypted "
            "keys may transit the network unencrypted. "
            "Add ?sslmode=require to DATABASE_URL to silence this warning.",
            database_url_host=(url.split("@")[-1].split("/")[0] if "@" in url else "(unparseable)"),
        )


def _run_migrations() -> None:
    """Run Alembic upgrade to head. Called at startup when RUN_MIGRATIONS_ON_STARTUP=true."""
    from alembic.config import Config

    from alembic import command  # noqa: PLC0415 — lazy: alembic may be absent in some test envs

    cfg = Config("alembic.ini")
    log.info("running database migrations")
    command.upgrade(cfg, "head")
    log.info("database migrations applied")


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

    _check_admin_bypass_safety(settings)
    _check_local_password_safety(settings)
    _check_db_ssl_safety(settings)

    try:
        from security_scanner.tokens.crypto import validate_startup_key  # noqa: PLC0415

        validate_startup_key(settings)
    except Exception as exc:  # noqa: BLE001 — exit on any crypto setup error
        log.error("startup failed: SCANNER_ENCRYPTION_KEY invalid", error=type(exc).__name__)
        sys.exit(1)

    if settings.LOCAL_SCAN_TOKEN and settings.USE_TOKEN_REGISTRY:
        log.warning(
            "LOCAL_SCAN_TOKEN is set but USE_TOKEN_REGISTRY=true; the env "
            "var is ignored. Remove it from your environment to silence "
            "this warning.",
        )

    if settings.RUN_MIGRATIONS_ON_STARTUP and settings.DATABASE_URL:
        try:
            _run_migrations()
        except Exception as exc:  # noqa: BLE001 — log and exit; broken DB = unsafe
            log.error("startup failed: migrations error", error=type(exc).__name__)
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
        token_registry_enabled=settings.USE_TOKEN_REGISTRY,
        admin_local_bypass=settings.ADMIN_LOCAL_BYPASS,
    )

    purge_task: asyncio.Task | None = None
    if settings.DATABASE_URL:
        purge_task = asyncio.create_task(_report_retention_loop())

    yield

    if purge_task is not None:
        purge_task.cancel()
        try:
            await purge_task
        except asyncio.CancelledError:
            pass
    log.info("service shutting down", version=VERSION)


async def _report_retention_loop() -> None:
    """Background task: purge scan records older than the configured retention window.

    Runs once immediately at startup, then every 24 hours. Only fires when
    report_retention_days is set in ScannerSettings; silently skips otherwise.
    Exceptions are caught and logged so a DB hiccup can never crash the app.
    """
    from sqlalchemy import delete, desc, select  # noqa: PLC0415

    from security_scanner.tokens.db import get_session_factory  # noqa: PLC0415
    from security_scanner.tokens.models import (  # noqa: PLC0415
        CiScanRecord,
        ScanRecord,
        ScannerSettings,
    )

    while True:
        try:
            factory = get_session_factory()
            async with factory() as session:
                sc = (
                    await session.execute(
                        select(ScannerSettings).order_by(desc(ScannerSettings.id)).limit(1)
                    )
                ).scalar_one_or_none()
                if sc and sc.report_retention_days:
                    cutoff = datetime.now(UTC) - timedelta(days=sc.report_retention_days)
                    portal_res = await session.execute(
                        delete(ScanRecord).where(ScanRecord.started_at < cutoff)
                    )
                    ci_res = await session.execute(
                        delete(CiScanRecord).where(CiScanRecord.started_at < cutoff)
                    )
                    await session.commit()
                    portal_n = portal_res.rowcount or 0
                    ci_n = ci_res.rowcount or 0
                    if portal_n or ci_n:
                        log.info(
                            "report retention purge",
                            retention_days=sc.report_retention_days,
                            portal_deleted=portal_n,
                            ci_deleted=ci_n,
                        )
        except Exception:  # noqa: BLE001 — purge must never crash the app
            log.warning("report retention purge failed", exc_info=True)

        await asyncio.sleep(86400)  # 24 h


def _local_test_mode_enabled() -> bool:
    return os.getenv("LOCAL_TEST_MODE", "").lower() == "true"


app = FastAPI(
    title="Phrase Security Vulnerability Scanner",
    version=VERSION,
    lifespan=lifespan,
)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Append OWASP-recommended security headers to every HTTP response.

    These are last-resort defences; the primary controls are authn/authz deps,
    Fernet-signed cookies with httponly+SameSite=Lax, and Jinja2 auto-escaping.

    X-Frame-Options:      prevent clickjacking (OWASP A05).
    X-Content-Type-Options: stop MIME-sniffing (OWASP A05).
    X-XSS-Protection:    disabled — modern browsers rely on CSP; the legacy
                          filter introduces its own XSS surface.
    Referrer-Policy:      default for non-sensitive routes; sensitive routes
                          override with "no-referrer" via _NO_STORE_HEADERS.
    """

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-XSS-Protection", "0")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if request.url.scheme == "https":
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response


app.add_middleware(_SecurityHeadersMiddleware)


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
# Local-advisory jurisdiction (Appendix D-12). Always mounted but
# self-disabling: every call 401s unless LOCAL_SCAN_TOKEN is configured, and
# it can never gate a deploy or open a PR (separate token, no gate_decision).
app.include_router(local_scan_router)
# Per-user token self-service portal. Always mounted; auth dep guards it.
# In legacy mode (USE_TOKEN_REGISTRY=false) it is reachable but issuing a
# token has no effect on /scan/local — there it still consults the env var.
app.include_router(portal_router)
app.include_router(okta_router)
# Admin panel — group-gated (ADMIN_GROUP_NAME). require_admin returns 403 for
# non-admins, so it is safe to mount unconditionally.
app.include_router(admin_router)

# LOCAL_TEST_MODE: conditional, non-production-only test endpoint that
# bypasses GitHub fetch with caller-supplied files. The env var is
# evaluated once at import time so the test surface is fully absent from
# production deploys.
if _local_test_mode_enabled():
    from security_scanner.agent.test_endpoint import router as test_router  # noqa: PLC0415

    app.include_router(test_router)
