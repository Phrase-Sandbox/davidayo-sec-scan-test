"""Tests for ``/scan/local`` auth in registry mode (USE_TOKEN_REGISTRY=true).

The legacy single-token path is covered by ``test_local_scan.py`` and stays
unchanged by PR 2. Here we verify:

- A token issued via the registry authenticates successfully and produces
  a ``scan_ok`` row in ``audit_events`` with the caller's email.
- Unknown / revoked / bad-signature tokens all 401 and produce a
  ``scan_unauthorized`` audit row with the right outcome.
- A missing/malformed Authorization header 401s with ``bad_format`` but
  produces NO audit row (we don't want every random hit to spam the table).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from security_scanner.agent.api import get_pipeline
from security_scanner.agent.api import router as agent_router
from security_scanner.agent.local_scan import router as local_router
from security_scanner.pipeline import ScanPipeline
from security_scanner.shared.models.enums import (
    Confidence,
    GateDecision,
    ScanTarget,
    ScanType,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.models.scan_result import ScanResult
from security_scanner.tokens import registry as token_registry
from security_scanner.tokens.db import Base
from security_scanner.tokens.models import (
    AuditEvent,
    AuditEventType,
    LocalScanToken,
)


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("USE_TOKEN_REGISTRY", "true")
    # DATABASE_URL is unused — get_session_factory is patched below.
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://unused:unused@unused:5432/unused"
    )
    monkeypatch.setenv("ADMIN_LOCAL_BYPASS", "true")
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", "ci-gate-token")
    # The settings object is cached via lru_cache in some paths; not here
    # (shared.config.get_settings() builds fresh) but be explicit.


@pytest.fixture
async def session_factory(monkeypatch):
    """In-memory SQLite session factory patched in for the duration of a test."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    # Patch the module-level accessor used by verify_local_scan_token and
    # _record_scan_ok_audit so both routes share THIS factory.
    monkeypatch.setattr(
        "security_scanner.agent.local_scan.get_session_factory", lambda: factory
    )
    try:
        yield factory
    finally:
        await engine.dispose()


# --- Fixtures shared with the existing test file -----------------------------


def _finding(severity: Severity) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id="A03:2021",
        severity=severity,
        confidence=Confidence.High,
        cvss_band={
            Severity.Critical: "9.0-10.0",
            Severity.High: "7.0-8.9",
            Severity.Medium: "4.0-6.9",
            Severity.Low: "0.1-3.9",
        }[severity],
        affected_file="app/db.py",
        affected_lines="6",
        description="SQL injection via string concatenation",
        suggested_fix="use parameterised queries",
        owasp_reference="https://owasp.org/Top10/A03_2021-Injection/",
        patch_file_path="patches/x.patch",
        exploit_scenario=(
            "Attacker sends a crafted payload via the username parameter to "
            "app/db.py bypassing the WHERE clause."
        ),
        verification_status=VerificationStatus.unverified,
    )


def _result(findings) -> ScanResult:
    return ScanResult(
        scan_id=uuid4(),
        repo_url="https://github.com/local/workspace",
        scan_target=ScanTarget.full_repo,
        scan_type=ScanType.on_demand,
        triggered_by="local-dev",
        timestamp=datetime(2026, 5, 23, tzinfo=UTC),
        findings_count=len(findings),
        gate_decision=GateDecision.advisory,
        partial_scan=False,
        unscanned_files=[],
        findings=findings,
        warnings=[],
        patches={},
    )


@pytest.fixture
def mock_pipeline() -> AsyncMock:
    return AsyncMock(spec=ScanPipeline)


@pytest.fixture
def client(mock_pipeline):
    app = FastAPI()
    app.include_router(local_router)
    app.include_router(agent_router)
    # Only override the CI pipeline dep — the local-scan auth dep runs real.
    app.dependency_overrides[get_pipeline] = lambda: mock_pipeline
    return TestClient(app)


def _post(client, token):
    return client.post(
        "/scan/local",
        json={
            "files": {"app/db.py": "q = 'SELECT '+u"},
            "repo_url": "https://github.com/local/workspace",
        },
        headers={"Authorization": f"Bearer {token}"} if token else {},
    )


async def _seed_token(factory, *, user_email: str) -> str:
    async with factory() as session:
        issued = await token_registry.issue_or_rotate_for_user(
            session, user_email=user_email
        )
        await session.commit()
        return issued.full_token


# --- Happy path --------------------------------------------------------------


async def test_registry_ok_returns_200_and_audits_scan_ok(
    session_factory, client, mock_pipeline, monkeypatch
):
    """Registry token → 200 + scan_ok audit row + last_used_at bumped."""
    from unittest.mock import AsyncMock as _AsyncMock
    from unittest.mock import MagicMock as _MagicMock

    from security_scanner.tokens.models import LLMProvider

    # Patch the three internal deps scan_local() now calls instead of factory.
    settings_row = _MagicMock()
    settings_row.provider = LLMProvider.anthropic
    settings_row.model = "claude-sonnet-4-6"
    settings_row.encrypted_api_key = b"fake-encrypted"

    monkeypatch.setattr(
        "security_scanner.agent.local_scan._load_user_llm_settings",
        _AsyncMock(return_value=settings_row),
    )
    monkeypatch.setattr(
        "security_scanner.tokens.crypto.decrypt",
        lambda _: "sk-ant-fake",
    )
    monkeypatch.setattr(
        "security_scanner.agent.local_scan.build_user_llm_client",
        lambda *_a, **_kw: _MagicMock(),
    )
    monkeypatch.setattr(
        "security_scanner.agent.local_scan.ScanPipeline",
        lambda *_a, **_kw: mock_pipeline,
    )
    # Let _persist_scan_data run so the scan_ok audit row is written.
    # It uses get_session_factory() from the module — already patched to the
    # in-memory factory by the session_factory fixture.

    mock_pipeline.run.return_value = _result([_finding(Severity.High)])
    token = await _seed_token(session_factory, user_email="alice@phrase.com")

    r = _post(client, token)
    assert r.status_code == 200, r.text

    # No gate_decision on local jurisdiction.
    body = r.json()
    assert "gate_decision" not in body
    assert body["findings_count"] == 1

    # A scan_ok audit row must have been written with alice's email.
    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AuditEvent).where(
                        AuditEvent.event_type == AuditEventType.scan_ok
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].user_email == "alice@phrase.com"
    assert rows[0].token_id is not None
    assert rows[0].event_metadata["file_count"] == 1
    assert rows[0].event_metadata["findings_count"] == 1
    assert rows[0].event_metadata["high"] == 1

    # And last_used_at was bumped on the token row.
    async with session_factory() as session:
        token_row = (
            await session.execute(select(LocalScanToken))
        ).scalar_one()
    assert token_row.last_used_at is not None


# --- Failure paths -----------------------------------------------------------


async def test_unknown_token_401_and_audits_scan_unauthorized(
    session_factory, client
):
    # No token seeded.
    fake = "phs_local_tok-deadbeefcafe_" + "A" * 43
    r = _post(client, fake)
    assert r.status_code == 401

    async with session_factory() as session:
        rows = (
            (await session.execute(select(AuditEvent))).scalars().all()
        )
    assert len(rows) == 1
    assert rows[0].event_type == AuditEventType.scan_unauthorized
    assert rows[0].event_metadata["outcome"] == "unknown_token"
    assert rows[0].user_email is None
    assert rows[0].token_id == "tok-deadbeefcafe"


async def test_revoked_token_401_with_revoked_outcome(session_factory, client):
    token = await _seed_token(session_factory, user_email="bob@phrase.com")
    async with session_factory() as session:
        await token_registry.revoke_active_for_user(
            session, user_email="bob@phrase.com", actor="self"
        )
        await session.commit()

    r = _post(client, token)
    assert r.status_code == 401

    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AuditEvent)
                    .where(AuditEvent.event_type == AuditEventType.scan_unauthorized)
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].event_metadata["outcome"] == "revoked"
    assert rows[0].user_email == "bob@phrase.com"


async def test_bad_signature_401(session_factory, client):
    real = await _seed_token(session_factory, user_email="carol@phrase.com")
    # Reuse the legitimate token_id prefix but scramble the suffix.
    # NB: don't use ``rsplit("_", 1)`` on the full token — url-safe base64
    # contains ``_`` so the split can land inside the suffix and produce a
    # malformed test fixture. Parse it properly instead.
    parsed = token_registry.parse_token(real)
    assert parsed is not None
    token_id, _suffix = parsed
    tampered = f"phs_local_{token_id}_" + ("Z" * 43)

    r = _post(client, tampered)
    assert r.status_code == 401

    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AuditEvent)
                    .where(AuditEvent.event_type == AuditEventType.scan_unauthorized)
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].event_metadata["outcome"] == "bad_signature"
    assert rows[0].user_email == "carol@phrase.com"


async def test_missing_header_401_no_audit_row(session_factory, client):
    # No Authorization header at all.
    r = _post(client, None)
    assert r.status_code == 401

    async with session_factory() as session:
        rows = (await session.execute(select(AuditEvent))).scalars().all()
    # We deliberately do NOT audit bad_format failures — every random hit
    # would create a row. Real attacks send well-formed tokens which DO
    # land in the unknown_token / bad_signature audits.
    assert rows == []


async def test_malformed_token_401_no_audit_row(session_factory, client):
    r = _post(client, "totally-not-a-real-token")
    assert r.status_code == 401
    async with session_factory() as session:
        rows = (await session.execute(select(AuditEvent))).scalars().all()
    assert rows == []
