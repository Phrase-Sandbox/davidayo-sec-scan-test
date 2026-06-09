"""End-to-end model enforcement: admin sets the model; users and CI use it.

Verifies that:
- CLI scans use OrgSettings.anthropic_model / .google_model (not user's model field)
- CI (/agent/scan) resolves the correct per-provider model
- No org_settings row → model=None (provider default) — no 500
- The _get_model_for_provider helper returns the right value for each provider alias
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from security_scanner.shared.llm.factory import _get_model_for_provider

# ---------------------------------------------------------------------------
# Unit tests for _get_model_for_provider
# ---------------------------------------------------------------------------


def _org_row(*, anthropic_model=None, google_model=None, default_provider="anthropic"):
    """Build a minimal mock OrgSettings row."""
    row = MagicMock()
    row.anthropic_model = anthropic_model
    row.google_model = google_model
    row.default_provider = MagicMock()
    row.default_provider.value = default_provider
    return row


class TestGetModelForProvider:
    def test_returns_anthropic_model_for_anthropic(self):
        row = _org_row(anthropic_model="claude-opus-4-7", google_model="gemini-2.5-pro")
        assert _get_model_for_provider(row, "anthropic") == "claude-opus-4-7"

    def test_returns_anthropic_model_for_claude_alias(self):
        row = _org_row(anthropic_model="claude-haiku-4-5-20251001")
        assert _get_model_for_provider(row, "claude") == "claude-haiku-4-5-20251001"

    def test_returns_google_model_for_google(self):
        row = _org_row(google_model="gemini-2.5-flash")
        assert _get_model_for_provider(row, "google") == "gemini-2.5-flash"

    def test_returns_google_model_for_gemini_alias(self):
        row = _org_row(google_model="gemini-2.5-pro")
        assert _get_model_for_provider(row, "gemini") == "gemini-2.5-pro"

    def test_returns_none_when_org_row_is_none(self):
        assert _get_model_for_provider(None, "anthropic") is None

    def test_returns_none_when_anthropic_model_not_set(self):
        row = _org_row(anthropic_model=None)
        assert _get_model_for_provider(row, "anthropic") is None

    def test_returns_none_when_google_model_not_set(self):
        row = _org_row(google_model=None)
        assert _get_model_for_provider(row, "google") is None

    def test_returns_none_for_unknown_provider(self):
        row = _org_row(anthropic_model="claude-sonnet-4-6")
        assert _get_model_for_provider(row, "unknown") is None

    def test_whitespace_in_provider_name_handled(self):
        row = _org_row(anthropic_model="claude-sonnet-4-6")
        assert _get_model_for_provider(row, "  anthropic  ") == "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# CLI: scan_local uses admin-set model (not user's model field)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("LOCAL_SCAN_TOKEN", "local-test-token")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", "ci-gate-token")
    monkeypatch.setenv("GITHUB_APP_ID", "1")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


def _mock_user_settings(provider: str = "anthropic"):
    """A minimal UserLLMSettings mock — model field is NULL (admin-controlled)."""
    from security_scanner.tokens.models import LLMProvider

    row = MagicMock()
    row.provider = LLMProvider.anthropic if provider == "anthropic" else LLMProvider.google
    row.model = None  # not set — admin controls this
    row.encrypted_api_key = b"fake-encrypted"
    return row


def _mock_org_settings(*, anthropic_model=None, google_model=None):
    """A minimal OrgSettings mock."""
    row = MagicMock()
    row.anthropic_model = anthropic_model
    row.google_model = google_model
    return row


def _assert_build_called_with_model(captured_calls: list, expected_model):
    """Helper: check that build_user_llm_client was called with the expected model."""
    assert len(captured_calls) == 1
    _, _, model = captured_calls[0]
    assert model == expected_model


class TestCLIScanUsesAdminModel:
    """Verify that scan_local resolves the admin-set model, not the user's model field."""

    def _run_scan(self, monkeypatch, *, user_provider="anthropic", org_settings, pipeline_result):
        """Set up the full mock stack and POST to /scan/local."""

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from security_scanner.agent.local_scan import (
            AuthenticatedLocalCaller,
            verify_local_scan_token,
        )
        from security_scanner.agent.local_scan import (
            router as local_router,
        )

        captured_llm_calls: list[tuple] = []

        def _fake_build_user_llm_client(provider, api_key, model=None):
            captured_llm_calls.append((provider, api_key, model))
            return MagicMock()

        monkeypatch.setattr(
            "security_scanner.agent.local_scan._load_user_llm_settings",
            AsyncMock(return_value=_mock_user_settings(user_provider)),
        )
        monkeypatch.setattr(
            "security_scanner.agent.local_scan._load_active_org_settings",
            AsyncMock(return_value=org_settings),
        )
        monkeypatch.setattr(
            "security_scanner.tokens.crypto.decrypt",
            lambda _: "sk-decrypted",
        )
        monkeypatch.setattr(
            "security_scanner.agent.local_scan.build_user_llm_client",
            _fake_build_user_llm_client,
        )
        mock_pipeline = AsyncMock()
        mock_pipeline.run.return_value = pipeline_result
        monkeypatch.setattr(
            "security_scanner.agent.local_scan.ScanPipeline",
            lambda *a, **kw: mock_pipeline,
        )
        monkeypatch.setattr(
            "security_scanner.agent.local_scan._persist_scan_data",
            AsyncMock(),
        )

        app = FastAPI()
        app.include_router(local_router)
        app.dependency_overrides[verify_local_scan_token] = lambda: AuthenticatedLocalCaller(
            token="local-test-token",
            token_id="tok-abc123456789",
            user_email="dev@phrase.com",
        )
        client = TestClient(app)
        r = client.post(
            "/scan/local",
            json={
                "files": {"app.py": "x = 1"},
                "repo_url": "https://github.com/local/workspace",
            },
            headers={"Authorization": "Bearer local-test-token"},
        )
        return r, captured_llm_calls

    def _scan_result(self):
        from uuid import uuid4

        from security_scanner.shared.models.enums import (
            GateDecision,
            ScanTarget,
            ScanType,
        )
        from security_scanner.shared.models.scan_result import ScanResult

        return ScanResult(
            scan_id=uuid4(),
            repo_url="https://github.com/local/workspace",
            scan_target=ScanTarget.full_repo,
            scan_type=ScanType.on_demand,
            triggered_by="local-dev",
            timestamp=datetime(2026, 5, 26, tzinfo=UTC),
            findings_count=0,
            gate_decision=GateDecision.advisory,
            partial_scan=False,
            unscanned_files=[],
            findings=[],
            warnings=[],
            patches={},
        )

    def test_cli_anthropic_uses_admin_set_anthropic_model(self, monkeypatch):
        """CLI Anthropic scan calls build_user_llm_client with admin's anthropic_model."""
        org = _mock_org_settings(anthropic_model="claude-opus-4-7", google_model="gemini-2.5-flash")
        r, calls = self._run_scan(
            monkeypatch,
            user_provider="anthropic",
            org_settings=org,
            pipeline_result=self._scan_result(),
        )
        assert r.status_code == 200, r.text
        # build_user_llm_client should have been called with model="claude-opus-4-7"
        assert len(calls) == 1
        provider, _, model = calls[0]
        assert provider == "anthropic"
        assert model == "claude-opus-4-7"

    def test_cli_google_uses_admin_set_google_model(self, monkeypatch):
        """CLI Google scan calls build_user_llm_client with admin's google_model."""
        org = _mock_org_settings(anthropic_model="claude-sonnet-4-6", google_model="gemini-2.5-pro")
        r, calls = self._run_scan(
            monkeypatch,
            user_provider="google",
            org_settings=org,
            pipeline_result=self._scan_result(),
        )
        assert r.status_code == 200, r.text
        assert len(calls) == 1
        provider, _, model = calls[0]
        assert provider == "google"
        assert model == "gemini-2.5-pro"

    def test_cli_no_org_settings_uses_none_model(self, monkeypatch):
        """No org_settings row → model=None → provider uses its own default. No 500."""
        r, calls = self._run_scan(
            monkeypatch,
            user_provider="anthropic",
            org_settings=None,  # bootstrap window
            pipeline_result=self._scan_result(),
        )
        assert r.status_code == 200, r.text
        assert len(calls) == 1
        _, _, model = calls[0]
        assert model is None  # provider will use its own default


# ---------------------------------------------------------------------------
# CI: build_org_llm_client_from_settings uses per-provider model columns
# ---------------------------------------------------------------------------


class TestCIUsesAdminModel:
    """Verify the CI factory path uses anthropic_model / google_model, not default_model."""

    def test_ci_anthropic_uses_anthropic_model(self, monkeypatch):
        """build_org_llm_client_from_settings with anthropic provider uses org_row.anthropic_model."""
        from security_scanner.shared.llm.factory import build_org_llm_client_from_settings

        built: list = []

        def _fake_make_claude(api_key, model):
            built.append(("claude", api_key, model))
            return MagicMock()

        monkeypatch.setattr(
            "security_scanner.shared.llm.factory._make_claude",
            _fake_make_claude,
        )
        monkeypatch.setattr(
            "security_scanner.tokens.crypto.decrypt",
            lambda _: "sk-decrypted",
        )

        org = _org_row(anthropic_model="claude-haiku-4-5-20251001", google_model="gemini-2.5-flash")
        org.encrypted_anthropic_key = b"enc-key"
        org.encrypted_google_key = None

        build_org_llm_client_from_settings(org, provider_choice="anthropic")

        assert len(built) == 1
        _, _, model = built[0]
        assert model == "claude-haiku-4-5-20251001"

    def test_ci_google_uses_google_model(self, monkeypatch):
        """build_org_llm_client_from_settings with google provider uses org_row.google_model."""
        from security_scanner.shared.llm.factory import build_org_llm_client_from_settings

        built: list = []

        def _fake_make_gemini(api_key, model):
            built.append(("gemini", api_key, model))
            return MagicMock()

        monkeypatch.setattr(
            "security_scanner.shared.llm.factory._make_gemini",
            _fake_make_gemini,
        )
        monkeypatch.setattr(
            "security_scanner.tokens.crypto.decrypt",
            lambda _: "AI-decrypted",
        )

        org = _org_row(anthropic_model="claude-sonnet-4-6", google_model="gemini-2.5-pro")
        org.encrypted_anthropic_key = None
        org.encrypted_google_key = b"enc-google-key"

        build_org_llm_client_from_settings(org, provider_choice="google")

        assert len(built) == 1
        _, _, model = built[0]
        assert model == "gemini-2.5-pro"

    def test_ci_default_provider_selects_correct_model(self, monkeypatch):
        """Without provider_choice, default_provider drives model selection."""
        from security_scanner.shared.llm.factory import build_org_llm_client_from_settings

        built: list = []

        def _fake_make_claude(api_key, model):
            built.append(model)
            return MagicMock()

        monkeypatch.setattr(
            "security_scanner.shared.llm.factory._make_claude",
            _fake_make_claude,
        )
        monkeypatch.setattr(
            "security_scanner.tokens.crypto.decrypt",
            lambda _: "sk-decrypted",
        )

        # default_provider = anthropic → should use anthropic_model
        org = _org_row(
            anthropic_model="claude-sonnet-4-6",
            google_model="gemini-2.5-flash",
            default_provider="anthropic",
        )
        org.encrypted_anthropic_key = b"enc"
        org.encrypted_google_key = None

        build_org_llm_client_from_settings(org, provider_choice=None)

        assert built == ["claude-sonnet-4-6"]

    def test_ci_provider_choice_overrides_default_provider(self, monkeypatch):
        """provider_choice=google selects google_model even when default_provider=anthropic."""
        from security_scanner.shared.llm.factory import build_org_llm_client_from_settings

        built: list = []

        def _fake_make_gemini(api_key, model):
            built.append(model)
            return MagicMock()

        monkeypatch.setattr(
            "security_scanner.shared.llm.factory._make_gemini",
            _fake_make_gemini,
        )
        monkeypatch.setattr(
            "security_scanner.tokens.crypto.decrypt",
            lambda _: "AI-decrypted",
        )

        # default_provider = anthropic but we override to google
        org = _org_row(
            anthropic_model="claude-sonnet-4-6",
            google_model="gemini-2.5-pro",
            default_provider="anthropic",
        )
        org.encrypted_anthropic_key = None
        org.encrypted_google_key = b"enc-google"

        build_org_llm_client_from_settings(org, provider_choice="google")

        assert built == ["gemini-2.5-pro"]

    def test_ci_no_model_set_passes_none(self, monkeypatch):
        """When google_model is None, None is passed to _make_gemini (uses provider default)."""
        from security_scanner.shared.llm.factory import build_org_llm_client_from_settings

        built: list = []

        def _fake_make_gemini(api_key, model):
            built.append(model)
            return MagicMock()

        monkeypatch.setattr(
            "security_scanner.shared.llm.factory._make_gemini",
            _fake_make_gemini,
        )
        monkeypatch.setattr(
            "security_scanner.tokens.crypto.decrypt",
            lambda _: "AI-decrypted",
        )

        org = _org_row(anthropic_model=None, google_model=None, default_provider="google")
        org.encrypted_anthropic_key = None
        org.encrypted_google_key = b"enc-google"

        build_org_llm_client_from_settings(org, provider_choice="google")

        assert built == [None]
