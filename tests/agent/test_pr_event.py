"""Tests for POST /agent/pr-event (Appendix D-16).

Always audit-logs a rejected bot auto-fix PR; Slack alert ONLY for
High/Critical (the user's rule). Mirrors the test_bypass.py AsyncMock
pattern — the Slack function is mocked, so no network.
"""

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from security_scanner.agent import api as agent_api
from security_scanner.agent.api import router

_VALID_TOKEN = "phrase-scan-token-secret"  # noqa: S105 — test fixture


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("PHRASE_SCAN_TOKEN", _VALID_TOKEN)
    monkeypatch.setenv("GITHUB_APP_ID", "123")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY", "-----BEGIN PRIVATE KEY-----")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "Iv1.test")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "secret")


@pytest.fixture
def alert(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr(agent_api, "send_pr_rejected_alert", mock)
    return mock


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


_AUTH = {"Authorization": f"Bearer {_VALID_TOKEN}"}


def _body(**kw) -> dict:
    b = {
        "repo_url": "https://github.com/davidayomide/VAmPI",
        "pr_number": 5,
        "pr_url": "https://github.com/davidayomide/VAmPI/pull/5",
        "head_ref": "security/issues/master",
        "merged": False,
        "closed_by": "dave",
        "closed_at": "2026-05-19T03:00:00Z",
        "reason": "will fix manually",
        "critical": 2,
        "high": 1,
    }
    b.update(kw)
    return b


def test_requires_auth(client, alert):
    r = client.post("/agent/pr-event", json=_body())
    assert r.status_code == 401
    alert.assert_not_awaited()


def test_high_critical_rejection_alerts(client, alert):
    r = client.post("/agent/pr-event", json=_body(), headers=_AUTH)
    assert r.status_code == 200
    assert r.json() == {"ignored": False, "logged": True, "alerted": True}
    alert.assert_awaited_once()


def test_high_only_rejection_alerts(client, alert):
    r = client.post("/agent/pr-event", json=_body(critical=0, high=3), headers=_AUTH)
    assert r.json()["alerted"] is True
    alert.assert_awaited_once()


def test_medium_low_only_is_logged_not_alerted(client, alert):
    r = client.post("/agent/pr-event", json=_body(critical=0, high=0), headers=_AUTH)
    assert r.status_code == 200
    assert r.json() == {"ignored": False, "logged": True, "alerted": False}
    alert.assert_not_awaited()


def test_merged_pr_is_ignored(client, alert):
    r = client.post("/agent/pr-event", json=_body(merged=True), headers=_AUTH)
    assert r.status_code == 200
    assert r.json()["ignored"] is True
    alert.assert_not_awaited()


def test_non_bot_branch_is_ignored(client, alert):
    r = client.post("/agent/pr-event", json=_body(head_ref="feature/x"), headers=_AUTH)
    assert r.status_code == 200
    assert r.json()["ignored"] is True
    alert.assert_not_awaited()


def test_missing_reason_still_alerts_and_passes_none(client, alert):
    r = client.post("/agent/pr-event", json=_body(reason=None), headers=_AUTH)
    assert r.status_code == 200
    assert r.json()["alerted"] is True
    alert.assert_awaited_once()
    assert alert.await_args.kwargs["reason"] is None
