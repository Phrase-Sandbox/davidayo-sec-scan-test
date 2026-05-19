"""Smoke tests for the env-var-driven Settings class.

Verifies fail-fast behaviour on missing required vars and correct defaults
when all required vars are provided. Real value parsing is left to pydantic.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from security_scanner.shared.config import Settings, get_settings

REQUIRED_VARS: dict[str, str] = {
    "ANTHROPIC_API_KEY": "sk-ant-test",
    "GITHUB_APP_ID": "123456",
    "GITHUB_APP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\\nMIIE...\\n-----END PRIVATE KEY-----",
    "GITHUB_OAUTH_CLIENT_ID": "Iv1.test",
    "GITHUB_OAUTH_CLIENT_SECRET": "oauth-secret",
}

OPTIONAL_VARS_TO_CLEAR: list[str] = [
    "PHRASE_SCAN_TOKEN",
    "SLACK_WEBHOOK_URL",
    "PORT",
    "LOG_LEVEL",
]


@pytest.fixture
def clean_env(monkeypatch):
    """Strip every variable Settings cares about so each test starts from zero."""
    for key in list(REQUIRED_VARS) + OPTIONAL_VARS_TO_CLEAR:
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


def test_missing_required_vars_raises_validation_error(clean_env):
    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]


def test_loads_required_vars_from_environment(clean_env):
    for key, value in REQUIRED_VARS.items():
        clean_env.setenv(key, value)
    settings = get_settings()
    assert settings.ANTHROPIC_API_KEY == REQUIRED_VARS["ANTHROPIC_API_KEY"]
    assert settings.GITHUB_APP_ID == REQUIRED_VARS["GITHUB_APP_ID"]


def test_optional_vars_default_correctly_when_unset(clean_env):
    for key, value in REQUIRED_VARS.items():
        clean_env.setenv(key, value)
    settings = get_settings()
    assert settings.PHRASE_SCAN_TOKEN is None
    assert settings.SLACK_WEBHOOK_URL is None
    assert settings.PORT == 8000
    assert settings.LOG_LEVEL == "INFO"


def test_port_is_parsed_from_string(clean_env):
    for key, value in REQUIRED_VARS.items():
        clean_env.setenv(key, value)
    clean_env.setenv("PORT", "9001")
    settings = get_settings()
    assert settings.PORT == 9001


def test_unknown_env_vars_are_ignored(clean_env):
    for key, value in REQUIRED_VARS.items():
        clean_env.setenv(key, value)
    clean_env.setenv("UNRELATED_VAR_THAT_SHOULD_BE_IGNORED", "x")
    settings = get_settings()
    assert not hasattr(settings, "UNRELATED_VAR_THAT_SHOULD_BE_IGNORED")
