"""The env-selected provider factory (D-15).

Default = Anthropic (production unchanged). Non-Anthropic dispatch is proven
WITHOUT importing the optional SDKs or needing keys: the provider class is
monkeypatched on its module, and the missing-key / unknown-provider faults
fail fast *before* any client is constructed.
"""

import types

import pytest

from security_scanner.shared.claude.client import ClaudeClient
from security_scanner.shared.llm import factory as factory_mod
from security_scanner.shared.llm.base import LLMConfigError


def _settings(**kw):
    base = {
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "GOOGLE_API_KEY": None,
    }
    base.update(kw)
    return types.SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("SCANNER_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("SCANNER_LLM_MODEL", raising=False)


def test_default_is_anthropic_claude():
    client = factory_mod.build_llm_client(_settings())
    assert isinstance(client, ClaudeClient)


def test_explicit_anthropic_honours_model_override(monkeypatch):
    monkeypatch.setenv("SCANNER_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("SCANNER_LLM_MODEL", "claude-test-x")
    client = factory_mod.build_llm_client(_settings())
    assert isinstance(client, ClaudeClient)
    assert client._model == "claude-test-x"


def test_google_without_key_fails_fast(monkeypatch):
    monkeypatch.setenv("SCANNER_LLM_PROVIDER", "gemini")
    with pytest.raises(LLMConfigError):
        factory_mod.build_llm_client(_settings(GOOGLE_API_KEY=None))


def test_unknown_provider_raises(monkeypatch):
    monkeypatch.setenv("SCANNER_LLM_PROVIDER", "bogus-llm")
    with pytest.raises(LLMConfigError):
        factory_mod.build_llm_client(_settings())


def test_gemini_dispatch_and_data_governance_warning(monkeypatch):
    monkeypatch.setenv("SCANNER_LLM_PROVIDER", "google")
    import security_scanner.shared.llm.gemini_client as gc

    sentinel = object()
    captured = {}

    def fake_ctor(*, api_key, model):
        captured["api_key"] = api_key
        captured["model"] = model
        return sentinel

    monkeypatch.setattr(gc, "GeminiClient", fake_ctor)

    warnings: list = []

    class _FakeLog:
        def warning(self, *a, **k):
            warnings.append((a, k))

    monkeypatch.setattr(factory_mod, "log", _FakeLog())

    out = factory_mod.build_llm_client(_settings(GOOGLE_API_KEY="g-key"))

    assert out is sentinel
    assert captured["api_key"] == "g-key"
    assert captured["model"] == gc.DEFAULT_MODEL
    assert warnings, "non-Anthropic selection must emit the data-governance warning"
