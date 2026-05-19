"""Gemini client with the SDK fully injected (D-15).

The live network path is **never** exercised (no keys in the simulation):
the real SDK is bypassed via the `client=` DI parameter. These prove prompt
wiring + shared parsing + error mapping only — exactly the honest limit
recorded in Appendix D-15.
"""

from unittest.mock import MagicMock

import pytest

from security_scanner.shared.claude.client import (
    ClaudeTimeoutError,
    ClaudeUnavailableError,
)
from security_scanner.shared.llm.gemini_client import GeminiClient


def _gemini_sdk(text: str) -> MagicMock:
    sdk = MagicMock()
    sdk.models.generate_content.return_value = MagicMock(text=text)
    return sdk


# --- Gemini ----------------------------------------------------------------


def test_gemini_analyse_parses_findings():
    c = GeminiClient(api_key="x", client=_gemini_sdk('{"findings": []}'))
    assert c.analyse({"a.py": "x = 1"}) == []


def test_gemini_ask_returns_raw_text():
    c = GeminiClient(api_key="x", client=_gemini_sdk("VERDICT: no"))
    assert c.ask("s", "u") == "VERDICT: no"


def test_gemini_timeout_is_mapped():
    sdk = MagicMock()

    class ReadTimeout(Exception):
        pass

    sdk.models.generate_content.side_effect = ReadTimeout()
    c = GeminiClient(api_key="x", client=sdk)
    with pytest.raises(ClaudeTimeoutError):
        c.ask("s", "u")


def test_gemini_unavailable_after_retries(monkeypatch):
    monkeypatch.setattr(
        "security_scanner.shared.llm.gemini_client.time.sleep", lambda *_: None
    )
    sdk = MagicMock()
    sdk.models.generate_content.side_effect = RuntimeError("boom")
    c = GeminiClient(api_key="x", client=sdk)
    with pytest.raises(ClaudeUnavailableError):
        c.ask("s", "u")
