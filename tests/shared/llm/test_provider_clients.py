"""Gemini client with the SDK fully injected (D-15).

The live network path is **never** exercised (no keys in the simulation):
the real SDK is bypassed via the `client=` DI parameter. These prove prompt
wiring + shared parsing + error mapping only — exactly the honest limit
recorded in Appendix D-15.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from security_scanner.shared.claude.client import (
    ClaudeTimeoutError,
    ClaudeUnavailableError,
)
from security_scanner.shared.llm.gemini_client import GeminiClient


def _gemini_sdk(text: str) -> MagicMock:
    """Sync SDK mock — models.generate_content returns text."""
    sdk = MagicMock()
    sdk.models.generate_content.return_value = MagicMock(text=text)
    # Cache creation returns a mock with a .name attribute. NB: `name=` is a
    # reserved MagicMock kwarg that names the mock itself, not its `.name` attr —
    # set it explicitly after construction.
    cache_obj = MagicMock()
    cache_obj.name = "cachedContents/test-cache-123"
    sdk.caches.create.return_value = cache_obj
    return sdk


def _gemini_sdk_async(text: str) -> MagicMock:
    """Async SDK mock — aio.models.generate_content is an AsyncMock."""
    sdk = MagicMock()
    sdk.models.generate_content.return_value = MagicMock(text=text)
    cache_obj = MagicMock()
    cache_obj.name = "cachedContents/test-cache-123"
    sdk.caches.create.return_value = cache_obj
    # Wire the async surface.
    sdk.aio = MagicMock()
    sdk.aio.models = MagicMock()
    sdk.aio.models.generate_content = AsyncMock(return_value=MagicMock(text=text))
    return sdk


# --- Gemini sync -----------------------------------------------------------


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
    # Caches side-effect not needed: timeout happens in _complete before caching
    sdk.caches.create.side_effect = RuntimeError("cache unavailable")
    c = GeminiClient(api_key="x", client=sdk)
    with pytest.raises(ClaudeTimeoutError):
        c.ask("s", "u")


def test_gemini_unavailable_after_retries(monkeypatch):
    monkeypatch.setattr(
        "security_scanner.shared.llm.gemini_client.time.sleep", lambda *_: None
    )
    sdk = MagicMock()
    sdk.models.generate_content.side_effect = RuntimeError("boom")
    sdk.caches.create.side_effect = RuntimeError("cache unavailable")
    c = GeminiClient(api_key="x", client=sdk)
    with pytest.raises(ClaudeUnavailableError):
        c.ask("s", "u")


# --- Gemini async ----------------------------------------------------------


@pytest.mark.asyncio
async def test_gemini_analyse_async_parses_findings():
    sdk = _gemini_sdk_async('{"findings": []}')
    c = GeminiClient(api_key="x", client=sdk)
    result = await c.analyse_async({"a.py": "x = 1"})
    assert result == []
    sdk.aio.models.generate_content.assert_called_once()


@pytest.mark.asyncio
async def test_gemini_ask_async_returns_text():
    sdk = _gemini_sdk_async("VERDICT: yes")
    c = GeminiClient(api_key="x", client=sdk)
    result = await c.ask_async("sys", "usr")
    assert result == "VERDICT: yes"


@pytest.mark.asyncio
async def test_gemini_analyse_async_chunked_single_chunk():
    """Single-chunk fast path: no splitting, delegates to analyse_async."""
    sdk = _gemini_sdk_async('{"findings": []}')
    c = GeminiClient(api_key="x", client=sdk)
    findings, partial = await c.analyse_async_chunked({"a.py": "x = 1"}, chunk_size=10)
    assert findings == []
    assert partial == []


@pytest.mark.asyncio
async def test_gemini_analyse_async_chunked_multi_chunk():
    """Multi-chunk path splits files and gathers results."""
    sdk = _gemini_sdk_async('{"findings": []}')
    c = GeminiClient(api_key="x", client=sdk)
    files = {f"f{i}.py": "x = 1" for i in range(6)}
    findings, partial = await c.analyse_async_chunked(files, chunk_size=3)
    assert findings == []
    assert partial == []
    # Two chunks of 3 → 2 calls.
    assert sdk.aio.models.generate_content.call_count == 2


@pytest.mark.asyncio
async def test_gemini_analyse_async_chunked_timeout_marks_partial(monkeypatch):
    """A timed-out chunk's files appear in partial_files; others proceed."""
    monkeypatch.setattr(
        "security_scanner.shared.llm.gemini_client.asyncio.sleep",
        AsyncMock(),
    )
    sdk = MagicMock()
    sdk.caches.create.side_effect = RuntimeError("cache unavailable")
    call_n = {"i": 0}

    async def _side_effect(*_a, **_kw):
        call_n["i"] += 1
        if call_n["i"] == 1:
            raise ClaudeTimeoutError("timed out")
        return MagicMock(text='{"findings": []}')

    sdk.aio = MagicMock()
    sdk.aio.models = MagicMock()
    sdk.aio.models.generate_content = _side_effect

    c = GeminiClient(api_key="x", client=sdk)
    files = {"a.py": "x", "b.py": "y", "c.py": "z", "d.py": "w"}
    findings, partial = await c.analyse_async_chunked(files, chunk_size=2)

    # First chunk timed out → its files are partial.
    assert set(partial) == {"a.py", "b.py"}
    assert findings == []


# --- Gemini context caching ------------------------------------------------


def test_gemini_cache_creation_is_attempted():
    """_get_or_create_cache calls caches.create and stores the name."""
    sdk = _gemini_sdk("ok")
    c = GeminiClient(api_key="x", client=sdk)
    cache_name = c._get_or_create_cache()
    assert cache_name == "cachedContents/test-cache-123"
    sdk.caches.create.assert_called_once()


def test_gemini_cache_creation_failure_is_tolerated():
    """If caches.create raises, _get_or_create_cache returns None (graceful)."""
    sdk = MagicMock()
    sdk.caches.create.side_effect = RuntimeError("min-token threshold not met")
    c = GeminiClient(api_key="x", client=sdk)
    cache_name = c._get_or_create_cache()
    assert cache_name is None


def test_gemini_cache_is_reused_within_ttl():
    """The second call reuses the cached name without calling caches.create again."""
    sdk = _gemini_sdk("ok")
    c = GeminiClient(api_key="x", client=sdk)
    name1 = c._get_or_create_cache()
    name2 = c._get_or_create_cache()
    assert name1 == name2
    sdk.caches.create.assert_called_once()  # only one create call


def test_gemini_complete_uses_cache_when_available():
    """_complete passes cached_content when cache is available."""
    sdk = _gemini_sdk("VERDICT: ok")
    c = GeminiClient(api_key="x", client=sdk)
    c._complete("sys", "usr")
    config = sdk.models.generate_content.call_args.kwargs.get("config", {})
    assert "cached_content" in config
    assert config["cached_content"] == "cachedContents/test-cache-123"


def test_gemini_complete_falls_back_when_cache_unavailable():
    """_complete uses system_instruction when no cache is available."""
    sdk = MagicMock()
    sdk.caches.create.side_effect = RuntimeError("unavailable")
    sdk.models.generate_content.return_value = MagicMock(text="ok")
    c = GeminiClient(api_key="x", client=sdk)
    result = c._complete("sys", "usr")
    assert result == "ok"
    call_kwargs = sdk.models.generate_content.call_args
    config = call_kwargs.kwargs.get("config") or {}
    assert "system_instruction" in config
