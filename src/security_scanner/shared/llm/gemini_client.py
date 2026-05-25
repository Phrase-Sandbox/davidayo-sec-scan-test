"""Google Gemini provider client (Appendix D-15 — DEVIATION, sim-only).

Same ``LLMClient`` surface as ``ClaudeClient`` using the ``google-genai``
SDK, reusing the spec-hardened prompts + shared findings parser.

HONEST LIMITS: real code, **never run
against a live Gemini API** (no key), only unit-tested with the SDK
injected/mocked; Claude-tuned prompt may need adjustment; minimal
resilience; transport/parse failures raise the existing ``Claude*`` types
the pipeline already handles; DATA GOVERNANCE: ZDR/DPA confirmed for
Anthropic only, off by default, pending Security/Legal sign-off.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from security_scanner.shared.claude.client import (
    ClaudeResponseError,
    ClaudeTimeoutError,
    ClaudeUnavailableError,
)
from security_scanner.shared.llm.parsing import parse_findings
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.prompts.system import (
    build_system_prompt,
    build_user_message,
)

log = get_logger(__name__)

DEFAULT_MODEL = "gemini-2.5-pro"
DEFAULT_MAX_TOKENS = 4096
DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_ATTEMPTS = 2
BACKOFF_SECONDS = 2.0

# Read chunk size from LLM_CHUNK_SIZE (provider-agnostic) or fall back to
# CLAUDE_CHUNK_SIZE (backward-compat alias) or default 12.
_LLM_CHUNK_SIZE = int(
    os.environ.get("LLM_CHUNK_SIZE")
    or os.environ.get("CLAUDE_CHUNK_SIZE")
    or "12"
)

# Context-cache TTL: 5 minutes, matching Claude's ephemeral cache window.
_CACHE_TTL = "300s"


class GeminiClient:
    """Google Gemini client conforming to the ``LLMClient`` seam."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: Any | None = None,
    ) -> None:
        self._model = model
        self._max_tokens = max_tokens
        self._timeout = timeout
        # _cache_name is set on the first successful cache creation and
        # reused for subsequent calls within the 5-minute TTL window.
        self._cache_name: str | None = None
        self._cache_created_at: float = 0.0
        if client is not None:
            # Injected (tests) — the real SDK is never imported.
            self._client = client
        else:  # pragma: no cover - requires the optional `google-genai` extra + a key
            from google import genai

            self._client = genai.Client(api_key=api_key)

    # --- Public API (LLMClient) --------------------------------------------

    def analyse(self, files: dict[str, str]) -> list[dict]:
        text = self._complete(build_system_prompt(), build_user_message(files))
        return parse_findings(text, error_cls=ClaudeResponseError)

    def ask(self, system_prompt: str, user_message: str) -> str:
        return self._complete(system_prompt, user_message)

    # --- Async API ----------------------------------------------------------

    async def analyse_async(self, files: dict[str, str]) -> list[dict]:
        """Native async analysis — uses ``google-genai`` async surface."""
        text = await self._complete_async(
            build_system_prompt(), build_user_message(files)
        )
        return parse_findings(text, error_cls=ClaudeResponseError)

    async def ask_async(self, system: str, user: str) -> str:
        """Native async ask — uses ``google-genai`` async surface."""
        return await self._complete_async(system, user)

    async def analyse_async_chunked(
        self,
        files: dict[str, str],
        chunk_size: int = _LLM_CHUNK_SIZE,
    ) -> tuple[list[dict], list[str]]:
        """Split ``files`` into chunks and run ``analyse_async`` on each in parallel.

        Mirrors ``ClaudeClient.analyse_async_chunked`` — same return shape,
        same timeout-tolerance behaviour.

        Returns ``(raw_findings, partial_files)`` where ``partial_files`` are
        the names of files from any chunk that timed out (the caller marks
        those as unscanned).
        """
        effective_chunk_size = max(1, chunk_size) if chunk_size > 0 else len(files)

        # Fast path: everything fits in a single chunk.
        if len(files) <= effective_chunk_size:
            return await self.analyse_async(files), []

        items = list(files.items())
        chunks: list[dict[str, str]] = [
            dict(items[i : i + effective_chunk_size])
            for i in range(0, len(items), effective_chunk_size)
        ]

        log.info(
            "gemini chunked analysis start",
            total_files=len(files),
            chunk_count=len(chunks),
            chunk_size=effective_chunk_size,
        )

        tasks = [
            asyncio.create_task(self.analyse_async(chunk)) for chunk in chunks
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_findings: list[dict] = []
        partial_files: list[str] = []

        for chunk, result in zip(chunks, results):
            if isinstance(result, ClaudeTimeoutError):
                log.warning(
                    "gemini chunk timeout — files marked partial",
                    file_count=len(chunk),
                    reason=str(result),
                )
                partial_files.extend(chunk.keys())
            elif isinstance(result, Exception):
                raise result
            else:
                raw_findings.extend(result)

        log.info(
            "gemini chunked analysis complete",
            total_findings=len(raw_findings),
            partial_file_count=len(partial_files),
        )
        return raw_findings, partial_files

    # --- Context caching ----------------------------------------------------

    def _get_or_create_cache(self) -> str | None:
        """Attempt to obtain a Gemini context-cache name for the system prompt.

        Returns the cache name on success, ``None`` if caching is unsupported
        (e.g. content below the minimum-token threshold) or unavailable.
        This is **best-effort** — a failure here must never break the scan.
        """
        now = time.monotonic()
        # Reuse an existing cache if still within its TTL window.
        if self._cache_name and (now - self._cache_created_at) < 295:
            return self._cache_name

        try:
            cache = self._client.caches.create(
                model=self._model,
                config={
                    "system_instruction": build_system_prompt(),
                    "ttl": _CACHE_TTL,
                },
            )
            self._cache_name = cache.name
            self._cache_created_at = now
            log.info("gemini context cache created", cache_name=cache.name)
            return self._cache_name
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "gemini context cache unavailable — proceeding without caching",
                reason=str(exc),
            )
            self._cache_name = None
            return None

    # --- Internals ----------------------------------------------------------

    def _complete(self, system_prompt: str, user_message: str) -> str:
        last: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                # Try to use context caching for the system prompt.
                cache_name = self._get_or_create_cache()
                if cache_name:
                    resp = self._client.models.generate_content(
                        model=self._model,
                        contents=user_message,
                        config={
                            "cached_content": cache_name,
                            "max_output_tokens": self._max_tokens,
                        },
                    )
                else:
                    resp = self._client.models.generate_content(
                        model=self._model,
                        contents=user_message,
                        config={
                            "system_instruction": system_prompt,
                            "max_output_tokens": self._max_tokens,
                        },
                    )
            except Exception as exc:  # noqa: BLE001 - SDK error taxonomy varies
                last = exc
                if "timeout" in type(exc).__name__.lower():
                    raise ClaudeTimeoutError(
                        f"Gemini request exceeded {self._timeout}s timeout"
                    ) from exc
                log.warning(
                    "gemini call failed", model=self._model, attempt=attempt
                )
                if attempt + 1 < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_SECONDS)
                continue
            return getattr(resp, "text", "") or ""
        raise ClaudeUnavailableError(
            f"Gemini unavailable after {MAX_ATTEMPTS} attempts: {last!r}"
        )

    async def _complete_async(self, system_prompt: str, user_message: str) -> str:
        """Native async completion using ``google-genai``'s ``aio`` surface."""
        last: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
                # Try to use context caching for the system prompt.
                cache_name = self._get_or_create_cache()
                if cache_name:
                    resp = await self._client.aio.models.generate_content(
                        model=self._model,
                        contents=user_message,
                        config={
                            "cached_content": cache_name,
                            "max_output_tokens": self._max_tokens,
                        },
                    )
                else:
                    resp = await self._client.aio.models.generate_content(
                        model=self._model,
                        contents=user_message,
                        config={
                            "system_instruction": system_prompt,
                            "max_output_tokens": self._max_tokens,
                        },
                    )
            except Exception as exc:  # noqa: BLE001 - SDK error taxonomy varies
                last = exc
                if "timeout" in type(exc).__name__.lower():
                    raise ClaudeTimeoutError(
                        f"Gemini request exceeded {self._timeout}s timeout"
                    ) from exc
                log.warning(
                    "gemini async call failed", model=self._model, attempt=attempt
                )
                if attempt + 1 < MAX_ATTEMPTS:
                    await asyncio.sleep(BACKOFF_SECONDS)
                continue
            return getattr(resp, "text", "") or ""
        raise ClaudeUnavailableError(
            f"Gemini unavailable after {MAX_ATTEMPTS} attempts: {last!r}"
        )
