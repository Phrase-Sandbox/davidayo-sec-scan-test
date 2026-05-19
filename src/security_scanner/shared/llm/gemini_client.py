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

    # --- Internals ----------------------------------------------------------

    def _complete(self, system_prompt: str, user_message: str) -> str:
        last: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            try:
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
