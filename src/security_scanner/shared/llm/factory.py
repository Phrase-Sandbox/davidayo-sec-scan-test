"""Env-selected LLM-provider factory (Appendix D-15 — DEVIATION).

``build_llm_client(settings)`` returns the provider-specific client the
pipeline uses. Selection mirrors the existing ``CLAUDE_*`` override pattern
(client.py): an **env var, defaulting to Anthropic**, so when nothing is set
production / Phrase behaviour is byte-identical to before this change.

    SCANNER_LLM_PROVIDER   anthropic (default) | google|gemini
    SCANNER_LLM_MODEL      optional model override for the chosen provider

DATA GOVERNANCE: §7.2/§8.3 confirm ZDR + DPA for **Anthropic only**.
Selecting another provider routes filtered source code to a provider without
a confirmed zero-retention agreement — a sim-only deviation, off by default,
loudly warned here, pending Security/Legal sign-off.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from security_scanner.shared.llm.base import LLMConfigError
from security_scanner.shared.logging_util import get_logger

if TYPE_CHECKING:  # avoid import cycles / heavy imports at module load
    from security_scanner.shared.config import Settings
    from security_scanner.shared.llm.base import LLMClient

log = get_logger(__name__)

_DEFAULT_PROVIDER = "anthropic"
_DATA_GOVERNANCE_WARNING = (
    "NON-ANTHROPIC LLM PROVIDER SELECTED — DATA GOVERNANCE: the ZDR + DPA "
    "guarantees in spec §7.2/§8.3 are confirmed for Anthropic ONLY. Filtered "
    "source code will be sent to a provider WITHOUT a confirmed "
    "zero-retention agreement. This is a sim-only deviation (Appendix D-15), "
    "off by default, pending Security/Legal sign-off. Production is "
    "unaffected (default provider is anthropic)."
)


def build_llm_client(settings: Settings) -> LLMClient:
    """Build the LLM client for the configured provider (default Anthropic).

    Raises
    ------
    LLMConfigError
        Unknown ``SCANNER_LLM_PROVIDER`` or the selected provider's API key
        is not set. A fail-fast config fault — raised before any client is
        constructed, so a misconfiguration never silently falls back.
    """
    provider = (os.getenv("SCANNER_LLM_PROVIDER") or _DEFAULT_PROVIDER).strip().lower()
    model = os.getenv("SCANNER_LLM_MODEL") or None

    if provider in ("anthropic", "claude"):
        # Default path — unchanged. Only pass model when explicitly set so the
        # existing CLAUDE_MODEL / spec-default behaviour in client.py is kept.
        from security_scanner.shared.claude.client import ClaudeClient

        if model:
            return ClaudeClient(api_key=settings.ANTHROPIC_API_KEY, model=model)
        return ClaudeClient(api_key=settings.ANTHROPIC_API_KEY)

    # Any non-Anthropic provider is the D-15 data-governance deviation.
    log.warning("llm_provider_override", provider=provider, notice=_DATA_GOVERNANCE_WARNING)

    if provider in ("google", "gemini"):
        key = getattr(settings, "GOOGLE_API_KEY", None)
        if not key:
            raise LLMConfigError(
                "SCANNER_LLM_PROVIDER=google but GOOGLE_API_KEY is not set"
            )
        from security_scanner.shared.llm.gemini_client import (
            DEFAULT_MODEL as GEMINI_DEFAULT,
        )
        from security_scanner.shared.llm.gemini_client import GeminiClient

        return GeminiClient(api_key=key, model=model or GEMINI_DEFAULT)

    raise LLMConfigError(
        f"Unknown SCANNER_LLM_PROVIDER={provider!r} "
        "(expected: anthropic | google)"
    )


def build_local_llm_client(
    provider: str,
    api_key: str,
    model: str | None = None,
) -> LLMClient:
    """Build an LLM client from explicit args (CLI BYO path).

    Unlike ``build_llm_client`` this helper does **not** read env vars or
    ``Settings`` — the caller has already resolved provider/model/key from
    the CLI flag → env → config → default resolution chain.

    Raises
    ------
    LLMConfigError
        Unknown provider or missing API key.
    """
    provider = provider.strip().lower()

    if provider in ("anthropic", "claude"):
        if not api_key:
            raise LLMConfigError(
                "ANTHROPIC_API_KEY is required for --local mode with Claude. "
                "Set the env var, pass --api-key, or add it to your config."
            )
        from security_scanner.shared.claude.client import ClaudeClient

        if model:
            return ClaudeClient(api_key=api_key, model=model)
        return ClaudeClient(api_key=api_key)

    if provider in ("google", "gemini"):
        if not api_key:
            raise LLMConfigError(
                "GOOGLE_API_KEY is required for --local mode with Gemini. "
                "Set the env var, pass --api-key, or add it to your config."
            )
        log.warning("llm_provider_override", provider=provider, notice=_DATA_GOVERNANCE_WARNING)
        from security_scanner.shared.llm.gemini_client import (
            DEFAULT_MODEL as GEMINI_DEFAULT,
        )
        from security_scanner.shared.llm.gemini_client import GeminiClient

        return GeminiClient(api_key=api_key, model=model or GEMINI_DEFAULT)

    raise LLMConfigError(
        f"Unknown provider={provider!r} — expected: claude | gemini"
    )
