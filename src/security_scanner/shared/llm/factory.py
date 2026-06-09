"""LLM-provider factory for the two-channel scanner model.

Two build paths:

``build_user_llm_client(provider, api_key, model)``
    CLI / personal channel: the user's BYO key, decrypted from the DB by the
    handler before calling this function. This is the **only** path a
    developer's scan uses.

``build_org_llm_client_from_settings(org_row, provider_choice)``
    CI / org channel: the org's encrypted key, already decrypted by the
    handler. The scanner uses the org's key — the developer's key is never
    involved. This is the **only** path a CI scan uses.

``build_llm_client(settings)``
    Bootstrap fallback only: used during the very first run before an admin
    has saved org settings via the portal. Once ``org_settings`` has rows,
    this function is no longer called for CI scans.

DATA GOVERNANCE: §7.2/§8.3 confirm ZDR + DPA for **Anthropic only**.
Selecting ``google`` routes filtered source code to a provider without a
confirmed zero-retention agreement — a sim-only deviation (Appendix D-15),
off by default, loudly warned here.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from security_scanner.shared.llm.base import LLMConfigError
from security_scanner.shared.logging_util import get_logger

if TYPE_CHECKING:
    from security_scanner.shared.config import Settings
    from security_scanner.shared.llm.base import LLMClient
    from security_scanner.tokens.models import OrgSettings

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


def _make_claude(api_key: str, model: str | None) -> LLMClient:
    from security_scanner.shared.claude.client import ClaudeClient

    if model:
        return ClaudeClient(api_key=api_key, model=model)
    return ClaudeClient(api_key=api_key)


def _make_gemini(api_key: str, model: str | None) -> LLMClient:
    log.warning("llm_provider_override", provider="gemini", notice=_DATA_GOVERNANCE_WARNING)
    from security_scanner.shared.llm.gemini_client import (
        DEFAULT_MODEL as GEMINI_DEFAULT,
    )
    from security_scanner.shared.llm.gemini_client import (
        GeminiClient,
    )

    return GeminiClient(api_key=api_key, model=model or GEMINI_DEFAULT)


def build_user_llm_client(
    provider: str,
    api_key: str,
    model: str | None = None,
) -> LLMClient:
    """Build an LLM client from the user's stored BYO API key.

    The caller (``/scan/local`` handler) decrypts the key from
    ``user_llm_settings`` before passing it here.  This function never reads
    env vars or ``Settings`` — all config is explicit.

    Raises
    ------
    LLMConfigError
        Unknown provider or empty API key.
    """
    p = provider.strip().lower()
    if not api_key:
        raise LLMConfigError(
            f"Empty API key for provider={p!r}. Visit /portal/settings to update your key."
        )
    if p in ("anthropic", "claude"):
        return _make_claude(api_key, model)
    if p in ("google", "gemini"):
        return _make_gemini(api_key, model)
    raise LLMConfigError(
        f"Unknown provider={p!r} stored in user settings. Expected: anthropic | google."
    )


def _get_model_for_provider(
    org_row: OrgSettings | None,
    provider: str,
) -> str | None:
    """Return the admin-configured model for *provider* from *org_row*.

    Returns ``None`` when:
    - ``org_row`` is ``None`` (bootstrap window — no admin has saved settings yet)
    - The relevant per-provider column is empty / ``None``

    In both cases the caller should pass ``model=None`` to the LLM client,
    which falls back to the provider's own default (``CLAUDE_MODEL`` env var
    for Claude, ``GeminiClient.DEFAULT_MODEL`` for Gemini).
    """
    if org_row is None:
        return None
    p = provider.strip().lower()
    if p in ("anthropic", "claude"):
        return org_row.anthropic_model or None
    if p in ("google", "gemini"):
        return org_row.google_model or None
    return None


def build_org_llm_client_from_settings(
    org_row: OrgSettings,
    provider_choice: str | None = None,
    *,
    settings: Settings | None = None,
) -> LLMClient:
    """Build the org-channel LLM client from a decrypted ``OrgSettings`` row.

    ``provider_choice`` is the per-run CI override (e.g. workflow input
    ``provider: gemini``).  Falls back to ``org_row.default_provider`` when
    not specified.

    Model is read from the per-provider admin-set column (``anthropic_model``
    or ``google_model``).  ``None`` → provider uses its own default.

    The caller (``/agent/scan`` handler) decrypts the key before calling.
    This function receives plaintext keys — never stores or logs them.

    Raises
    ------
    LLMConfigError
        No key configured for the resolved provider.
    """
    from security_scanner.tokens.crypto import decrypt

    provider = (provider_choice or org_row.default_provider.value).strip().lower()
    model = _get_model_for_provider(org_row, provider)

    if provider in ("anthropic", "claude"):
        if not org_row.encrypted_anthropic_key:
            raise LLMConfigError(
                "CI scan requested Anthropic but no org Anthropic key is configured. "
                "Go to /admin/org-settings and save an ANTHROPIC_API_KEY."
            )
        key = decrypt(org_row.encrypted_anthropic_key)
        return _make_claude(key, model)

    if provider in ("google", "gemini"):
        if not org_row.encrypted_google_key:
            raise LLMConfigError(
                "CI scan requested Gemini but no org Google key is configured. "
                "Go to /admin/org-settings and save a GOOGLE_API_KEY."
            )
        key = decrypt(org_row.encrypted_google_key)
        return _make_gemini(key, model)

    raise LLMConfigError(
        f"Unknown provider={provider!r} in org_settings. Expected: anthropic | google."
    )


def build_llm_client(settings: Settings) -> LLMClient:
    """Bootstrap fallback: build from env vars when org_settings has no rows.

    This is the pre-two-channel code path kept alive only for the initial
    install window before an admin saves org settings via /admin/org-settings.
    Once org_settings is populated, CI uses ``build_org_llm_client_from_settings``
    instead.

    Raises
    ------
    LLMConfigError
        Unknown ``SCANNER_LLM_PROVIDER`` or the selected provider's API key
        is not set.
    """
    provider = (os.getenv("SCANNER_LLM_PROVIDER") or _DEFAULT_PROVIDER).strip().lower()
    model = os.getenv("SCANNER_LLM_MODEL") or None

    if provider in ("anthropic", "claude"):
        if not settings.ANTHROPIC_API_KEY:
            raise LLMConfigError("ANTHROPIC_API_KEY is not set (bootstrap fallback path).")
        return _make_claude(settings.ANTHROPIC_API_KEY, model)

    if provider in ("google", "gemini"):
        key = getattr(settings, "GOOGLE_API_KEY", None)
        if not key:
            raise LLMConfigError(
                "SCANNER_LLM_PROVIDER=google but GOOGLE_API_KEY is not set "
                "(bootstrap fallback path)."
            )
        return _make_gemini(key, model)

    raise LLMConfigError(
        f"Unknown SCANNER_LLM_PROVIDER={provider!r} (expected: anthropic | google)"
    )
