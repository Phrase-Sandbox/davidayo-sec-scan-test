"""Pre-scan secret stripping for the Security Vulnerability Scanner.

Implements BR-003 (§4.1) and EC-009 (§5): every source file destined for the
Claude API has its credentials redacted *before* the prompt is built. Per §12
"What NOT to Do" #1–2, raw secrets must never leave the codebase boundary and
must never appear in logs.

Two detection layers run on every file:

1. Explicit regex patterns for the six BR-003 minimum-coverage types
   (truffleHog-style entropy patterns + vendor-specific token shapes).
2. ``detect-secrets`` (Yelp) as the supplementary engine — catches credential
   formats the regex layer does not enumerate (e.g. SoftLayer, IBM Cloud).

Both layers redact in place with the literal string ``[SECRET REDACTED]``.
The original secret value is never logged.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from security_scanner.shared.logging_util import get_logger

log = get_logger(__name__)

REDACTED = "[SECRET REDACTED]"
HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR = 4.0
HIGH_ENTROPY_MIN_LENGTH = 20  # BR-003 type 1

# --- BR-003 type 4: PEM private keys (multi-line) ---------------------------
_PEM_PATTERN: re.Pattern[str] = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"
)

# --- BR-003 type 6: GitHub / Anthropic / AWS credential formats -------------
# GitHub PAT (ghp_), OAuth (gho_), user-to-server (ghu_), server-to-server (ghs_),
# refresh (ghr_). All are 36 chars after the prefix.
_GITHUB_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"\bgh[opsur]_[A-Za-z0-9]{36}\b")
# Fine-grained PATs: github_pat_<82 chars>
_GITHUB_PAT_PATTERN: re.Pattern[str] = re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")
# Anthropic: sk-ant-<prefix>-<key>
_ANTHROPIC_PATTERN: re.Pattern[str] = re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")
# AWS Access Key ID (AKIA = long-lived, ASIA = STS temporary)
_AWS_ACCESS_KEY_PATTERN: re.Pattern[str] = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")

# --- BR-003 type 2: OAuth tokens --------------------------------------------
# RFC 6750 Bearer scheme — replace the token, keep "Bearer" for context.
_BEARER_TOKEN_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)\bBearer\s+([A-Za-z0-9_\-.+/=]{20,})\b"
)
# Google OAuth access tokens always start with ya29.
_GOOGLE_OAUTH_PATTERN: re.Pattern[str] = re.compile(r"\bya29\.[A-Za-z0-9_\-.]{40,}\b")

# --- BR-003 type 3: JWTs (three base64url segments, first segment starts eyJ)
_JWT_PATTERN: re.Pattern[str] = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
)

# --- BR-003 type 5: password=, secret=, token=, api_key=, auth_token= -------
# Value-only redaction to keep the key/separator visible for the analysis model.
_CONFIG_SECRET_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)\b((?:password|passwd|secret|token|api[_\-]?key|auth[_\-]?token)\s*[:=]\s*)"
    r"(['\"]?)([^\s'\"]{4,})\2"
)

# --- BR-003 type 1: generic high-entropy strings ≥20 chars in quoted contexts
_QUOTED_STRING_PATTERN: re.Pattern[str] = re.compile(
    rf"(['\"])([A-Za-z0-9+/=_\-]{{{HIGH_ENTROPY_MIN_LENGTH},}})\1"
)


@dataclass
class SecretStripResult:
    cleaned_files: dict[str, str]
    secrets_found: bool
    affected_files: list[str]


def strip(files: dict[str, str]) -> SecretStripResult:
    """Redact secrets from every file in *files*.

    The original input dict is not mutated. For each file that contained at
    least one secret, exactly one log line is emitted to stdout in the form
    ``[secret stripped from file: <filename>]`` — the original secret value is
    **never** logged.
    """
    cleaned: dict[str, str] = {}
    affected: list[str] = []
    for filename, content in files.items():
        new_content, had_secret = _strip_one(content)
        cleaned[filename] = new_content
        if had_secret:
            affected.append(filename)
            log.info(f"[secret stripped from file: {filename}]", filename=filename)
    return SecretStripResult(
        cleaned_files=cleaned,
        secrets_found=bool(affected),
        affected_files=affected,
    )


def _strip_one(content: str) -> tuple[str, bool]:
    """Return ``(cleaned_content, had_secret)`` for a single file body."""
    original = content

    # PEM first — multi-line, mustn't be fragmented by later line-by-line work.
    content = _PEM_PATTERN.sub(REDACTED, content)

    # Specific high-precision token formats — replace the entire token.
    for pattern in (
        _GITHUB_PAT_PATTERN,  # longest GitHub format first
        _GITHUB_TOKEN_PATTERN,
        _ANTHROPIC_PATTERN,
        _AWS_ACCESS_KEY_PATTERN,
        _GOOGLE_OAUTH_PATTERN,
        _JWT_PATTERN,
    ):
        content = pattern.sub(REDACTED, content)

    # Bearer <token> — keep "Bearer" prefix, redact only the token value.
    content = _BEARER_TOKEN_PATTERN.sub(
        lambda m: m.group(0).replace(m.group(1), REDACTED), content
    )

    # password=/secret=/token=/api_key= — replace value, keep key and separator.
    content = _CONFIG_SECRET_PATTERN.sub(_redact_config_value, content)

    # Generic high-entropy quoted strings (truffleHog-style, length + Shannon).
    content = _QUOTED_STRING_PATTERN.sub(_redact_if_high_entropy, content)

    # Supplementary scan via detect-secrets — catches anything the regex layer
    # missed. Replace each found value literally; never log raw values.
    for value in _detect_secrets_values(content):
        if value and value != REDACTED:
            content = content.replace(value, REDACTED)

    return content, content != original


def _redact_config_value(m: re.Match[str]) -> str:
    prefix, quote, _value = m.group(1), m.group(2), m.group(3)
    return f"{prefix}{quote}{REDACTED}{quote}"


def _redact_if_high_entropy(m: re.Match[str]) -> str:
    quote, value = m.group(1), m.group(2)
    if _shannon_entropy(value) >= HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR:
        return f"{quote}{REDACTED}{quote}"
    return m.group(0)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _detect_secrets_values(content: str) -> list[str]:
    """Return secret string values found by detect-secrets; swallow library errors.

    detect-secrets is **supplementary** — the regex layer above is the
    authoritative safety net for the BR-003 minimum coverage list. Some
    default detect-secrets plugins (e.g. ``KeywordDetector``) emit short,
    common words as candidate secrets, which would otherwise overwrite
    benign content like ``hello world`` with ``[SECRET REDACTED]``.

    To prevent that, we apply the same length and entropy thresholds we use
    for our own truffleHog-style heuristic: a candidate must be ≥20 chars
    AND have Shannon entropy ≥4.0 bits/char before we redact it. The regex
    layer remains responsible for short structured tokens (e.g. ``AKIA…``).
    """
    try:
        from detect_secrets.core import scan
        from detect_secrets.settings import default_settings
    except ImportError:  # pragma: no cover — pinned dep, only triggers in broken installs
        return []

    values: list[str] = []
    try:
        with default_settings():
            for line in content.splitlines():
                for secret in scan.scan_line(line):
                    value = getattr(secret, "secret_value", None)
                    if not value or len(value) < HIGH_ENTROPY_MIN_LENGTH:
                        continue
                    if _shannon_entropy(value) < HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR:
                        continue
                    # URL/path fragments routinely have high entropy + length but
                    # are not secrets; skip them to avoid mangling URLs in source.
                    if "/" in value or "://" in value:
                        continue
                    values.append(value)
    except Exception:  # noqa: BLE001 — defensive: never let a lib bug break the scan
        return values
    return values
