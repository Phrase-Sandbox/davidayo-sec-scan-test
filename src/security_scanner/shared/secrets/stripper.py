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


@dataclass(frozen=True)
class SecretHit:
    """One credential occurrence found by the stripper.

    The hit carries enough trace context to verify a SECRET-001 finding
    without ever exposing the secret value itself. ``hint`` is up to 40
    chars of the line preceding the secret (e.g. ``"ANTHROPIC_API_KEY = "``)
    — a textual anchor a reviewer can grep for.
    """

    filename: str
    line: int            # 1-based start line of the secret
    end_line: int        # 1-based end line; equals ``line`` except for PEM blocks
    hint: str            # text on the same line, immediately before the secret
    detector: str        # which rule matched: pem, github_pat, anthropic, …


@dataclass
class SecretStripResult:
    cleaned_files: dict[str, str]
    secrets_found: bool
    affected_files: list[str]
    hits: list[SecretHit]


def strip(files: dict[str, str]) -> SecretStripResult:
    """Redact secrets from every file in *files*.

    The original input dict is not mutated. For each file that contained at
    least one secret, exactly one log line is emitted to stdout in the form
    ``[secret stripped from file: <filename>]`` — the original secret value is
    **never** logged.
    """
    cleaned: dict[str, str] = {}
    affected: list[str] = []
    all_hits: list[SecretHit] = []
    for filename, content in files.items():
        new_content, file_hits = _strip_one(content, filename)
        cleaned[filename] = new_content
        if file_hits:
            affected.append(filename)
            all_hits.extend(file_hits)
            log.info(f"[secret stripped from file: {filename}]", filename=filename)
    return SecretStripResult(
        cleaned_files=cleaned,
        secrets_found=bool(affected),
        affected_files=affected,
        hits=all_hits,
    )


def _strip_one(content: str, filename: str) -> tuple[str, list[SecretHit]]:
    """Return ``(cleaned_content, hits)`` for a single file body."""
    original = content
    # detect-secrets is the expensive layer; run it once on the original and
    # reuse the result for both location tracking and redaction.
    ds_values = _detect_secrets_values(original)
    hits = _scan_for_hits(original, filename, ds_values)

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

    # Supplementary detect-secrets redaction — uses values found above.
    for value in ds_values:
        if value and value != REDACTED:
            content = content.replace(value, REDACTED)

    return content, hits


def _line_at(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def _hint_before(content: str, offset: int, max_chars: int = 40) -> str:
    """Return up to ``max_chars`` of the line preceding ``offset``.

    Used as a non-sensitive anchor in SECRET-001 findings so a reviewer
    can locate the credential by context (e.g. the variable name) without
    the report ever including the secret value itself.
    """
    line_start = content.rfind("\n", 0, offset) + 1
    return content[line_start:offset][-max_chars:].rstrip()


def _scan_for_hits(
    content: str, filename: str, ds_values: list[str]
) -> list[SecretHit]:
    """Scan ORIGINAL file content and return location metadata for each secret.

    Scanning is done before any redaction so line numbers map to the source
    the user wrote. We never store the secret value — only its position and
    the surrounding non-sensitive prefix.
    """
    hits: list[SecretHit] = []

    def _record(start: int, end: int, detector: str) -> None:
        hits.append(
            SecretHit(
                filename=filename,
                line=_line_at(content, start),
                end_line=_line_at(content, end),
                hint=_hint_before(content, start),
                detector=detector,
            )
        )

    for m in _PEM_PATTERN.finditer(content):
        _record(m.start(), m.end(), "pem")

    for pattern, name in (
        (_GITHUB_PAT_PATTERN, "github_pat"),
        (_GITHUB_TOKEN_PATTERN, "github_token"),
        (_ANTHROPIC_PATTERN, "anthropic"),
        (_AWS_ACCESS_KEY_PATTERN, "aws_access_key"),
        (_GOOGLE_OAUTH_PATTERN, "google_oauth"),
        (_JWT_PATTERN, "jwt"),
    ):
        for m in pattern.finditer(content):
            _record(m.start(), m.end(), name)

    for m in _BEARER_TOKEN_PATTERN.finditer(content):
        _record(m.start(1), m.end(1), "bearer_token")

    for m in _CONFIG_SECRET_PATTERN.finditer(content):
        _record(m.start(3), m.end(3), "config_secret")

    for m in _QUOTED_STRING_PATTERN.finditer(content):
        if _shannon_entropy(m.group(2)) >= HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR:
            _record(m.start(2), m.end(2), "high_entropy")

    # detect-secrets supplementary — locate each value by literal search so
    # we still get a line number even though detect-secrets is opaque.
    for value in ds_values:
        if not value or value == REDACTED:
            continue
        idx = content.find(value)
        if idx != -1:
            _record(idx, idx + len(value), "detect_secrets")

    # Dedupe by (line, end_line): multiple regex layers commonly fire on the
    # same secret (e.g. a github_pat inside a config_secret assignment). One
    # finding per source location is what a reviewer actually wants.
    seen: set[tuple[int, int]] = set()
    deduped: list[SecretHit] = []
    for h in hits:
        key = (h.line, h.end_line)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)
    return deduped


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
