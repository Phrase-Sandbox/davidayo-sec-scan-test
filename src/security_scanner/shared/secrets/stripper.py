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

import contextlib
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
# Slack incoming-webhook URLs. The trailing token segment is the credential —
# anyone with the URL can post into the linked Slack channel. The URL filter
# in ``_detect_secrets_values`` drops these (no Basic-Auth segment) and
# ``detect-secrets`` has no Slack-webhook plugin, so a dedicated Layer-1
# regex is the only way to surface them.
_SLACK_WEBHOOK_PATTERN: re.Pattern[str] = re.compile(
    r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}\b"
)

# --- BR-003 type 2: OAuth tokens --------------------------------------------
# RFC 6750 Bearer scheme — replace the token, keep "Bearer" for context.
_BEARER_TOKEN_PATTERN: re.Pattern[str] = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-.+/=]{20,})\b")
# Google OAuth access tokens always start with ya29.
_GOOGLE_OAUTH_PATTERN: re.Pattern[str] = re.compile(r"\bya29\.[A-Za-z0-9_\-.]{40,}\b")

# --- BR-003 type 3: JWTs (three base64url segments, first segment starts eyJ)
_JWT_PATTERN: re.Pattern[str] = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
)

# --- BR-003 type 5: password=, secret=, token=, api_key=, auth_token= -------
# Value-only redaction to keep the key/separator visible for the analysis model.
# Two alternation arms:
#   1. lowercase keyword vocabulary (case-insensitive via (?i))
#   2. ALL_CAPS env-var shapes ending in _KEY/_TOKEN/_SECRET/_PASSWORD/_PWD
#      (e.g. STRIPE_KEY, DB_PASSWORD, JWT_SECRET) — not covered by arm 1
#      because the keyword has to appear as a whole word.
_CONFIG_SECRET_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)\b((?:"
    r"password|passwd|pwd|pass|secret|token|api[_\-]?key|auth[_\-]?token"
    r"|private[_\-]?key|client[_\-]?secret|access[_\-]?key|credential|bearer"
    r"|[A-Z][A-Z0-9]*_(?:KEY|TOKEN|SECRET|PASSWORD|PWD)"
    r")\s*[:=]\s*)"
    # ``.`` is allowed in the value class so dotted vendor tokens (SendGrid
    # ``SG.xxx.yyy``, Mailchimp ``xxx-us1``, JWT ``a.b.c``) match. Python
    # expression FPs like ``token = obj.attr`` are still filtered by the
    # entropy gate in ``_scan_for_hits`` for unquoted code-file values.
    r"(['\"]?)([^\s'\"()\[\]{},+]{4,})\2"
)

# --- BR-003 type 1: generic high-entropy strings ≥20 chars in quoted contexts
_QUOTED_STRING_PATTERN: re.Pattern[str] = re.compile(
    rf"(['\"])([A-Za-z0-9+/=_\-]{{{HIGH_ENTROPY_MIN_LENGTH},}})\1"
)

# --- SQL fixture credentials -------------------------------------------------
# Matches ``password='hunter2'``, ``md5('hunter2')``, ``crypt('pw')`` —
# shapes where the credential is a quoted argument rather than a
# ``keyword = value`` assignment. Constrained to ``.sql`` files in the
# call sites below to avoid FP explosion on every quoted short string in
# code files.
_SQL_CREDENTIAL_LITERAL_PATTERN: re.Pattern[str] = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|md5|sha1|sha256|crypt|hash)"
    r"\s*[(=]\s*['\"]([^'\"]{1,128})['\"]"
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
    line: int  # 1-based start line of the secret
    end_line: int  # 1-based end line; equals ``line`` except for PEM blocks
    hint: str  # text on the same line, immediately before the secret
    detector: str  # which rule matched: pem, github_pat, anthropic, …


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
    # Initialise detect-secrets settings once for the entire batch.
    # Calling default_settings() per file (500× on a large repo) costs ~22 ms
    # each and breaks the §10 NFR.  A single context here satisfies BR-003
    # while keeping strip() well under 10 s for 500-file repos.
    try:
        from detect_secrets.settings import default_settings

        _ctx: contextlib.AbstractContextManager = default_settings()
        _ds_ready = True
    except ImportError:
        _ctx = contextlib.nullcontext()
        _ds_ready = False

    cleaned: dict[str, str] = {}
    affected: list[str] = []
    all_hits: list[SecretHit] = []
    with _ctx:
        for filename, content in files.items():
            new_content, file_hits = _strip_one(content, filename, _ds_initialized=_ds_ready)
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


def _credential_shaped(value: str) -> bool:
    """Real API keys/tokens almost always contain BOTH lowercase letters AND digits.

    English prose ("Local-dev bypass"), Python ALL_CAPS constants
    (``HTTP_401_UNAUTHORIZED``), and qualified identifiers (``received_token``)
    all fail this check — and they are the dominant FP shapes in detect-secrets
    matches against source files. Real credentials forgotten in a comment
    (``# leftover: sk_test_4eC39HqLyjWDarjtT1zdp7dc``) still satisfy it.
    """
    has_lower = any(c.islower() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_lower and has_digit


def _strip_one(
    content: str, filename: str, _ds_initialized: bool = False
) -> tuple[str, list[SecretHit]]:
    """Return ``(cleaned_content, hits)`` for a single file body."""
    original = content
    # detect-secrets is the expensive layer; run it once on the original and
    # reuse the result for both location tracking and redaction.
    ds_values = _detect_secrets_values(original, _initialized=_ds_initialized)
    # In code files, restrict detect-secrets matches to credential-shaped
    # values. Config files keep the permissive behavior — any high-entropy
    # value in `.env` / `.yaml` / `.ini` is meaningful.
    if _is_code_file(filename):
        ds_values = [v for v in ds_values if _credential_shaped(v)]
    hits = _scan_for_hits(original, filename, ds_values)

    # PEM first — multi-line, mustn't be fragmented by later line-by-line work.
    content = _PEM_PATTERN.sub(REDACTED, content)

    # Specific high-precision token formats — replace the entire token.
    for pattern in (
        _GITHUB_PAT_PATTERN,  # longest GitHub format first
        _GITHUB_TOKEN_PATTERN,
        _ANTHROPIC_PATTERN,
        _AWS_ACCESS_KEY_PATTERN,
        _SLACK_WEBHOOK_PATTERN,
        _GOOGLE_OAUTH_PATTERN,
        _JWT_PATTERN,
    ):
        content = pattern.sub(REDACTED, content)

    # Bearer <token> — keep "Bearer" prefix, redact only the token value.
    content = _BEARER_TOKEN_PATTERN.sub(lambda m: m.group(0).replace(m.group(1), REDACTED), content)

    # password=/secret=/token=/api_key= — replace value, keep key and separator.
    content = _CONFIG_SECRET_PATTERN.sub(_make_redact_config_value(filename), content)

    # SQL fixture credentials — quoted arguments next to password columns
    # or md5()/crypt() calls. Scoped to .sql to avoid FP explosion.
    if filename.lower().endswith(".sql"):
        content = _SQL_CREDENTIAL_LITERAL_PATTERN.sub(_redact_sql_literal, content)

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


def _scan_for_hits(content: str, filename: str, ds_values: list[str]) -> list[SecretHit]:
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
        (_SLACK_WEBHOOK_PATTERN, "slack_webhook"),
        (_GOOGLE_OAUTH_PATTERN, "google_oauth"),
        (_JWT_PATTERN, "jwt"),
    ):
        for m in pattern.finditer(content):
            _record(m.start(), m.end(), name)

    for m in _BEARER_TOKEN_PATTERN.finditer(content):
        _record(m.start(1), m.end(1), "bearer_token")

    for m in _CONFIG_SECRET_PATTERN.finditer(content):
        quote, value = m.group(2), m.group(3)
        if (
            _is_code_file(filename)
            and not quote
            and _shannon_entropy(value) < HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR
        ):
            continue
        _record(m.start(3), m.end(3), "config_secret")

    if filename.lower().endswith(".sql"):
        for m in _SQL_CREDENTIAL_LITERAL_PATTERN.finditer(content):
            _record(m.start(2), m.end(2), "sql_credential")

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


# Source-code extensions where an unquoted `token = something` is almost
# always a variable reference, not a config-style credential assignment.
# For these we apply an extra entropy gate to suppress FPs. Other extensions
# (.env, .yaml, .ini, .cfg, .toml, .properties, anything unknown) keep the
# permissive behavior where any `key=value` is treated as a credential.
_CODE_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".rb"}
)


def _is_code_file(filename: str) -> bool:
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in _CODE_FILE_EXTENSIONS)


# Committed template files (``.env.example``, ``.env.local.example``,
# ``.tmpl``, ``.dist``) exist to teach a hardcoding *shape* with placeholder
# values. They get special handling in the verifier: Layer-1 vendor matches
# are not auto-verified (so a real key accidentally pasted into a template
# is still caught), and structural-placeholder matches are downgraded to
# Medium with a 1Password-policy advisory rather than reported as Critical.
_TEMPLATE_FILE_SUFFIXES: frozenset[str] = frozenset(
    {".example", ".sample", ".template", ".tmpl", ".dist"}
)


def _is_template_file(filename: str) -> bool:
    """True iff ``filename`` ends with a committed-template suffix.

    Covers ``.env.example``, ``.env.local.example``, ``config.yaml.sample``,
    ``docker-compose.template``, ``app.config.tmpl``, ``Makefile.dist`` etc.
    """
    lower = filename.lower()
    return any(lower.endswith(suffix) for suffix in _TEMPLATE_FILE_SUFFIXES)


def _make_redact_config_value(filename: str):
    """Closure-based redactor so we can consult the filename in the callback."""

    def _redact(m: re.Match[str]) -> str:
        prefix, quote, value = m.group(1), m.group(2), m.group(3)
        # In source code, an unquoted `token = X` is overwhelmingly a variable
        # reference. Only treat it as a credential if the value is high-entropy.
        if (
            _is_code_file(filename)
            and not quote
            and _shannon_entropy(value) < HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR
        ):
            return m.group(0)
        return f"{prefix}{quote}{REDACTED}{quote}"

    return _redact


def _redact_sql_literal(m: re.Match[str]) -> str:
    """Replace the quoted value while preserving the SQL function/column context."""
    full = m.group(0)
    value = m.group(2)
    return full.replace(value, REDACTED, 1)


def _redact_if_high_entropy(m: re.Match[str]) -> str:
    quote, value = m.group(1), m.group(2)
    if _shannon_entropy(value) >= HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR:
        return f"{quote}{REDACTED}{quote}"
    return m.group(0)


_BASIC_AUTH_URL_RE: re.Pattern[str] = re.compile(
    r"://[^@/\s]+:[^@/\s]+@",
    re.IGNORECASE,
)


def _is_plain_url_or_path(value: str) -> bool:
    """True iff *value* should be dropped as a URL/path false positive.

    The original blanket filter dropped anything containing ``/`` or ``://``,
    which also discarded genuine Basic-Auth URLs like
    ``postgres://user:pw@host``. This version keeps that suppression for
    plain URLs, paths, and URL substrings returned by ``detect-secrets``,
    but carves out an exception: a value containing a
    ``scheme://user:pw@`` authority segment is a real credential and is
    NOT treated as a URL FP.
    """
    if _BASIC_AUTH_URL_RE.search(value):
        return False
    return "/" in value


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _detect_secrets_values(content: str, _initialized: bool = False) -> list[str]:
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

    ``_initialized=True`` signals that the caller already holds a
    ``default_settings()`` context, so this function skips re-initialisation
    (which is ~22 ms per call and untenable for 500-file repos).
    """
    try:
        from detect_secrets.core import scan
        from detect_secrets.settings import default_settings
    except ImportError:  # pragma: no cover — pinned dep, only triggers in broken installs
        return []

    _ctx: contextlib.AbstractContextManager = (
        contextlib.nullcontext() if _initialized else default_settings()
    )

    values: list[str] = []
    try:
        with _ctx:
            for line in content.splitlines():
                for secret in scan.scan_line(line):
                    value = getattr(secret, "secret_value", None)
                    if not value:
                        continue
                    # Basic-Auth credentials are short by nature
                    # (``postgres://user:pw@host``). Skip the length/entropy
                    # gates and the URL filter for this high-precision plugin.
                    if getattr(secret, "type", "") == "Basic Auth Credentials":
                        values.append(value)
                        continue
                    if len(value) < HIGH_ENTROPY_MIN_LENGTH:
                        continue
                    if _shannon_entropy(value) < HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR:
                        continue
                    # Plain URLs and filesystem paths are common high-entropy
                    # FPs from the generic detect-secrets plugins; drop them.
                    if _is_plain_url_or_path(value):
                        continue
                    values.append(value)
    except Exception:  # noqa: BLE001 — defensive: never let a lib bug break the scan
        return values
    return values
