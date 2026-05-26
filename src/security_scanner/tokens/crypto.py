"""Fernet-backed encryption for at-rest secrets (user + org LLM API keys).

The key lives in ``SCANNER_ENCRYPTION_KEY`` (urlsafe-b64, 32 bytes). It is
distinct from the LLM API keys it protects: rotating one does not require
rotating the other. To rotate the Fernet key itself, decrypt every row
with the old key, re-encrypt with the new key, then swap the env var. The
procedure is documented in devci-readme.md.

This module is intentionally tiny: a single Fernet instance per process,
constructed once from settings, plus typed encrypt/decrypt helpers and a
startup validator.
"""

from __future__ import annotations

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from security_scanner.shared.config import Settings, get_settings


class EncryptionKeyMissing(RuntimeError):
    """Raised when at-rest encryption is required but no key is configured."""


class EncryptionKeyInvalid(RuntimeError):
    """Raised when ``SCANNER_ENCRYPTION_KEY`` is set but unusable as a Fernet key."""


@lru_cache(maxsize=1)
def _fernet_for(key: str) -> Fernet:
    # lru_cache keys on the raw string so a rotation that changes the env
    # var produces a different cache slot, not stale state.
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise EncryptionKeyInvalid(
            "SCANNER_ENCRYPTION_KEY is set but is not a valid Fernet key "
            "(must be urlsafe-base64-encoded 32 bytes). Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        ) from exc


def _resolve_key(settings: Settings | None) -> str:
    s = settings or get_settings()
    if not s.SCANNER_ENCRYPTION_KEY:
        raise EncryptionKeyMissing(
            "SCANNER_ENCRYPTION_KEY is not configured. The scanner cannot "
            "encrypt or decrypt stored API keys. Set it and restart."
        )
    return s.SCANNER_ENCRYPTION_KEY


def encrypt(plaintext: str, *, settings: Settings | None = None) -> bytes:
    """Encrypt a UTF-8 string into a Fernet ciphertext blob."""
    fernet = _fernet_for(_resolve_key(settings))
    return fernet.encrypt(plaintext.encode("utf-8"))


def decrypt(ciphertext: bytes, *, settings: Settings | None = None) -> str:
    """Decrypt a Fernet blob produced by :func:`encrypt`.

    Raises :class:`InvalidToken` if the ciphertext is tampered with or was
    encrypted under a different key (e.g. mid-rotation).
    """
    fernet = _fernet_for(_resolve_key(settings))
    return fernet.decrypt(ciphertext).decode("utf-8")


def validate_startup_key(settings: Settings) -> None:
    """Fail-fast startup probe.

    If ``SCANNER_ENCRYPTION_KEY`` is set, construct the Fernet once to
    surface a malformed key as a clear startup error rather than the first
    encrypt/decrypt call after traffic arrives.

    Whether the key is *required* is decided by the caller — startup may
    choose to allow ``None`` during a migration window. Here we only
    validate the value when it is present.
    """
    if settings.SCANNER_ENCRYPTION_KEY:
        _fernet_for(settings.SCANNER_ENCRYPTION_KEY)


def mask_for_display(secret: str, *, keep: int = 4) -> str:
    """Render a secret as ``sk-…last4`` for safe UI display.

    Never used on log output (that path goes through the redact filter);
    only for portal/admin pages that intentionally surface the tail.
    """
    if len(secret) <= keep:
        return "…" * keep
    return f"…{secret[-keep:]}"


InvalidToken = InvalidToken  # re-export for callers that catch it
