"""Unit tests for crypto.py — encrypt_report / decrypt_report."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from security_scanner.tokens.crypto import (
    EncryptionKeyMissing,
    decrypt_report,
    encrypt_report,
)


@pytest.fixture()
def key() -> str:
    return Fernet.generate_key().decode()


def _settings(key_value: str | None):
    """Minimal settings stub used to inject the key without env mutation."""
    from unittest.mock import MagicMock

    s = MagicMock()
    s.SCANNER_ENCRYPTION_KEY = key_value
    return s


class TestEncryptReport:
    def test_round_trip(self, key: str) -> None:
        s = _settings(key)
        ciphertext = encrypt_report("hello world", settings=s)
        assert ciphertext != "hello world"
        assert decrypt_report(ciphertext, settings=s) == "hello world"

    def test_no_key_returns_plaintext(self) -> None:
        s = _settings(None)
        result = encrypt_report("plain", settings=s)
        assert result == "plain"

    def test_produces_fernet_prefix(self, key: str) -> None:
        s = _settings(key)
        assert encrypt_report("data", settings=s).startswith("gAAAAA")

    def test_html_round_trip(self, key: str) -> None:
        html = "<!DOCTYPE html><html><body><p>report</p></body></html>"
        s = _settings(key)
        assert decrypt_report(encrypt_report(html, settings=s), settings=s) == html


class TestDecryptReport:
    def test_none_returns_none(self, key: str) -> None:
        assert decrypt_report(None, settings=_settings(key)) is None

    def test_legacy_plaintext_returned_unchanged(self, key: str) -> None:
        # Rows written before encryption was added start with < not gAAAAA.
        legacy = "<!DOCTYPE html><p>old report</p>"
        assert decrypt_report(legacy, settings=_settings(key)) == legacy

    def test_legacy_plaintext_no_key(self) -> None:
        legacy = "<!DOCTYPE html><p>old report</p>"
        assert decrypt_report(legacy, settings=_settings(None)) == legacy

    def test_encrypted_missing_key_raises(self, key: str) -> None:
        s = _settings(key)
        ciphertext = encrypt_report("secret findings", settings=s)
        with pytest.raises(EncryptionKeyMissing):
            decrypt_report(ciphertext, settings=_settings(None))

    def test_different_key_raises(self, key: str) -> None:
        s1 = _settings(key)
        s2 = _settings(Fernet.generate_key().decode())
        ciphertext = encrypt_report("data", settings=s1)
        from cryptography.fernet import InvalidToken

        with pytest.raises(InvalidToken):
            decrypt_report(ciphertext, settings=s2)
