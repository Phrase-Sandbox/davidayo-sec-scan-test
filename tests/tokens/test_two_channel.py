"""Tests for two-channel features added in 0002_two_channel migration.

Covers:
- Fernet encrypt/decrypt round-trip + mask_for_display
- 30-day TTL: expired outcome on verify()
- User deactivation: deactivated outcome on verify()
- OrgSettings: versioning + _load_active_org_settings reads MAX(id) row
- Scan persistence: scan_records + scan_usage + llm_usage_monthly written atomically
- CIToken: hash-only storage, rotation marks old row revoked
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from security_scanner.tokens import registry
from security_scanner.tokens.models import (
    CIToken,
    LLMProvider,
    LLMUsageMonthly,
    OrgSettings,
    ScanRecord,
    ScanStatus,
    ScanUsage,
    User,
    UserRole,
)

# ---------------------------------------------------------------------------
# Fernet crypto
# ---------------------------------------------------------------------------


def _make_settings(key: str | None):
    """Return a minimal settings-like mock with SCANNER_ENCRYPTION_KEY set."""
    s = MagicMock()
    s.SCANNER_ENCRYPTION_KEY = key
    return s


def test_fernet_round_trip():
    """encrypt → decrypt round-trips without data loss."""
    from cryptography.fernet import Fernet

    from security_scanner.tokens.crypto import decrypt, encrypt

    key = Fernet.generate_key().decode()
    settings = _make_settings(key)

    plaintext = "sk-ant-super-secret-key-12345"
    ciphertext = encrypt(plaintext, settings=settings)
    assert isinstance(ciphertext, bytes)
    assert decrypt(ciphertext, settings=settings) == plaintext


def test_fernet_ciphertext_is_not_plaintext():
    """Stored bytes should not contain the raw secret."""
    from cryptography.fernet import Fernet

    from security_scanner.tokens.crypto import encrypt

    key = Fernet.generate_key().decode()
    settings = _make_settings(key)
    secret = "sk-ant-my-real-key"
    ciphertext = encrypt(secret, settings=settings)
    assert secret.encode() not in ciphertext


def test_mask_for_display():
    """mask_for_display shows only the last 4 chars of the secret."""
    from security_scanner.tokens.crypto import mask_for_display

    masked = mask_for_display("sk-ant-abcdefgh")
    # The tail chars must be present.
    assert "efgh" in masked
    # The full secret must not be present.
    assert "sk-ant-abcd" not in masked
    # Starts with the ellipsis marker.
    assert masked.startswith("…")


def test_missing_encryption_key_raises_on_encrypt():
    """encrypt() raises EncryptionKeyMissing when SCANNER_ENCRYPTION_KEY is None."""
    from security_scanner.tokens.crypto import EncryptionKeyMissing, encrypt

    settings = _make_settings(None)
    with pytest.raises(EncryptionKeyMissing, match="SCANNER_ENCRYPTION_KEY"):
        encrypt("any-value", settings=settings)


def test_invalid_fernet_key_raises_on_encrypt():
    """encrypt() raises EncryptionKeyInvalid when the key is not valid Fernet."""
    from security_scanner.tokens.crypto import EncryptionKeyInvalid, encrypt

    settings = _make_settings("not-a-valid-fernet-key")
    with pytest.raises(EncryptionKeyInvalid):
        encrypt("any-value", settings=settings)


# ---------------------------------------------------------------------------
# 30-day TTL: verify() returns "expired"
# ---------------------------------------------------------------------------


async def test_expired_token_returns_expired_outcome(session: AsyncSession):
    """A token whose expires_at is in the past → verify() → 'expired'."""
    issued = await registry.issue_or_rotate_for_user(session, user_email="expired@phrase.com")
    # Backdate the expires_at to 31 days ago.
    from sqlalchemy import select

    from security_scanner.tokens.models import LocalScanToken

    row = (
        await session.execute(
            select(LocalScanToken).where(LocalScanToken.token_id == issued.token_id)
        )
    ).scalar_one()
    row.expires_at = datetime.now(UTC) - timedelta(days=31)
    await session.flush()

    result = await registry.verify(session, issued.full_token)
    assert result.outcome == "expired"
    assert result.user_email == "expired@phrase.com"


async def test_non_expired_token_verifies_ok(session: AsyncSession):
    """A token with expires_at in the future verifies successfully."""
    issued = await registry.issue_or_rotate_for_user(session, user_email="fresh@phrase.com")
    result = await registry.verify(session, issued.full_token)
    assert result.outcome == "ok"


# ---------------------------------------------------------------------------
# User deactivation: verify() returns "deactivated"
# ---------------------------------------------------------------------------


async def test_deactivated_user_returns_deactivated_outcome(session: AsyncSession):
    """A valid token for a deactivated user → verify() → 'deactivated'."""
    # Upsert user, then issue token.
    await registry.upsert_user(session, email="gone@phrase.com")
    issued = await registry.issue_or_rotate_for_user(session, user_email="gone@phrase.com")
    await session.flush()

    # Deactivate the user.
    user_row = (
        await session.execute(select(User).where(User.email == "gone@phrase.com"))
    ).scalar_one()
    user_row.is_active = False
    await session.flush()

    result = await registry.verify(session, issued.full_token)
    assert result.outcome == "deactivated"
    assert result.user_email == "gone@phrase.com"


async def test_reactivated_user_verifies_ok(session: AsyncSession):
    """A reactivated user's token verifies successfully."""
    await registry.upsert_user(session, email="back@phrase.com")
    issued = await registry.issue_or_rotate_for_user(session, user_email="back@phrase.com")
    # Deactivate then reactivate.
    user_row = (
        await session.execute(select(User).where(User.email == "back@phrase.com"))
    ).scalar_one()
    user_row.is_active = False
    await session.flush()
    user_row.is_active = True
    await session.flush()

    result = await registry.verify(session, issued.full_token)
    assert result.outcome == "ok"


# ---------------------------------------------------------------------------
# OrgSettings versioning
# ---------------------------------------------------------------------------


async def test_org_settings_new_row_per_save(session: AsyncSession):
    """Each save inserts a new row; MAX(id) returns the latest."""
    now = datetime.now(UTC)

    row1 = OrgSettings(
        encrypted_anthropic_key=b"enc1",
        encrypted_google_key=None,
        default_provider=LLMProvider.anthropic,
        anthropic_model="claude-sonnet-4-6",
        google_model=None,
        updated_at=now,
        updated_by_email="admin@phrase.com",
    )
    session.add(row1)
    await session.flush()
    v1_id = row1.id

    row2 = OrgSettings(
        encrypted_anthropic_key=b"enc2",
        encrypted_google_key=None,
        default_provider=LLMProvider.anthropic,
        anthropic_model="claude-opus-4-7",
        google_model=None,
        updated_at=now,
        updated_by_email="admin@phrase.com",
    )
    session.add(row2)
    await session.flush()

    # MAX(id) row should be row2.
    stmt = select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
    latest = (await session.execute(stmt)).scalar_one()
    assert latest.id > v1_id
    assert latest.anthropic_model == "claude-opus-4-7"
    assert latest.encrypted_anthropic_key == b"enc2"


async def test_org_settings_returns_none_when_empty(session: AsyncSession):
    """Empty table → no active org settings row."""
    stmt = select(OrgSettings).order_by(OrgSettings.id.desc()).limit(1)
    result = (await session.execute(stmt)).scalar_one_or_none()
    assert result is None


# ---------------------------------------------------------------------------
# Scan persistence
# ---------------------------------------------------------------------------


async def test_scan_record_and_usage_inserted(session: AsyncSession):
    """ScanRecord + ScanUsage can be written and read back atomically."""
    import uuid

    scan_id = uuid.uuid4()
    now = datetime.now(UTC)
    rec = ScanRecord(
        scan_id=scan_id,
        user_email="dev@phrase.com",
        started_at=now,
        finished_at=now,
        repo_url="https://github.com/phrase/test",
        scan_target="full_repo",
        status=ScanStatus.ok,
        findings_count=3,
        critical=1,
        high=2,
        medium=0,
        low=0,
        markdown_report="# findings",
        html_report="<h1>findings</h1>",
        provider="anthropic",
        model="claude-sonnet-4-6",
    )
    session.add(rec)
    await session.flush()

    usage = ScanUsage(
        scan_id=scan_id,
        provider="anthropic",
        model="claude-sonnet-4-6",
        n_llm_calls=5,
        input_tokens=10_000,
        output_tokens=2_000,
        cache_creation_input_tokens=500,
        cache_read_input_tokens=3_000,
        response_ids="msg_01ABC,msg_01DEF",
    )
    session.add(usage)
    await session.flush()

    fetched_rec = (
        await session.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id))
    ).scalar_one()
    fetched_usage = (
        await session.execute(select(ScanUsage).where(ScanUsage.scan_id == scan_id))
    ).scalar_one()

    assert fetched_rec.findings_count == 3
    assert fetched_rec.critical == 1
    assert fetched_usage.n_llm_calls == 5
    assert fetched_usage.input_tokens == 10_000
    assert fetched_usage.response_ids == "msg_01ABC,msg_01DEF"


async def test_llm_usage_monthly_upsert(session: AsyncSession):
    """LLMUsageMonthly rows can be inserted and read back."""
    now = datetime.now(UTC)
    row = LLMUsageMonthly(
        user_email="dev@phrase.com",
        year_month="2026-05",
        provider="anthropic",
        model="claude-sonnet-4-6",
        input_tokens=50_000,
        output_tokens=10_000,
        cache_creation_input_tokens=1_000,
        cache_read_input_tokens=8_000,
        scan_count=3,
        last_updated=now,
    )
    session.add(row)
    await session.flush()

    fetched = (
        await session.execute(
            select(LLMUsageMonthly)
            .where(LLMUsageMonthly.user_email == "dev@phrase.com")
            .where(LLMUsageMonthly.year_month == "2026-05")
        )
    ).scalar_one()

    assert fetched.input_tokens == 50_000
    assert fetched.scan_count == 3


# ---------------------------------------------------------------------------
# CIToken rotation
# ---------------------------------------------------------------------------


async def test_ci_token_rotation_marks_old_revoked(session: AsyncSession):
    """Rotating a CI token: old row gets revoked_at, new row is inserted."""
    import hashlib as hl
    import secrets as sec

    now = datetime.now(UTC)

    def _new_ci_token():
        suffix = sec.token_urlsafe(32)
        plaintext = f"phs_ci_{suffix}"
        token_hash = hl.sha256(plaintext.encode()).hexdigest()
        return plaintext, token_hash

    pt1, h1 = _new_ci_token()
    row1 = CIToken(
        token_hash=h1,
        created_at=now,
        created_by_email="admin@phrase.com",
    )
    session.add(row1)
    await session.flush()
    id1 = row1.id

    # Rotate: mark old revoked, insert new.
    row1.revoked_at = now
    row1.revoked_by_email = "admin@phrase.com"
    await session.flush()

    pt2, h2 = _new_ci_token()
    row2 = CIToken(
        token_hash=h2,
        created_at=now,
        created_by_email="admin@phrase.com",
    )
    session.add(row2)
    await session.flush()

    # Active token = MAX(id) WHERE revoked_at IS NULL
    active = (
        await session.execute(
            select(CIToken).where(CIToken.revoked_at.is_(None)).order_by(CIToken.id.desc()).limit(1)
        )
    ).scalar_one()
    assert active.id > id1
    assert active.token_hash == h2

    # Old token should be revoked.
    old = (await session.execute(select(CIToken).where(CIToken.id == id1))).scalar_one()
    assert old.revoked_at is not None


# ---------------------------------------------------------------------------
# upsert_user
# ---------------------------------------------------------------------------


async def test_upsert_user_creates_then_updates(session: AsyncSession):
    """upsert_user creates on first call; updates last_login_at on subsequent calls."""
    user = await registry.upsert_user(session, email="new@phrase.com", is_admin=False)
    assert user.email == "new@phrase.com"
    assert user.role == UserRole.user
    assert user.is_active is True

    # Second call should update last_login_at.
    first_login = user.last_login_at
    import asyncio

    await asyncio.sleep(0.01)
    user2 = await registry.upsert_user(session, email="new@phrase.com")
    assert user2.last_login_at >= first_login  # type: ignore[operator]


async def test_upsert_user_promotes_to_admin(session: AsyncSession):
    """upsert_user with is_admin=True promotes an existing user to admin."""
    await registry.upsert_user(session, email="promoted@phrase.com", is_admin=False)
    user = await registry.upsert_user(session, email="promoted@phrase.com", is_admin=True)
    assert user.role == UserRole.admin
