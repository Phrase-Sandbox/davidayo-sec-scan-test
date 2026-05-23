"""Unit tests for ``security_scanner.tokens.registry``.

Covers the lifecycle:
- issue (first time, new ``token_id``)
- rotate (same ``token_id``, new suffix, old row marked revoked)
- verify (ok / unknown_token / revoked / bad_signature / bad_format)
- revoke (self) and force_rotate (admin)
- list_all filters
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from security_scanner.tokens import registry
from security_scanner.tokens.models import (
    AuditEvent,
    AuditEventType,
    IssuedVia,
    LocalScanToken,
)


# --- parse_token --------------------------------------------------------------


def test_parse_token_accepts_well_formed() -> None:
    parsed = registry.parse_token(
        "phs_local_tok-0123456789ab_" + "A" * 43
    )
    assert parsed == ("tok-0123456789ab", "A" * 43)


def test_parse_token_rejects_garbage() -> None:
    assert registry.parse_token("not-a-token") is None
    assert registry.parse_token("phs_local_tok-short_" + "A" * 43) is None
    assert registry.parse_token("phs_local_tok-0123456789ab_short") is None


# --- issue / rotate -----------------------------------------------------------


async def test_first_issue_creates_token(session: AsyncSession) -> None:
    issued = await registry.issue_or_rotate_for_user(
        session, user_email="alice@phrase.com"
    )
    await session.commit()

    assert issued.was_rotation is False
    assert issued.user_email == "alice@phrase.com"
    assert issued.token_id.startswith("tok-")
    assert len(issued.token_id) == 16  # "tok-" + 12 hex
    assert issued.full_token.startswith("phs_local_" + issued.token_id + "_")

    # One active row in DB.
    rows = (await session.execute(select(LocalScanToken))).scalars().all()
    assert len(rows) == 1
    assert rows[0].revoked_at is None
    assert rows[0].user_email == "alice@phrase.com"
    assert rows[0].issued_via == IssuedVia.self_portal

    # Audit event recorded.
    events = (await session.execute(select(AuditEvent))).scalars().all()
    assert [e.event_type for e in events] == [AuditEventType.token_issued]


async def test_rotation_preserves_token_id_and_revokes_old(
    session: AsyncSession,
) -> None:
    first = await registry.issue_or_rotate_for_user(
        session, user_email="bob@phrase.com"
    )
    await session.commit()

    second = await registry.issue_or_rotate_for_user(
        session, user_email="bob@phrase.com"
    )
    await session.commit()

    # Same stable identifier, different secret.
    assert second.token_id == first.token_id
    assert second.full_token != first.full_token
    assert second.was_rotation is True

    rows = (
        (await session.execute(select(LocalScanToken).order_by(LocalScanToken.issued_at)))
        .scalars()
        .all()
    )
    assert len(rows) == 2
    # Old one revoked, new one active.
    assert rows[0].revoked_at is not None
    assert rows[1].revoked_at is None
    assert rows[0].token_hash != rows[1].token_hash


# --- verify -------------------------------------------------------------------


async def test_verify_ok_returns_user_email_and_updates_last_used(
    session: AsyncSession,
) -> None:
    issued = await registry.issue_or_rotate_for_user(
        session, user_email="carol@phrase.com"
    )
    await session.commit()

    result = await registry.verify(session, issued.full_token)
    await session.commit()

    assert result.outcome == "ok"
    assert result.user_email == "carol@phrase.com"
    assert result.token_id == issued.token_id

    row = (
        (await session.execute(select(LocalScanToken).where(LocalScanToken.token_id == issued.token_id)))
        .scalar_one()
    )
    assert row.last_used_at is not None


async def test_verify_bad_format_short_circuits(session: AsyncSession) -> None:
    result = await registry.verify(session, "definitely-not-a-token")
    assert result.outcome == "bad_format"
    assert result.token_id is None


async def test_verify_unknown_token(session: AsyncSession) -> None:
    result = await registry.verify(
        session, "phs_local_tok-deadbeefcafe_" + "A" * 43
    )
    assert result.outcome == "unknown_token"
    assert result.token_id == "tok-deadbeefcafe"
    assert result.user_email is None


async def test_verify_revoked_returns_revoked_outcome(session: AsyncSession) -> None:
    issued = await registry.issue_or_rotate_for_user(
        session, user_email="dan@phrase.com"
    )
    await session.commit()

    await registry.revoke_active_for_user(
        session, user_email="dan@phrase.com", actor="self"
    )
    await session.commit()

    result = await registry.verify(session, issued.full_token)
    assert result.outcome == "revoked"
    assert result.token_id == issued.token_id
    assert result.user_email == "dan@phrase.com"


async def test_verify_bad_signature(session: AsyncSession) -> None:
    issued = await registry.issue_or_rotate_for_user(
        session, user_email="eve@phrase.com"
    )
    await session.commit()

    # Same token_id prefix, wrong suffix.
    bad = "phs_local_" + issued.token_id + "_" + ("B" * 43)
    result = await registry.verify(session, bad)
    assert result.outcome == "bad_signature"
    assert result.token_id == issued.token_id
    assert result.user_email == "eve@phrase.com"


# --- revoke / force_rotate ----------------------------------------------------


async def test_revoke_active_for_user_returns_false_when_none(
    session: AsyncSession,
) -> None:
    revoked = await registry.revoke_active_for_user(
        session, user_email="ghost@phrase.com", actor="self"
    )
    assert revoked is False


async def test_admin_force_rotate_issues_new_with_same_token_id(
    session: AsyncSession,
) -> None:
    original = await registry.issue_or_rotate_for_user(
        session, user_email="frank@phrase.com"
    )
    await session.commit()

    rotated = await registry.force_rotate_by_token_id(
        session,
        token_id=original.token_id,
        admin_email="admin@phrase.com",
    )
    await session.commit()

    assert rotated is not None
    assert rotated.token_id == original.token_id
    assert rotated.full_token != original.full_token

    # Audit log has BOTH a token_rotated and an admin_force_rotate event.
    events = (
        (await session.execute(select(AuditEvent).order_by(AuditEvent.at)))
        .scalars()
        .all()
    )
    types = [e.event_type for e in events]
    assert AuditEventType.token_rotated in types
    assert AuditEventType.admin_force_rotate in types


async def test_admin_force_rotate_returns_none_for_unknown_token_id(
    session: AsyncSession,
) -> None:
    result = await registry.force_rotate_by_token_id(
        session,
        token_id="tok-notarealid01",  # 12 hex chars but no such row
        admin_email="admin@phrase.com",
    )
    assert result is None


async def test_admin_force_rotate_rejects_malformed_token_id(
    session: AsyncSession,
) -> None:
    result = await registry.force_rotate_by_token_id(
        session,
        token_id="not-a-token-id",
        admin_email="admin@phrase.com",
    )
    assert result is None


async def test_admin_revoke_by_token_id(session: AsyncSession) -> None:
    issued = await registry.issue_or_rotate_for_user(
        session, user_email="grace@phrase.com"
    )
    await session.commit()

    revoked = await registry.revoke_by_token_id(
        session, token_id=issued.token_id, admin_email="admin@phrase.com"
    )
    await session.commit()
    assert revoked is True

    result = await registry.verify(session, issued.full_token)
    assert result.outcome == "revoked"


# --- list_all -----------------------------------------------------------------


async def test_list_all_active_only_filter(session: AsyncSession) -> None:
    await registry.issue_or_rotate_for_user(session, user_email="hank@phrase.com")
    await registry.issue_or_rotate_for_user(session, user_email="ivy@phrase.com")
    await session.commit()
    await registry.revoke_active_for_user(
        session, user_email="hank@phrase.com", actor="self"
    )
    await session.commit()

    all_rows = await registry.list_all(session)
    assert len(all_rows) == 2

    active = await registry.list_all(session, active_only=True)
    assert len(active) == 1
    assert active[0].user_email == "ivy@phrase.com"


async def test_list_all_email_filter(session: AsyncSession) -> None:
    await registry.issue_or_rotate_for_user(session, user_email="alice@phrase.com")
    await registry.issue_or_rotate_for_user(session, user_email="bob@phrase.com")
    await session.commit()

    matched = await registry.list_all(session, user_email_contains="alice")
    assert len(matched) == 1
    assert matched[0].user_email == "alice@phrase.com"
