"""Token lifecycle for the per-user ``LOCAL_SCAN_TOKEN`` registry.

Token format:

    phs_local_tok-<12hex>_<43-char-url-safe-b64>

- ``tok-<12hex>`` is the user's stable identifier (NOT a secret; shows in
  audit logs). 12 hex chars = 48 bits = ~281 trillion buckets — plenty for
  collision-free user tagging.
- The suffix is 32 bytes of ``secrets.token_urlsafe`` randomness (~256 bits
  of entropy). The user CANNOT pick or modify it — a user-chosen suffix
  would be brute-forceable (6 digits = seconds) and would make "revoke"
  meaningless.

We store only ``sha256(full_token)``. The plaintext is shown to the user
exactly once (at issue or rotate) in their already-authenticated browser
session — that session is the secure channel.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from security_scanner.tokens.audit import record as audit_record
from security_scanner.tokens.models import (
    AuditEventType,
    IssuedVia,
    LocalScanToken,
)

# --- Token format ------------------------------------------------------------

_TOKEN_PREFIX = "phs_local_"
_TOKEN_ID_RE = re.compile(r"^tok-[0-9a-f]{12}$")
_FULL_TOKEN_RE = re.compile(r"^phs_local_(tok-[0-9a-f]{12})_([A-Za-z0-9_\-]{43})$")


def _new_token_id() -> str:
    """A new 12-hex user identifier. Used only when issuing a user's FIRST token."""
    return "tok-" + secrets.token_hex(6)


def _new_suffix() -> str:
    """32 bytes of entropy, url-safe base64 (43 chars)."""
    return secrets.token_urlsafe(32)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _build_token(token_id: str, suffix: str) -> str:
    return f"{_TOKEN_PREFIX}{token_id}_{suffix}"


def parse_token(provided: str) -> tuple[str, str] | None:
    """Return ``(token_id, suffix)`` or ``None`` if the shape doesn't match.

    A non-match never triggers a DB lookup — saves a round-trip on garbage.
    """
    m = _FULL_TOKEN_RE.match(provided)
    if m is None:
        return None
    return m.group(1), m.group(2)


# --- Verify outcome ----------------------------------------------------------

VerifyOutcome = Literal["ok", "bad_format", "unknown_token", "revoked", "bad_signature"]


@dataclass(frozen=True)
class VerifyResult:
    outcome: VerifyOutcome
    token_id: str | None = None
    user_email: str | None = None


async def verify(session: AsyncSession, provided: str) -> VerifyResult:
    """Validate a bearer token against the registry.

    Constant-time comparison on the hash so token length / collision-leading
    bytes don't leak through timing. Returns a tagged outcome so the caller
    can both record metrics and emit the right audit event.
    """
    parsed = parse_token(provided)
    if parsed is None:
        return VerifyResult(outcome="bad_format")

    token_id, _suffix = parsed
    stmt = (
        select(LocalScanToken)
        .where(LocalScanToken.token_id == token_id)
        .where(LocalScanToken.revoked_at.is_(None))
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        # Either no such token_id, or the only matching row is revoked.
        # Disambiguate so the audit log distinguishes "never existed" from
        # "previously valid but revoked".
        revoked_stmt = (
            select(LocalScanToken).where(LocalScanToken.token_id == token_id).limit(1)
        )
        revoked = (await session.execute(revoked_stmt)).scalar_one_or_none()
        if revoked is None:
            return VerifyResult(outcome="unknown_token", token_id=token_id)
        return VerifyResult(
            outcome="revoked",
            token_id=token_id,
            user_email=revoked.user_email,
        )

    provided_hash = _hash_token(provided)
    if not hmac.compare_digest(provided_hash, row.token_hash):
        return VerifyResult(
            outcome="bad_signature",
            token_id=token_id,
            user_email=row.user_email,
        )

    # Update last_used_at on a successful verify. Caller commits.
    row.last_used_at = datetime.now(UTC)

    return VerifyResult(
        outcome="ok",
        token_id=token_id,
        user_email=row.user_email,
    )


# --- Issue / rotate ----------------------------------------------------------


@dataclass(frozen=True)
class IssuedToken:
    """Returned exactly once when issuing or rotating. The CALLER must
    render ``full_token`` to the user and then drop the reference."""

    full_token: str
    token_id: str
    user_email: str
    was_rotation: bool


async def issue_or_rotate_for_user(
    session: AsyncSession,
    *,
    user_email: str,
    issued_via: IssuedVia = IssuedVia.self_portal,
    issued_by: str | None = None,
    request_id: str | None = None,
) -> IssuedToken:
    """Mint a new token for ``user_email``.

    - First-time issue: pick a fresh ``token_id``, insert a row.
    - Rotation: revoke the current active row, insert a new row reusing the
      same ``token_id`` so audit history stays continuous.
    """
    now = datetime.now(UTC)

    active_stmt = (
        select(LocalScanToken)
        .where(LocalScanToken.user_email == user_email)
        .where(LocalScanToken.revoked_at.is_(None))
    )
    current = (await session.execute(active_stmt)).scalar_one_or_none()

    if current is not None:
        token_id = current.token_id
        current.revoked_at = now
        current.revoked_by = issued_by or "self"
        was_rotation = True
        # Force the UPDATE to flush BEFORE we add the new row. Postgres'
        # partial unique index on (user_email) WHERE revoked_at IS NULL is
        # checked at statement time, so the old row must already be marked
        # revoked before the new active row is inserted.
        await session.flush()
    else:
        token_id = _new_token_id()
        was_rotation = False

    suffix = _new_suffix()
    full_token = _build_token(token_id, suffix)

    new_row = LocalScanToken(
        token_id=token_id,
        user_email=user_email,
        token_hash=_hash_token(full_token),
        issued_at=now,
        issued_via=issued_via,
        issued_by=issued_by,
    )
    session.add(new_row)

    await audit_record(
        session,
        event_type=AuditEventType.token_rotated if was_rotation else AuditEventType.token_issued,
        user_email=user_email,
        token_id=token_id,
        actor_email=issued_by,
        request_id=request_id,
        issued_via=issued_via.value,
    )

    return IssuedToken(
        full_token=full_token,
        token_id=token_id,
        user_email=user_email,
        was_rotation=was_rotation,
    )


# --- Revoke / force-rotate ---------------------------------------------------


async def revoke_active_for_user(
    session: AsyncSession,
    *,
    user_email: str,
    actor: str,
    request_id: str | None = None,
) -> bool:
    """Revoke the user's current active token, if any. Returns whether a row was revoked."""
    stmt = (
        select(LocalScanToken)
        .where(LocalScanToken.user_email == user_email)
        .where(LocalScanToken.revoked_at.is_(None))
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        return False

    row.revoked_at = datetime.now(UTC)
    row.revoked_by = actor

    await audit_record(
        session,
        event_type=AuditEventType.token_revoked,
        user_email=user_email,
        token_id=row.token_id,
        actor_email=actor,
        request_id=request_id,
    )
    return True


async def force_rotate_by_token_id(
    session: AsyncSession,
    *,
    token_id: str,
    admin_email: str,
    request_id: str | None = None,
) -> IssuedToken | None:
    """Admin path: rotate a user's token without them being logged in.

    Returns the new plaintext token (admin will hand-deliver via a secure
    channel) or ``None`` if no active row exists for that ``token_id``.
    """
    if not _TOKEN_ID_RE.match(token_id):
        return None

    stmt = (
        select(LocalScanToken)
        .where(LocalScanToken.token_id == token_id)
        .where(LocalScanToken.revoked_at.is_(None))
    )
    current = (await session.execute(stmt)).scalar_one_or_none()
    if current is None:
        return None

    user_email = current.user_email
    issued = await issue_or_rotate_for_user(
        session,
        user_email=user_email,
        issued_via=IssuedVia.admin_force_rotate,
        issued_by=admin_email,
        request_id=request_id,
    )
    await audit_record(
        session,
        event_type=AuditEventType.admin_force_rotate,
        user_email=user_email,
        token_id=issued.token_id,
        actor_email=admin_email,
        request_id=request_id,
    )
    return issued


async def revoke_by_token_id(
    session: AsyncSession,
    *,
    token_id: str,
    admin_email: str,
    request_id: str | None = None,
) -> bool:
    """Admin path: revoke any user's active token by ``token_id``."""
    if not _TOKEN_ID_RE.match(token_id):
        return False

    stmt = (
        select(LocalScanToken)
        .where(LocalScanToken.token_id == token_id)
        .where(LocalScanToken.revoked_at.is_(None))
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        return False

    row.revoked_at = datetime.now(UTC)
    row.revoked_by = admin_email

    await audit_record(
        session,
        event_type=AuditEventType.token_revoked,
        user_email=row.user_email,
        token_id=row.token_id,
        actor_email=admin_email,
        request_id=request_id,
    )
    return True


# --- Read paths --------------------------------------------------------------


async def get_active_for_user(
    session: AsyncSession, *, user_email: str
) -> LocalScanToken | None:
    stmt = (
        select(LocalScanToken)
        .where(LocalScanToken.user_email == user_email)
        .where(LocalScanToken.revoked_at.is_(None))
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_all(
    session: AsyncSession,
    *,
    active_only: bool = False,
    user_email_contains: str | None = None,
    limit: int = 500,
) -> list[LocalScanToken]:
    """Admin view: list tokens with optional filters."""
    stmt = select(LocalScanToken).order_by(LocalScanToken.issued_at.desc()).limit(limit)
    if active_only:
        stmt = stmt.where(LocalScanToken.revoked_at.is_(None))
    if user_email_contains:
        like = f"%{user_email_contains}%"
        stmt = stmt.where(LocalScanToken.user_email.ilike(like))
    return list((await session.execute(stmt)).scalars().all())
