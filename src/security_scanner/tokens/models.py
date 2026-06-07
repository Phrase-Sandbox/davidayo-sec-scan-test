"""ORM models for the token registry, audit log, and two-channel config.

Conventions:
- Soft-delete rather than hard-delete a token (``revoked_at``) so historic
  audit events still resolve ``token_id → user_email``.
- Token rotation = mark current row revoked, insert a new row reusing the
  same ``token_id`` prefix. That keeps the user's identity continuous in
  audit logs across rotations.
- org_settings is append-only (immutable history); latest row = MAX(id).
- ci_tokens is append-only; latest active = MAX(id) WHERE revoked_at IS NULL.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from security_scanner.tokens.db import Base

# JSONB on Postgres, generic JSON elsewhere. Production stays JSONB
# (indexable / queryable); tests on SQLite get plain JSON.
_JsonType = JSON().with_variant(JSONB(), "postgresql")


class IssuedVia(enum.StrEnum):
    self_portal = "self_portal"
    admin_force_rotate = "admin_force_rotate"


class AuditEventType(enum.StrEnum):
    scan_ok = "scan_ok"
    scan_unauthorized = "scan_unauthorized"
    token_issued = "token_issued"  # noqa: S105 — audit event name, not a credential
    token_rotated = "token_rotated"  # noqa: S105 — audit event name, not a credential
    token_revoked = "token_revoked"  # noqa: S105 — audit event name, not a credential
    admin_force_rotate = "admin_force_rotate"
    user_deactivated = "user_deactivated"
    user_reactivated = "user_reactivated"
    user_llm_settings_updated = "user_llm_settings_updated"  # noqa: S105
    org_config_changed = "org_config_changed"
    ci_token_rotated = "ci_token_rotated"  # noqa: S105
    slack_webhook_configured = "slack_webhook_configured"  # noqa: S105
    user_promoted = "user_promoted"    # role user → admin (app-managed)
    user_demoted = "user_demoted"      # role admin → user (app-managed)
    user_password_force_reset = "user_password_force_reset"  # noqa: S105
    user_password_changed = "user_password_changed"  # noqa: S105
    user_okta_login = "user_okta_login"
    user_local_login = "user_local_login"


class UserRole(enum.StrEnum):
    user = "user"
    admin = "admin"


class LLMProvider(enum.StrEnum):
    anthropic = "anthropic"
    google = "google"


class ScanStatus(enum.StrEnum):
    ok = "ok"
    partial = "partial"
    failed = "failed"
    unauthorized = "unauthorized"


class LocalScanToken(Base):
    __tablename__ = "local_scan_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    # 12-hex prefix embedded in the token string — stable per user across
    # rotations. NOT unique by itself (a user may have many historical rows
    # with the same prefix; only one is active at a time — enforced at the
    # app layer, plus a PG-only partial unique index for concurrency safety
    # added in the Alembic migration).
    # 16 chars: literal "tok-" (4) + 12 hex chars. NOT 12.
    token_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    user_email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    issued_via: Mapped[IssuedVia] = mapped_column(
        Enum(IssuedVia, name="issued_via"), nullable=False
    )
    issued_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # 30-day TTL: set on issue/rotate; NULL = legacy unlimited token.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    event_type: Mapped[AuditEventType] = mapped_column(
        Enum(AuditEventType, name="audit_event_type"), nullable=False, index=True
    )
    user_email: Mapped[str | None] = mapped_column(String(320), nullable=True, index=True)
    token_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    # Never paths or content — see CLAUDE.md §local-scan privacy. Free-form
    # bag for severity counts, outcomes, request IDs, etc.
    event_metadata: Mapped[dict | None] = mapped_column("metadata", _JsonType, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


# ---------------------------------------------------------------------------
# Two-channel model: users, user settings, org settings, scan history, usage
# ---------------------------------------------------------------------------


class User(Base):
    """Portal user, created/updated on every successful Okta-authenticated visit."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), primary_key=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"), nullable=False, default=UserRole.user
    )
    is_active: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    okta_groups: Mapped[list | None] = mapped_column(_JsonType, nullable=True)

    # Stable Okta user ID (sub claim). Unique — allows lookup across email changes.
    # NULL for local-only users who have never logged in via Okta.
    okta_user_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True, unique=True, index=True
    )
    # "okta" or "local". Determines which credential is verified on login.
    auth_provider: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="local"
    )
    # Bcrypt hash for local users. NULL = no individual password set yet;
    # login falls back to LOCAL_PORTAL_PASSWORD env var.
    password_hash: Mapped[bytes | None] = mapped_column(LargeBinary(), nullable=True)
    # When True, user is redirected to /portal/change-password on next local login.
    must_change_password: Mapped[bool] = mapped_column(
        Boolean(), nullable=False, default=False, server_default="false"
    )
    # Set to now() by admin on reactivation. Sessions issued before this are rejected.
    last_reactivation_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Display name from Okta (name claim) or derived from email for local users.
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)


class UserLLMSettings(Base):
    """Per-user LLM provider + model + encrypted API key.

    One row per user — upserted via portal /settings form. The raw key is
    never stored; only the Fernet-encrypted blob. Display uses the last-4
    chars of the decrypted key (see crypto.mask_for_display).
    """

    __tablename__ = "user_llm_settings"

    user_email: Mapped[str] = mapped_column(
        String(320), ForeignKey("users.email", ondelete="CASCADE"), primary_key=True
    )
    provider: Mapped[LLMProvider] = mapped_column(
        Enum(LLMProvider, name="llm_provider"), nullable=False
    )
    # Nullable: model is now admin-controlled via OrgSettings.  The column is
    # kept for schema compatibility but the application no longer writes or
    # reads it — the admin-set model from OrgSettings is used at scan time.
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    encrypted_api_key: Mapped[bytes] = mapped_column(LargeBinary(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class OrgSettings(Base):
    """Append-only org LLM configuration.  Latest row (MAX id) is authoritative.

    Admin saves → INSERT a new row. The scanner reads MAX(id) on every CI
    scan request, so key changes propagate to the next scan with no restart.
    API keys are Fernet-encrypted; plaintext never persisted.
    """

    __tablename__ = "org_settings"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)
    encrypted_anthropic_key: Mapped[bytes | None] = mapped_column(
        LargeBinary(), nullable=True
    )
    encrypted_google_key: Mapped[bytes | None] = mapped_column(
        LargeBinary(), nullable=True
    )
    default_provider: Mapped[LLMProvider] = mapped_column(
        Enum(LLMProvider, name="llm_provider"),
        nullable=False,
        default=LLMProvider.anthropic,
    )
    # Per-provider admin-set models (migration 0003).  NULL = use the
    # provider's own default (e.g. CLAUDE_MODEL env var / GeminiClient default).
    anthropic_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    google_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Fernet-encrypted Slack webhook URL (migration 0004).  NULL = not configured;
    # the scanner falls back to the SLACK_WEBHOOK_URL environment variable.
    encrypted_slack_webhook: Mapped[bytes | None] = mapped_column(
        LargeBinary(), nullable=True
    )
    # Bypass Slack notification mode (migration 0005).
    # "dev_only" (default) — notify only when a dev repo triggers bypass.
    # "all"      — notify on every bypass (pre-0005 hard-coded behaviour).
    # "none"     — never send a Slack alert on bypass.
    bypass_slack_mode: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="dev_only"
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_by_email: Mapped[str] = mapped_column(String(320), nullable=False)


class ScanRecord(Base):
    """Persisted CLI scan result (advisory channel only — CI not persisted)."""

    __tablename__ = "scan_records"

    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True)
    user_email: Mapped[str] = mapped_column(
        String(320),
        ForeignKey("users.email", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    repo_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scan_target: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), nullable=False, default=ScanStatus.ok
    )
    findings_count: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    critical: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    high: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    medium: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    low: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    markdown_report: Mapped[str | None] = mapped_column(Text(), nullable=True)
    html_report: Mapped[str | None] = mapped_column(Text(), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)


class ScanUsage(Base):
    """Per-scan LLM token usage — one row per completed scan.

    ``response_ids`` is a comma-separated list of provider response IDs so
    users can cross-reference with the provider's own console (transparency).
    """

    __tablename__ = "scan_usage"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("scan_records.scan_id", ondelete="CASCADE"), primary_key=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    n_llm_calls: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    input_tokens: Mapped[int] = mapped_column(BigInteger(), nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(BigInteger(), nullable=False, default=0)
    cache_creation_input_tokens: Mapped[int] = mapped_column(
        BigInteger(), nullable=False, default=0
    )
    cache_read_input_tokens: Mapped[int] = mapped_column(
        BigInteger(), nullable=False, default=0
    )
    # Comma-separated provider response IDs (e.g. "msg_01ABC,msg_01DEF").
    response_ids: Mapped[str | None] = mapped_column(Text(), nullable=True)


class LLMUsageMonthly(Base):
    """Monthly aggregate per (user × provider × model).

    Updated by UPSERT after each scan completes so the portal always shows
    totals consistent with the scan_usage rows.  The composite PK is the
    natural grouping; no surrogate key needed.
    """

    __tablename__ = "llm_usage_monthly"

    user_email: Mapped[str] = mapped_column(String(320), primary_key=True)
    year_month: Mapped[str] = mapped_column(String(7), primary_key=True)  # "2026-05"
    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    model: Mapped[str] = mapped_column(String(128), primary_key=True)
    input_tokens: Mapped[int] = mapped_column(BigInteger(), nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(BigInteger(), nullable=False, default=0)
    cache_creation_input_tokens: Mapped[int] = mapped_column(
        BigInteger(), nullable=False, default=0
    )
    cache_read_input_tokens: Mapped[int] = mapped_column(
        BigInteger(), nullable=False, default=0
    )
    scan_count: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CIToken(Base):
    """Append-only CI bearer token registry.

    Each rotation inserts a new row and marks the previous one revoked.
    Active token = MAX(id) WHERE revoked_at IS NULL.
    Token is SHA-256 hashed; plaintext shown once in the admin UI on creation.
    """

    __tablename__ = "ci_tokens"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by_email: Mapped[str] = mapped_column(String(320), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
