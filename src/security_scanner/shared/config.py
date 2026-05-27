from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Service configuration loaded from environment variables.

    Required variables (no default) raise pydantic.ValidationError at
    instantiation if missing, failing fast before traffic is served.
    """

    model_config = SettingsConfigDict(
        env_file=None,
        case_sensitive=True,
        extra="ignore",
    )

    ANTHROPIC_API_KEY: str = Field(..., description="Anthropic API key for Claude")

    # Optional non-default LLM providers (Appendix D-15 — DEVIATION, sim-only).
    # Unset by default → the spec-mandated Anthropic path is unchanged. Only
    # consulted when SCANNER_LLM_PROVIDER selects that provider; DATA
    # GOVERNANCE: ZDR/DPA is confirmed for Anthropic ONLY (§7.2/§8.3).
    GOOGLE_API_KEY: str | None = Field(
        default=None,
        description="Google API key — only used when SCANNER_LLM_PROVIDER=google (D-15)",
    )

    PHRASE_SCAN_TOKEN: str | None = Field(
        default=None,
        description="CI gate-path token (jurisdiction: enforcement); None disables gate auth",
    )

    LOCAL_SCAN_TOKEN: str | None = Field(
        default=None,
        description=(
            "DEPRECATED single-shared bearer for /scan/local. Kept as a "
            "fallback for one release while the per-user token registry "
            "rolls out; emits a startup warning if set. The new path is "
            "USE_TOKEN_REGISTRY=true with tokens issued via /portal/."
        ),
    )

    # --- Token registry (Phase 1 of the LOCAL_SCAN_TOKEN per-user rollout) ---
    DATABASE_URL: str | None = Field(
        default=None,
        description=(
            "Postgres connection string for the token registry + audit log. "
            "Required when USE_TOKEN_REGISTRY=true. Format: "
            "postgresql+psycopg://user:pass@host:5432/db"
        ),
    )

    USE_TOKEN_REGISTRY: bool = Field(
        default=False,
        description=(
            "Feature flag. When True, /scan/local validates tokens against "
            "the DB-backed registry instead of LOCAL_SCAN_TOKEN. Defaults "
            "False so PR 1 lands without behavioural change."
        ),
    )

    RUN_MIGRATIONS_ON_STARTUP: bool = Field(
        default=False,
        description=(
            "When True, Alembic upgrades the DB to head before the FastAPI "
            "app starts serving traffic. Convenient for local-dev; production "
            "should run migrations as a separate K8s Job."
        ),
    )

    ADMIN_GROUP_NAME: str = Field(
        default="security-scanner-admins",
        description=(
            "Okta group name that grants access to /admin/*. Read from the "
            "platform-injected X-Userinfo.groups claim."
        ),
    )

    ADMIN_LOCAL_BYPASS: bool = Field(
        default=False,
        description=(
            "LOCAL DEVELOPMENT ONLY. When True, injects a fake admin user "
            "so /portal/* and /admin/* work without the platform's Okta "
            "gateway. Startup REFUSES if this is True and DATABASE_URL does "
            "not point at localhost or postgres (production safeguard)."
        ),
    )

    PORTAL_LOGIN_URL: str = Field(
        default="",
        description=(
            "URL to redirect unauthenticated browser users to for Okta login. "
            "In production this is the Okta authorization URL or the ingress "
            "login path (e.g. '/_oauth/start?rd=/portal/'). "
            "Leave blank to show the built-in login page with contact instructions."
        ),
    )

    GITHUB_APP_ID: str = Field(..., description="GitHub App ID")
    GITHUB_APP_PRIVATE_KEY: str = Field(
        ...,
        description="GitHub App PEM private key (newlines escaped in env)",
    )

    GITHUB_OAUTH_CLIENT_ID: str = Field(..., description="GitHub OAuth client ID for skill flow")
    GITHUB_OAUTH_CLIENT_SECRET: str = Field(..., description="GitHub OAuth client secret")

    SLACK_WEBHOOK_URL: str | None = Field(
        default=None,
        description="Slack #security webhook for bypass alerts; None disables Slack",
    )

    # --- GitHub OIDC auth (master-scanner-pipeline → /scan) ---------------------
    # When True, /scan accepts GitHub-issued OIDC JWTs from workflows that
    # match GITHUB_OIDC_ALLOWED_WORKFLOW_REFS. Bearer-token auth still works
    # as a fallback (CLI/local paths). Off by default.
    GITHUB_OIDC_ENABLED: bool = Field(
        default=False,
        description="When True, /scan accepts GitHub OIDC JWTs in addition to bearer tokens",
    )
    GITHUB_OIDC_AUDIENCE: str = Field(
        default="phrase-scanner",
        description="Expected `aud` claim on incoming OIDC tokens",
    )
    GITHUB_OIDC_ALLOWED_WORKFLOW_REFS: str = Field(
        default="",
        description=(
            "Comma-separated prefixes that the OIDC `job_workflow_ref` claim "
            "must match. Example: "
            "'Phrase-Sandbox/master-scanner-pipeline/.github/workflows/scanner.yml@'"
        ),
    )

    # --- Encryption at rest (org_settings + user_llm_settings) ----------------
    # Required when the new two-channel model is active. Generated with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Rotating: decrypt-with-old, re-encrypt-with-new; see devci-readme.md.
    SCANNER_ENCRYPTION_KEY: str | None = Field(
        default=None,
        description=(
            "Fernet key (urlsafe-b64, 32 bytes). Required when encrypted "
            "user/org LLM keys are stored in the DB. Startup fails if the "
            "value is set but malformed."
        ),
    )

    PORT: int = Field(default=8000, description="HTTP port")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")


def get_settings() -> Settings:
    """Return a Settings instance loaded from the current environment.

    Kept as a factory (rather than a module-level singleton) so that importing
    this module does not require any env vars to be set, which keeps tests and
    static analysis tooling working out of the box.
    """
    return Settings()  # type: ignore[call-arg]
