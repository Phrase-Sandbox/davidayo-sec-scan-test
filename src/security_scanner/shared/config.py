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
            "Local-advisory auth token (jurisdiction: /scan/local). Distinct "
            "from PHRASE_SCAN_TOKEN — the boundary between the two "
            "jurisdictions. None disables the /scan/local endpoint entirely."
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

    PORT: int = Field(default=8000, description="HTTP port")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")


def get_settings() -> Settings:
    """Return a Settings instance loaded from the current environment.

    Kept as a factory (rather than a module-level singleton) so that importing
    this module does not require any env vars to be set, which keeps tests and
    static analysis tooling working out of the box.
    """
    return Settings()  # type: ignore[call-arg]
