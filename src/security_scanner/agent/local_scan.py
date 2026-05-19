"""Local-advisory jurisdiction — ``POST /scan/local`` (Appendix D-12).

A developer, on their own machine, uploads their working tree and gets a
**report back**. This endpoint is *structurally incapable of enforcement*:

- It runs the **on-demand** pipeline (``ScanType.on_demand``) — same as the
  pre-push skill — so no BR-009 gate verification.
- Its response model has **no ``gate_decision``**. It returns a Markdown
  report + severity counts only. It can never block a deployment or open a
  PR. That separation is the whole point of the two-jurisdiction design.
- It is gated by a **different token** (``LOCAL_SCAN_TOKEN``) than the CI
  gate path (``PHRASE_SCAN_TOKEN``). The CI token cannot reach here and the
  local token cannot reach ``/agent/scan``. Jurisdiction is enforced by
  distinct credentials, not by trust. If ``LOCAL_SCAN_TOKEN`` is unset the
  endpoint is effectively disabled (every call → 401).

§12: uploaded source is scanned in-memory and never persisted or logged —
only file *count* is logged, never content. Secret stripping still runs as a
normal pipeline step before any Claude call.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from security_scanner.agent.test_endpoint import _MockGitHubClient
from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.claude.client import ClaudeClient
from security_scanner.shared.config import Settings, get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import ScanTarget, ScanType, Severity
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.reports.markdown import build_markdown_report

log = get_logger(__name__)

router = APIRouter(prefix="/scan", tags=["local-scan"])

_REPO_URL_RE = re.compile(r"^https://github\.com/[^/\s]+/[^/\s]+?(\.git)?/?$")
_AUTH_FAILURE = "Local scan authentication failed (LOCAL_SCAN_TOKEN)."


def verify_local_scan_token(request: Request) -> str:
    """Validate ``Authorization: Bearer`` against ``LOCAL_SCAN_TOKEN``.

    A different credential than the CI gate's ``PHRASE_SCAN_TOKEN`` — this is
    the jurisdiction boundary. If ``LOCAL_SCAN_TOKEN`` is unset the local
    endpoint is disabled (raises 401), so a default deploy exposes nothing
    extra.
    """
    header = request.headers.get("Authorization") or request.headers.get("authorization")
    token: str | None = None
    if header:
        scheme, _, raw = header.partition(" ")
        if scheme.lower() == "bearer" and raw.strip():
            token = raw.strip()

    expected = get_settings().LOCAL_SCAN_TOKEN
    if token is None or expected is None or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTH_FAILURE,
        )
    return token


class LocalScanRequest(BaseModel):
    """Body of ``POST /scan/local`` — the dev's uploaded working tree."""

    files: dict[str, str] = Field(..., description="{relative_path: file_content}")
    triggered_by: str = "local-dev"
    directory: str = ""
    repo_url: str = "https://github.com/local/workspace"


class LocalScanResponse(BaseModel):
    """Advisory result. Deliberately has NO ``gate_decision`` field —
    the local jurisdiction cannot communicate an enforcement verdict."""

    markdown: str
    findings_count: int
    critical: int
    high: int
    medium: int
    low: int
    findings: list[VulnerabilityFinding]


LocalPipelineFactory = Callable[[dict[str, str]], ScanPipeline]


def get_local_pipeline_factory(
    settings: Annotated[Settings, Depends(get_settings)],
) -> LocalPipelineFactory:
    """On-demand pipeline over uploaded files (no GitHub, no BR-009 gate)."""

    def build(files: dict[str, str]) -> ScanPipeline:
        github_client = _MockGitHubClient(files)
        claude_client = ClaudeClient(api_key=settings.ANTHROPIC_API_KEY)
        return ScanPipeline(github_client, claude_client, mode=ScanType.on_demand)

    return build


_TokenDep = Annotated[str, Depends(verify_local_scan_token)]
_FactoryDep = Annotated[LocalPipelineFactory, Depends(get_local_pipeline_factory)]


@router.post("/local", response_model=LocalScanResponse)
async def scan_local(
    body: LocalScanRequest,
    _token: _TokenDep,
    factory: _FactoryDep,
) -> LocalScanResponse:
    if not _REPO_URL_RE.match(body.repo_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid repo_url (got {body.repo_url!r})",
        )
    if not body.files:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No files supplied to scan.",
        )

    # §12: log the count only — never the paths or content.
    log.info("local advisory scan", file_count=len(body.files), triggered_by=body.triggered_by)

    pipeline = factory(body.files)
    try:
        result = await pipeline.run(
            repo_url=body.repo_url,
            scan_target=ScanTarget.directory if body.directory else ScanTarget.full_repo,
            triggered_by=body.triggered_by,
            directory=body.directory,
        )
    except TokenLimitError as exc:
        return LocalScanResponse(
            markdown=(
                "# Security Scan Report\n\n"
                f"> Project too large to scan in one pass "
                f"(~{exc.estimated_tokens} tokens > {exc.threshold}). "
                "Re-run scoped to a sub-directory.\n"
            ),
            findings_count=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            findings=[],
        )

    def _count(sev: Severity) -> int:
        return sum(1 for f in result.findings if f.severity == sev)

    return LocalScanResponse(
        markdown=build_markdown_report(result),
        findings_count=result.findings_count,
        critical=_count(Severity.Critical),
        high=_count(Severity.High),
        medium=_count(Severity.Medium),
        low=_count(Severity.Low),
        findings=result.findings,
    )
