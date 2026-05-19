"""**LOCAL TESTING ONLY** — bypass GitHub fetch with caller-supplied files.

⚠️  Production deploys MUST NEVER load this module. The router is conditionally
imported by ``main.py`` only when ``LOCAL_TEST_MODE=true``. A clear startup
warning is logged when that gate is open.

The endpoint accepts the same body as ``/agent/scan`` plus an extra
``mock_files`` field. Instead of fetching from GitHub, the pipeline is given
a tiny duck-typed GitHubClient stub that returns the caller-supplied files.
**Every other pipeline step runs for real** — secret stripping, file
filtering, the token gate, the live Claude API call, schema validation,
post-filter, BR-009 verification (gate mode), and gate decision.

This is the cheapest possible end-to-end test of the scanner: no GitHub App
needed, but you still pay the Claude API call (so set a real
``ANTHROPIC_API_KEY``).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from security_scanner.agent.auth import verify_scan_token
from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.claude.client import ClaudeClient
from security_scanner.shared.config import Settings, get_settings
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import GateDecision, ScanTarget, ScanType
from security_scanner.shared.models.scan_result import ScanResult

log = get_logger(__name__)

router = APIRouter(prefix="/agent", tags=["agent-test"])

_REPO_URL_RE = re.compile(r"^https://github\.com/[^/\s]+/[^/\s]+?(\.git)?/?$")


class _MockGitHubClient:
    """Duck-typed ``GitHubClient`` that returns pre-supplied files.

    Pipeline only ever calls ``get_repo_files`` and ``get_diff_files`` on the
    GitHub client, both of which we satisfy here. No HTTP, no JWT, no
    installation lookup — that's the point.
    """

    def __init__(self, files: dict[str, str]) -> None:
        self._files = files

    def get_repo_files(
        self,
        owner: str,  # noqa: ARG002
        repo: str,  # noqa: ARG002
        ref: str = "HEAD",  # noqa: ARG002
        path: str = "",  # noqa: ARG002
    ) -> dict[str, str]:
        return self._files

    def get_diff_files(
        self,
        owner: str,  # noqa: ARG002
        repo: str,  # noqa: ARG002
        base: str,  # noqa: ARG002
        head: str,  # noqa: ARG002
    ) -> dict[str, str]:
        return self._files


class TestScanRequest(BaseModel):
    repo_url: str
    scan_target: ScanTarget
    triggered_by: str
    ref: str = "HEAD"
    base: str | None = None
    head: str | None = None
    directory: str = ""
    mock_files: dict[str, str]


TestPipelineFactory = Callable[[dict[str, str]], ScanPipeline]


def get_test_pipeline_factory(
    settings: Annotated[Settings, Depends(get_settings)],
) -> TestPipelineFactory:
    """Build a deployment-gate-mode pipeline backed by ``_MockGitHubClient``."""

    def build(mock_files: dict[str, str]) -> ScanPipeline:
        github_client = _MockGitHubClient(mock_files)
        claude_client = ClaudeClient(api_key=settings.ANTHROPIC_API_KEY)
        return ScanPipeline(github_client, claude_client, mode=ScanType.deployment_gate)

    return build


_TokenDep = Annotated[str, Depends(verify_scan_token)]
_FactoryDep = Annotated[TestPipelineFactory, Depends(get_test_pipeline_factory)]


@router.post("/test-scan", response_model=ScanResult)
async def test_scan(
    body: TestScanRequest,
    _token: _TokenDep,
    factory: _FactoryDep,
) -> ScanResult:
    if not _REPO_URL_RE.match(body.repo_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Invalid repo_url; expected https://github.com/{org}/{repo} "
                f"(got {body.repo_url!r})"
            ),
        )

    log.warning(
        "LOCAL_TEST_MODE scan invoked — bypasses GitHub fetch",
        file_count=len(body.mock_files),
        triggered_by=body.triggered_by,
    )

    pipeline = factory(body.mock_files)

    try:
        return await pipeline.run(
            repo_url=body.repo_url,
            scan_target=body.scan_target,
            triggered_by=body.triggered_by,
            ref=body.ref,
            base=body.base,
            head=body.head,
            directory=body.directory,
        )
    except TokenLimitError as exc:
        log.warning(
            "token-limit exceeded on test scan",
            estimated_tokens=exc.estimated_tokens,
            threshold=exc.threshold,
        )
        return _token_limit_advisory(body, exc)


def _token_limit_advisory(body: TestScanRequest, exc: TokenLimitError) -> ScanResult:
    return ScanResult(
        repo_url=body.repo_url,
        scan_target=body.scan_target,
        scan_type=ScanType.deployment_gate,
        triggered_by=body.triggered_by,
        findings_count=0,
        gate_decision=GateDecision.advisory,
        partial_scan=False,
        unscanned_files=[],
        findings=[],
        warnings=[
            f"Mock-file set exceeds scan size limit "
            f"(~{exc.estimated_tokens} tokens, max {exc.threshold}). "
            "BR-005: pass fewer files in mock_files."
        ],
    )
