"""On-demand skill API endpoint — POST /skill/scan (spec §2.2 skill path, §6.1).

The skill path is invoked from Claude.ai. The developer's OAuth session
cookie identifies them; the access token attached to that session is what
``GitHubClient`` uses to read the repo. Unlike the gate path, the skill
**never** runs BR-009 parallel verification (cost control — the skill is
informational, not enforcement).

Failure modes:

- ``TokenLimitError`` → HTTP 200 with a BR-005 warning in the response body.
  The skill UI surfaces this and asks the developer to scope to a directory.
- ``ClaudeUnavailableError`` → HTTP 503 with the EC-002 message.
- ``GitHubAuthError`` → HTTP 401 with the EC-005 message (OAuth token died).
- Bad ``repo_url`` → 422 (FastAPI body validation).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.claude.client import ClaudeUnavailableError
from security_scanner.shared.config import Settings, get_settings
from security_scanner.shared.github.client import GitHubAuthError, GitHubClient
from security_scanner.shared.llm.factory import build_llm_client
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.enums import GateDecision, ScanTarget, ScanType
from security_scanner.shared.models.scan_result import ScanResult
from security_scanner.skill.auth import verify_oauth_token
from security_scanner.skill.responses import format_skill_response

log = get_logger(__name__)

router = APIRouter(prefix="/skill", tags=["skill"])

_REPO_URL_RE = re.compile(r"^https://github\.com/[^/\s]+/[^/\s]+?(\.git)?/?$")

_EC_002_MESSAGE = (
    "The scan service is temporarily unavailable. Please try again in a few minutes."
)
_EC_005_MESSAGE = "GitHub authorisation failed. Please re-authorise and try again."


SkillPipelineFactory = Callable[[str], ScanPipeline]


class SkillScanRequest(BaseModel):
    repo_url: str
    scan_target: ScanTarget
    ref: str = "HEAD"
    base: str | None = None
    head: str | None = None
    directory: str = ""


def get_skill_pipeline_factory(
    settings: Annotated[Settings, Depends(get_settings)],
) -> SkillPipelineFactory:
    """Return a factory that builds an on-demand-mode pipeline.

    The factory takes the OAuth token at call time so the constructed
    ``GitHubClient`` runs in user-OAuth mode. Tests override this dep to
    inject a mock pipeline.
    """

    def build(oauth_token: str) -> ScanPipeline:
        github_client = GitHubClient(oauth_token=oauth_token)
        llm_client = build_llm_client(settings)
        return ScanPipeline(github_client, llm_client, mode=ScanType.on_demand)

    return build


_OAuthTokenDep = Annotated[str, Depends(verify_oauth_token)]
_FactoryDep = Annotated[SkillPipelineFactory, Depends(get_skill_pipeline_factory)]


@router.post("/scan")
async def scan(
    body: SkillScanRequest,
    oauth_token: _OAuthTokenDep,
    factory: _FactoryDep,
) -> dict:
    if not _REPO_URL_RE.match(body.repo_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Invalid repo_url; expected https://github.com/{org}/{repo} "
                f"(got {body.repo_url!r})"
            ),
        )

    pipeline = factory(oauth_token)

    try:
        result = await pipeline.run(
            repo_url=body.repo_url,
            scan_target=body.scan_target,
            triggered_by="(skill OAuth session)",
            ref=body.ref,
            base=body.base,
            head=body.head,
            directory=body.directory,
        )
    except TokenLimitError as exc:
        log.warning(
            "token-limit exceeded on skill scan",
            estimated_tokens=exc.estimated_tokens,
            threshold=exc.threshold,
        )
        return format_skill_response(_token_limit_result(body, exc), patches={})
    except ClaudeUnavailableError as exc:
        log.warning("claude unavailable on skill scan", reason=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_EC_002_MESSAGE,
        ) from exc
    except GitHubAuthError as exc:
        log.warning("github auth failed on skill scan", reason=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_EC_005_MESSAGE,
        ) from exc

    return format_skill_response(result, result.patches)


def _token_limit_result(body: SkillScanRequest, exc: TokenLimitError) -> ScanResult:
    """Synthesise a ``ScanResult`` for the BR-005 token-limit response."""
    return ScanResult(
        repo_url=body.repo_url,
        scan_target=body.scan_target,
        scan_type=ScanType.on_demand,
        triggered_by="(skill OAuth session)",
        findings_count=0,
        gate_decision=GateDecision.advisory,
        partial_scan=False,
        unscanned_files=[],
        findings=[],
        warnings=[
            f"Repository exceeds scan size limit "
            f"(~{exc.estimated_tokens} tokens, max {exc.threshold}). "
            "BR-005: recommend scanning by directory (pass directory= "
            "in the request body)."
        ],
    )
