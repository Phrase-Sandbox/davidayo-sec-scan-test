"""Integration-style tests for the scan pipeline (spec §2.2)."""

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.claude.client import (
    ClaudeClient,
    ClaudeTimeoutError,
    ClaudeUnavailableError,
)
from security_scanner.shared.github.client import GitHubAuthError, GitHubClient
from security_scanner.shared.models.enums import (
    GateDecision,
    ScanTarget,
    ScanType,
)

# --- Helpers ----------------------------------------------------------------


def _run(pipeline: ScanPipeline, **kwargs):
    return asyncio.run(pipeline.run(**kwargs))


def _gh(files_or_diff: dict[str, str] | None = None) -> MagicMock:
    mock = MagicMock(spec=GitHubClient)
    mock.get_repo_files.return_value = files_or_diff or {}
    mock.get_diff_files.return_value = files_or_diff or {}
    return mock


def _claude(findings: list[dict] | None = None) -> MagicMock:
    mock = MagicMock(spec=ClaudeClient)
    mock.analyse.return_value = findings or []
    # The verifier on the gate path calls .ask() — default to "yes" so any
    # Critical finding is verified unless a test overrides.
    mock.ask.return_value = "VERDICT: yes"
    return mock


_REPO = "https://github.com/Phrase-Launchpad/example"


def _high_finding_dict(*, file: str = "src/handlers/login.py") -> dict:
    return {
        "vulnerability_id": "A03:2021",
        "severity": "High",
        "confidence": "High",
        "cvss_band": "7.0-8.9",
        "affected_file": file,
        "affected_lines": "42-55",
        "description": "SQL injection.",
        "suggested_fix": (
            "Use a parameterised query:\n"
            "```\nq = db.exec('SELECT ? FROM users', user_id)\n```"
        ),
        "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
        "patch_file_path": "patches/x.patch",
        "exploit_scenario": (
            f"Attacker sends username=admin' OR '1'='1 as a login payload "
            f"to {file} bypassing the WHERE clause."
        ),
        "verification_status": "unverified",
    }


# --- Happy path -------------------------------------------------------------


def test_happy_path_high_high_finding_blocks_gate():
    files = {"src/handlers/login.py": "def login(u):\n    return q(u)\n"}
    github = _gh(files)
    claude = _claude([_high_finding_dict()])

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    assert result.gate_decision == GateDecision.blocked
    assert result.findings_count == 1
    assert result.findings[0].vulnerability_id == "A03:2021"


def test_skill_path_does_not_run_verification():
    files = {"src/handlers/login.py": "def login(u):\n    return q(u)\n"}
    github = _gh(files)
    claude = _claude([_high_finding_dict()])

    _run(
        ScanPipeline(github, claude, mode=ScanType.on_demand),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    # Skill path skips BR-009 — no .ask() calls.
    claude.ask.assert_not_called()


def test_gate_path_verifies_critical_findings_via_ask():
    critical = _high_finding_dict()
    critical["severity"] = "Critical"
    critical["cvss_band"] = "9.0-10.0"
    files = {"src/handlers/login.py": "def login(u):\n    return q(u)\n"}
    github = _gh(files)
    claude = _claude([critical])

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    claude.ask.assert_called_once()
    assert result.gate_decision == GateDecision.blocked
    assert result.findings[0].verification_status.value == "verified"


# --- Empty input -----------------------------------------------------------


def test_no_files_returned_results_in_advisory():
    github = _gh(files_or_diff={})
    claude = _claude()

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    assert result.gate_decision == GateDecision.advisory
    assert result.findings == []
    claude.analyse.assert_not_called()


def test_empty_diff_skips_scan_and_is_advisory():
    """BR-004 / EC-008: zero changed files → skip scan."""
    github = _gh(files_or_diff={})
    claude = _claude()

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.diff,
        triggered_by="alice@phrase.com",
        base="abc",
        head="def",
    )

    assert result.gate_decision == GateDecision.advisory
    claude.analyse.assert_not_called()


def test_diff_target_without_base_or_head_is_scan_failed():
    github = _gh()
    claude = _claude()

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.diff,
        triggered_by="alice@phrase.com",
    )

    assert result.gate_decision == GateDecision.scan_failed
    github.get_repo_files.assert_not_called()
    github.get_diff_files.assert_not_called()


# --- Secret stripping (BR-003) ---------------------------------------------


def test_secret_detected_produces_secret_001_critical_finding():
    files = {"src/config.py": 'API_KEY = "ghp_' + "X" * 36 + '"\n'}
    github = _gh(files)
    claude = _claude([])  # no Claude findings — just the secret

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    secret_findings = [f for f in result.findings if f.vulnerability_id == "SECRET-001"]
    assert len(secret_findings) == 1
    finding = secret_findings[0]
    assert finding.severity.value == "Critical"
    assert finding.confidence.value == "High"
    assert finding.affected_file == "src/config.py"
    # Secret detection is deterministic — pre-verified, no BR-009 needed.
    assert finding.verification_status.value == "verified"


def test_secret_finding_blocks_gate():
    files = {"src/config.py": 'API_KEY = "ghp_' + "X" * 36 + '"\n'}
    github = _gh(files)
    claude = _claude([])

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    assert result.gate_decision == GateDecision.blocked


def test_secret_value_never_sent_to_claude():
    fake_secret = "ghp_" + "Y" * 36
    files = {"src/config.py": f'API_KEY = "{fake_secret}"\n'}
    github = _gh(files)
    claude = _claude([])

    _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    # If Claude was called at all, the user message must not contain the secret.
    if claude.analyse.called:
        sent_files = claude.analyse.call_args.args[0]
        assert all(fake_secret not in c for c in sent_files.values())


# --- Claude unavailable (BR-006, EC-001/EC-002) ----------------------------


def test_claude_unavailable_on_gate_path_results_in_advisory_not_blocked():
    """BR-006 — gate fails open on infrastructure failure."""
    files = {"src/app.py": "x = 1\n"}
    github = _gh(files)
    claude = _claude()
    claude.analyse.side_effect = ClaudeUnavailableError("retries exhausted")

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    assert result.gate_decision == GateDecision.advisory
    assert result.findings == []


def test_claude_unavailable_on_skill_path_is_raised_to_caller():
    files = {"src/app.py": "x = 1\n"}
    github = _gh(files)
    claude = _claude()
    claude.analyse.side_effect = ClaudeUnavailableError("retries exhausted")

    with pytest.raises(ClaudeUnavailableError):
        _run(
            ScanPipeline(github, claude, mode=ScanType.on_demand),
            repo_url=_REPO,
            scan_target=ScanTarget.full_repo,
            triggered_by="alice@phrase.com",
        )


# --- Claude timeout (EC-004) -----------------------------------------------


def test_claude_timeout_sets_partial_scan_and_lists_unscanned_files():
    files = {"src/a.py": "x = 1\n", "src/b.py": "y = 2\n"}
    github = _gh(files)
    claude = _claude()
    claude.analyse.side_effect = ClaudeTimeoutError("30s timeout")

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    assert result.partial_scan is True
    assert set(result.unscanned_files) == set(files.keys())
    assert result.findings == []
    # No blocking findings but partial → advisory.
    assert result.gate_decision == GateDecision.advisory


# --- Token limit (BR-005) --------------------------------------------------


def test_token_limit_exceeded_raises_token_limit_error():
    # 600,001 chars → 150,000.25 tokens → strictly exceeds the 150,000 threshold.
    big = {"src/big.py": "x" * 600_001}
    github = _gh(big)
    claude = _claude()

    with pytest.raises(TokenLimitError):
        _run(
            ScanPipeline(github, claude, mode=ScanType.deployment_gate),
            repo_url=_REPO,
            scan_target=ScanTarget.full_repo,
            triggered_by="alice@phrase.com",
        )
    claude.analyse.assert_not_called()


# --- URL parsing -----------------------------------------------------------


def test_invalid_repo_url_results_in_scan_failed():
    github = _gh()
    claude = _claude()

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url="not-a-url",
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    assert result.gate_decision == GateDecision.scan_failed
    github.get_repo_files.assert_not_called()


def test_ssh_repo_url_is_parsed_correctly():
    files = {"src/app.py": "x = 1\n"}
    github = _gh(files)
    claude = _claude([])

    _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url="git@github.com:Phrase-Launchpad/example.git",
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    call = github.get_repo_files.call_args
    assert call.args[0] == "Phrase-Launchpad"
    assert call.args[1] == "example"


# --- GitHub failures -------------------------------------------------------


def test_github_auth_error_is_propagated_not_degraded():
    """Auth errors are unrecoverable — let the caller surface EC-005/EC-006."""
    github = _gh()
    github.get_repo_files.side_effect = GitHubAuthError("401")
    claude = _claude()

    with pytest.raises(GitHubAuthError):
        _run(
            ScanPipeline(github, claude, mode=ScanType.deployment_gate),
            repo_url=_REPO,
            scan_target=ScanTarget.full_repo,
            triggered_by="alice@phrase.com",
        )


# --- Patch generation side effect ------------------------------------------


def test_patches_are_generated_and_attached_to_findings():
    """generate_all_patches must run inside the pipeline so patch_file_path is updated."""
    files = {"src/handlers/login.py": "line 1\nline 2\nline 3\nline 4\nline 5\n"}
    github = _gh(files)
    # The default suggested_fix from _high_finding_dict has a code block.
    finding_dict = _high_finding_dict()
    finding_dict["affected_lines"] = "2-3"
    claude = _claude([finding_dict])

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    finding = result.findings[0]
    # The pipeline overwrote Claude's "patches/x.patch" with the canonical
    # {scan_id}_{index}_{basename}.patch form.
    assert finding.patch_file_path.endswith("_0_login.py.patch")
    assert str(result.scan_id) in finding.patch_file_path


# --- Filtering interaction -------------------------------------------------


def test_findings_in_test_directories_are_post_filtered():
    files = {"src/handlers/login.py": "def x(): pass\n"}
    github = _gh(files)
    test_path_finding = _high_finding_dict(file="src/handlers/login.py")
    test_path_finding["affected_file"] = "tests/test_login.py"
    test_path_finding["exploit_scenario"] = test_path_finding["exploit_scenario"].replace(
        "src/handlers/login.py", "tests/test_login.py",
    )
    real_finding = _high_finding_dict(file="src/handlers/login.py")
    real_finding["vulnerability_id"] = "A05:2021"
    claude = _claude([test_path_finding, real_finding])

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    surviving_ids = [f.vulnerability_id for f in result.findings]
    assert "A03:2021" not in surviving_ids  # the test-path one
    assert "A05:2021" in surviving_ids


# --- Smoke: response is JSON-serialisable (lets callers ship as artifact) --


def test_scan_result_serialises_to_json():
    files = {"src/app.py": "x = 1\n"}
    github = _gh(files)
    claude = _claude([_high_finding_dict(file="src/app.py")])

    result = _run(
        ScanPipeline(github, claude, mode=ScanType.deployment_gate),
        repo_url=_REPO,
        scan_target=ScanTarget.full_repo,
        triggered_by="alice@phrase.com",
    )

    data = json.loads(result.model_dump_json())
    assert data["findings_count"] >= 1
    assert "gate_decision" in data
