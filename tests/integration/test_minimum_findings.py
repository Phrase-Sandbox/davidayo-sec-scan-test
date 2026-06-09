"""Minimum-findings quality gate — asserts the scanner finds >= 9 issues on a
comprehensive vulnerable payload.

This test uses the real Layer-1 scanners (Bandit + Semgrep) with NO LLM call,
making it fully deterministic and suitable for CI.  It is the hard enforcement
of the "< 9 findings is never acceptable" bar.

Structure
---------
Layer-1 scanners (Bandit, Semgrep) run on the fixture file directly.
Each of the 9 mandatory vulnerability patterns maps to at least one Bandit or
Semgrep rule, so the combined candidate list must reach 9 distinct lines.

Skips if neither Bandit nor Semgrep is installed (mirrors graceful-degrade
policy elsewhere in the test suite).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

_FIXTURE = Path(__file__).parents[2] / "tests" / "fixtures" / "vuln_comprehensive.py"

_REQUIRES_BANDIT = pytest.mark.skipif(
    shutil.which("bandit") is None,
    reason="bandit binary not installed — install to run minimum-findings gate",
)
_REQUIRES_SEMGREP = pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep binary not installed — install to run minimum-findings gate",
)

MINIMUM_FINDINGS = 9
"""Scanner must report at least this many distinct candidate findings on the
comprehensive fixture.  Any regression that drops the count below this number
will fail this test."""


def _read_fixture() -> dict[str, str]:
    """Load the comprehensive vulnerable fixture as a {path: content} dict."""
    return {"vuln_comprehensive.py": _FIXTURE.read_text(encoding="utf-8")}


# ---------------------------------------------------------------------------
# Layer-1 (Bandit) — deterministic, no LLM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@_REQUIRES_BANDIT
async def test_bandit_minimum_findings() -> None:
    """Bandit alone must find >= 9 candidates on the comprehensive fixture.

    Bandit rules triggered:
      B105 hardcoded_password_string  (DB_PASSWORD, STRIPE_SECRET_KEY)
      B608 hardcoded_sql_expressions  (f-string + % format queries)
      B605 start_process_with_a_shell (os.system)
      B602 subprocess_popen_with_shell_equals_true (subprocess shell=True)
      B303 use_of_md5                 (hashlib.md5)
      B311 standard_pseudo_random_generators (random.randint)
      B301 pickle                     (pickle.loads)
      B506 yaml_load                  (yaml.load without Loader)
    """
    from security_scanner.shared.scanners.adapters.bandit import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    files = _read_fixture()

    async with ScannerWorkspace(scan_id="min-findings-bandit") as ws:
        for path, content in files.items():
            await ws.write_file(path, content)
        candidates = await scan(ws)

    count = len(candidates)
    assert count >= MINIMUM_FINDINGS, (
        f"Bandit found only {count} candidates on the comprehensive fixture "
        f"(minimum required: {MINIMUM_FINDINGS}).\n"
        f"Candidates: {[(c.file, c.vuln_class, c.line_start) for c in candidates]}"
    )


# ---------------------------------------------------------------------------
# Layer-1 (Semgrep) — deterministic, no LLM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@_REQUIRES_SEMGREP
async def test_semgrep_minimum_findings() -> None:
    """Semgrep alone must find >= 9 candidates on the comprehensive fixture.

    Semgrep rules triggered (from semgrep_configs/):
      python-sqli-fstring           (f-string SELECT)
      python-sqli-string-format     (% format SELECT)
      python-os-system-input        (os.system)
      python-subprocess-shell-true  (subprocess shell=True)
      python-hashlib-md5            (hashlib.md5)
      python-random-security        (random.randint)
      python-pickle-loads           (pickle.loads)
      python-xml-parse-no-defusedxml (ET.parse)
      python-yaml-load-unsafe       (yaml.load)
    """
    from security_scanner.shared.scanners.adapters.semgrep import scan
    from security_scanner.shared.scanners.workdir import ScannerWorkspace

    files = _read_fixture()

    async with ScannerWorkspace(scan_id="min-findings-semgrep") as ws:
        for path, content in files.items():
            await ws.write_file(path, content)
        candidates = await scan(ws)

    count = len(candidates)
    assert count >= MINIMUM_FINDINGS, (
        f"Semgrep found only {count} candidates on the comprehensive fixture "
        f"(minimum required: {MINIMUM_FINDINGS}).\n"
        f"Candidates: {[(c.file, c.vuln_class, c.line_start) for c in candidates]}"
    )


# ---------------------------------------------------------------------------
# Combined Layer-1 (Bandit + Semgrep merged) — primary quality gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.skipif(
    shutil.which("bandit") is None and shutil.which("semgrep") is None,
    reason="neither bandit nor semgrep installed — install at least one",
)
async def test_combined_layer1_minimum_findings() -> None:
    """Combined Bandit + Semgrep must produce >= 9 DISTINCT candidates
    (after merge deduplication) on the comprehensive fixture.

    This is the PRIMARY quality gate.  Failing here means the scanner cannot
    meet the minimum recall bar on a known vulnerable payload — a blocker.
    """
    from security_scanner.shared.scanners import run_layer1

    files = _read_fixture()
    candidates = await run_layer1(files, scan_id="min-findings-combined")

    # Deduplicate by (file, vuln_class, line_start) to count distinct issues,
    # not raw tool-firing count.
    distinct: set[tuple[str, str, int]] = set()
    for c in candidates:
        distinct.add((c.file, c.vuln_class, c.line_start))

    count = len(distinct)
    assert count >= MINIMUM_FINDINGS, (
        f"Combined Layer-1 found only {count} distinct candidates "
        f"(minimum required: {MINIMUM_FINDINGS}).\n"
        f"Distinct findings: {sorted(distinct)}"
    )


# ---------------------------------------------------------------------------
# Pipeline integration test — mocked LLM returning all 9 mandatory findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pipeline_minimum_findings_with_mock_llm() -> None:
    """Full pipeline with a mocked LLM client must return >= 9 findings.

    The mock is configured to return all 9 mandatory findings from the
    comprehensive fixture.  This validates that:
    1. The pipeline doesn't silently drop findings through post-filter.
    2. The verifier (also mocked as 'real + high confidence') keeps all 9.
    3. Secret findings from the stripper are added on top.

    No external binaries required — entirely self-contained.
    """
    from unittest.mock import AsyncMock, MagicMock

    from security_scanner.pipeline import ScanPipeline
    from security_scanner.shared.claude.client import ClaudeClient
    from security_scanner.shared.github.client import GitHubClient
    from security_scanner.shared.models.enums import ScanTarget, ScanType

    files = _read_fixture()

    # 9 mandatory findings the LLM first-pass returns.
    # exploit_scenario MUST: (a) embed affected_file verbatim, (b) contain ≥1 of:
    # payload|request|query|parameter|injection|bypass|forge
    llm_findings: list[dict] = [
        {
            "vulnerability_id": "A03:2021",
            "severity": "High",
            "confidence": "High",
            "cvss_band": "7.0-8.9",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "31-34",
            "description": "SQL injection via f-string interpolation.",
            "suggested_fix": "Use parameterised queries.",
            "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker sends a crafted query parameter to vuln_comprehensive.py causing SQL injection via f-string interpolation.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A03:2021",
            "severity": "High",
            "confidence": "High",
            "cvss_band": "7.0-8.9",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "39-42",
            "description": "SQL injection via % string format.",
            "suggested_fix": "Use parameterised queries.",
            "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker crafts a malicious query parameter passed to vuln_comprehensive.py to perform SQL injection via % formatting.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A03:2021",
            "severity": "Critical",
            "confidence": "High",
            "cvss_band": "9.0-10.0",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "46-47",
            "description": "Command injection via os.system.",
            "suggested_fix": "Use subprocess with list args and shell=False.",
            "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker passes a shell injection payload via the host parameter in vuln_comprehensive.py to execute arbitrary OS commands.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A03:2021",
            "severity": "Critical",
            "confidence": "High",
            "cvss_band": "9.0-10.0",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "52-55",
            "description": "Command injection via subprocess shell=True.",
            "suggested_fix": "Use shell=False with list argument.",
            "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker injects OS commands via report_name parameter in vuln_comprehensive.py by passing a semicolon payload with shell=True.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A02:2021",
            "severity": "High",
            "confidence": "High",
            "cvss_band": "7.0-8.9",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "61-62",
            "description": "Weak hash function: MD5 used for passwords.",
            "suggested_fix": "Use bcrypt or argon2.",
            "owasp_reference": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker obtains the MD5 hash from vuln_comprehensive.py and performs an offline dictionary or rainbow-table attack to recover the original password.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A02:2021",
            "severity": "High",
            "confidence": "High",
            "cvss_band": "7.0-8.9",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "67-68",
            "description": "Insecure PRNG used for session token.",
            "suggested_fix": "Use secrets.token_hex().",
            "owasp_reference": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker exploits the predictable token generated by random.randint in vuln_comprehensive.py to forge a valid session and bypass authentication.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A08:2021",
            "severity": "Critical",
            "confidence": "High",
            "cvss_band": "9.0-10.0",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "73-74",
            "description": "Insecure deserialization via pickle.loads.",
            "suggested_fix": "Use JSON or a safe format.",
            "owasp_reference": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker sends a crafted pickle payload to vuln_comprehensive.py which pickle.loads deserializes, triggering arbitrary code execution.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A05:2021",
            "severity": "High",
            "confidence": "High",
            "cvss_band": "7.0-8.9",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "79-80",
            "description": "XXE vulnerability via xml.etree.ElementTree.",
            "suggested_fix": "Use defusedxml.ElementTree.",
            "owasp_reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker provides a malicious XML payload to vuln_comprehensive.py that triggers XXE and allows reading internal server files via entity injection.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
        {
            "vulnerability_id": "A08:2021",
            "severity": "Critical",
            "confidence": "High",
            "cvss_band": "9.0-10.0",
            "affected_file": "vuln_comprehensive.py",
            "affected_lines": "85-87",
            "description": "Unsafe yaml.load — allows arbitrary object instantiation.",
            "suggested_fix": "Use yaml.safe_load().",
            "owasp_reference": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            "patch_file_path": "",
            "exploit_scenario": "Attacker sends a crafted YAML payload to vuln_comprehensive.py that yaml.load deserializes into an arbitrary Python object, enabling remote code execution.",
            "verification_status": "unverified",
            "sources": ["claude"],
        },
    ]

    # GitHub mock returns our fixture files
    gh_mock = MagicMock(spec=GitHubClient)
    gh_mock.get_repo_files.return_value = files
    gh_mock.get_diff_files.return_value = files

    # Claude mock returns the 9 LLM findings + always verifies as real/high
    claude_mock = MagicMock(spec=ClaudeClient)
    claude_mock.analyse_async_chunked = AsyncMock(return_value=(llm_findings, []))
    # Verifier: always "real, high confidence" for every candidate
    verifier_response = "\n".join(
        f"VERDICT #{i + 1}: real\nCONFIDENCE #{i + 1}: high\nREASON #{i + 1}: Confirmed.\n"
        for i in range(len(llm_findings) + 5)  # extra headroom for scanner merge
    )
    claude_mock.ask = MagicMock(return_value=verifier_response)
    claude_mock.ask_async = AsyncMock(return_value=verifier_response)
    claude_mock.analyse = MagicMock(return_value=llm_findings)

    pipeline = ScanPipeline(
        github_client=gh_mock,
        claude_client=claude_mock,
        mode=ScanType.on_demand,
    )

    result = await pipeline.run(
        repo_url="https://github.com/test/comprehensive-vuln-fixture",
        scan_target=ScanTarget.full_repo,
        triggered_by="pytest",
    )

    # Secret findings (from the stripper on DB_PASSWORD + STRIPE_SECRET_KEY)
    # are added on top of the LLM findings. Total must be >= 9.
    total = result.findings_count
    assert total >= MINIMUM_FINDINGS, (
        f"Pipeline returned only {total} findings on the comprehensive fixture "
        f"(minimum required: {MINIMUM_FINDINGS}).\n"
        f"Findings: {[(f.vulnerability_id, f.severity, f.verification_status.value) for f in result.findings]}"
    )

    # Additionally, every mandatory OWASP class must be represented.
    found_classes = {f.vulnerability_id for f in result.findings}
    for required_class in ("A03:2021", "A02:2021", "A08:2021"):
        assert any(required_class in vid for vid in found_classes), (
            f"Required OWASP class {required_class} missing from findings. "
            f"Found classes: {found_classes}"
        )
