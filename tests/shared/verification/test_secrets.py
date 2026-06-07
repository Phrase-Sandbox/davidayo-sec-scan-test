"""Tests for LLM verification of SECRET-001 Layer-2/3 findings."""

from unittest.mock import MagicMock

from security_scanner.shared.claude.client import ClaudeClient, ClaudeTimeoutError
from security_scanner.shared.models.enums import (
    Confidence,
    Severity,
    VerificationStatus,
)
from security_scanner.shared.models.finding import VulnerabilityFinding
from security_scanner.shared.secrets.stripper import SecretHit
from security_scanner.shared.verification.secrets import verify_secret_findings


def _finding(file: str = "src/x.py", line: int = 1) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        vulnerability_id="SECRET-001",
        severity=Severity.Critical,
        confidence=Confidence.High,
        cvss_band="9.0-10.0",
        affected_file=file,
        affected_lines=str(line),
        description="Hardcoded credential.",
        suggested_fix="Rotate.",
        owasp_reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        patch_file_path="",
        exploit_scenario="Attacker extracts.",
        verification_status=VerificationStatus.verified,
    )


def _hit(detector: str, file: str = "src/x.py", line: int = 1) -> SecretHit:
    return SecretHit(
        filename=file, line=line, end_line=line, hint="api_key = ", detector=detector
    )


def test_layer1_detectors_skip_llm_and_pass_through():
    client = MagicMock(spec=ClaudeClient)
    findings = [_finding(), _finding(), _finding()]
    hits = [_hit("github_pat"), _hit("anthropic"), _hit("aws_access_key")]
    files = {"src/x.py": "api_key = ghp_xxx\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert out == findings  # all kept
    client.ask.assert_not_called()  # no LLM calls for Layer-1


def test_layer2_real_verdict_keeps_finding():
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = "VERDICT: real\nValue is a literal credential in a YAML config."

    findings = [_finding(file="conf.yaml", line=3)]
    hits = [_hit("config_secret", file="conf.yaml", line=3)]
    files = {"conf.yaml": "db:\n  user: x\n  password: postgres\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert len(out) == 1
    assert "LLM verification:" in out[0].description
    client.ask.assert_called_once()


def test_layer3_false_positive_verdict_drops_finding():
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = "VERDICT: false_positive\nDocstring example, not a real secret."

    findings = [_finding()]
    hits = [_hit("detect_secrets")]
    files = {"src/x.py": "x = 1\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert out == []


def test_claude_error_keeps_finding_failsafe():
    client = MagicMock(spec=ClaudeClient)
    client.ask.side_effect = ClaudeTimeoutError("slow")

    findings = [_finding()]
    hits = [_hit("high_entropy")]
    files = {"src/x.py": "x = 'aaaaaaaaaaaaaaaaaaaa'\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert out == findings  # never silently drop on transport failure


def test_unparseable_response_keeps_finding_failsafe():
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = "I cannot determine."

    findings = [_finding()]
    hits = [_hit("config_secret")]
    files = {"src/x.py": "token = abc\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert out == findings


def test_mixed_batch_preserves_order():
    client = MagicMock(spec=ClaudeClient)
    # Two LLM-bound hits (b.py FP, d.py real) are now grouped into ONE
    # batched call. The response carries one indexed verdict per candidate.
    client.ask.return_value = (
        "VERDICT #1: false_positive\nObvious placeholder.\n"
        "VERDICT #2: real\nLooks like a credential.\n"
    )

    findings = [
        _finding(file="a.py", line=1),  # Layer 1 — kept
        _finding(file="b.py", line=2),  # Layer 2 FP — dropped
        _finding(file="c.py", line=3),  # Layer 1 — kept
        _finding(file="d.py", line=4),  # Layer 3 real — kept
    ]
    hits = [
        _hit("anthropic", file="a.py", line=1),
        _hit("config_secret", file="b.py", line=2),
        _hit("github_token", file="c.py", line=3),
        _hit("detect_secrets", file="d.py", line=4),
    ]
    files = {h.filename: "stub\n" * 5 for h in hits}

    out = verify_secret_findings(findings, hits, files, client)

    assert [f.affected_file for f in out] == ["a.py", "c.py", "d.py"]
    # Batched: two LLM-bound findings → one Claude call (was 2).
    assert client.ask.call_count == 1


def test_empty_input_short_circuits():
    client = MagicMock(spec=ClaudeClient)
    assert verify_secret_findings([], [], {}, client) == []
    client.ask.assert_not_called()


def test_missing_file_keeps_finding_failsafe():
    client = MagicMock(spec=ClaudeClient)
    findings = [_finding(file="gone.py")]
    hits = [_hit("config_secret", file="gone.py")]
    files: dict[str, str] = {}  # file disappeared

    out = verify_secret_findings(findings, hits, files, client)

    assert out == findings
    client.ask.assert_not_called()


def test_test_fixture_verdict_downgrades_to_medium():
    """A test_fixture verdict keeps the finding but lowers severity to Medium."""
    from security_scanner.shared.severity.mapping import severity_to_cvss_band

    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = (
        "VERDICT: test_fixture\nPlausible password in a SQL fixture file."
    )

    findings = [_finding(file="fixtures.sql", line=2)]
    hits = [_hit("sql_credential", file="fixtures.sql", line=2)]
    files = {"fixtures.sql": "-- seed data\nINSERT INTO users VALUES ('a', 'hunter2');\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert len(out) == 1
    assert out[0].severity == Severity.Medium
    assert out[0].cvss_band == severity_to_cvss_band(Severity.Medium)
    assert out[0].description.startswith("[Likely test fixture")
    assert "LLM verification:" in out[0].description


def test_mixed_verdicts_keep_real_and_test_fixture_drop_fp():
    """Real → kept Critical; test_fixture → kept Medium; false_positive → dropped."""
    client = MagicMock(spec=ClaudeClient)
    # All three findings now fit in one batched call (batch size 5).
    client.ask.return_value = (
        "VERDICT #1: real\nProduction Stripe key.\n"
        "VERDICT #2: test_fixture\nIn a fixtures file.\n"
        "VERDICT #3: false_positive\nPlaceholder XXX.\n"
    )

    findings = [
        _finding(file="prod.env", line=1),
        _finding(file="fixtures.sql", line=2),
        _finding(file="readme.md", line=3),
    ]
    hits = [
        _hit("config_secret", file="prod.env", line=1),
        _hit("sql_credential", file="fixtures.sql", line=2),
        _hit("detect_secrets", file="readme.md", line=3),
    ]
    files = {h.filename: "stub\n" * 5 for h in hits}

    out = verify_secret_findings(findings, hits, files, client)

    assert [(f.affected_file, f.severity) for f in out] == [
        ("prod.env", Severity.Critical),
        ("fixtures.sql", Severity.Medium),
    ]


def test_verifier_prompt_includes_all_three_verdicts():
    """Regression guard for the three-way verdict scheme."""
    from security_scanner.shared.verification.secrets import _VERIFY_SYSTEM_PROMPT

    for verdict_line in (
        "VERDICT: real",
        "VERDICT: test_fixture",
        "VERDICT: false_positive",
    ):
        assert verdict_line in _VERIFY_SYSTEM_PROMPT, f"missing: {verdict_line}"


def test_layer1_hit_in_template_file_is_sent_to_llm():
    """Template files override the Layer-1 auto-verify so placeholders get judged."""
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = "VERDICT: template_example\nPlaceholder line."

    findings = [_finding(file=".env.local.example", line=1)]
    hits = [_hit("anthropic", file=".env.local.example", line=1)]
    files = {".env.local.example": "ANTHROPIC_API_KEY=sk-ant-replace-with-real-key\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert len(out) == 1
    client.ask.assert_called_once()  # LLM was invoked despite Layer-1 detector


def test_layer1_hit_in_non_template_file_still_auto_verifies():
    """Regression guard: real code paths keep the Layer-1 auto-verify optimisation."""
    client = MagicMock(spec=ClaudeClient)
    findings = [_finding(file="src/app.py", line=1)]
    hits = [_hit("anthropic", file="src/app.py", line=1)]
    files = {"src/app.py": "API_KEY = 'sk-ant-real-looking-token-here'\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert out == findings
    client.ask.assert_not_called()


def test_template_example_verdict_downgrades_to_medium_with_policy():
    from security_scanner.shared.severity.mapping import severity_to_cvss_band

    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = (
        "VERDICT: template_example\nObvious placeholder in env template."
    )

    findings = [_finding(file=".env.local.example", line=1)]
    hits = [_hit("config_secret", file=".env.local.example", line=1)]
    files = {".env.local.example": "ANTHROPIC_API_KEY=sk-ant-replace-with-real-key\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert len(out) == 1
    assert out[0].severity == Severity.Medium
    assert out[0].cvss_band == severity_to_cvss_band(Severity.Medium)
    assert out[0].description.startswith("[Template placeholder")
    assert "1Password" in out[0].suggested_fix


def test_template_real_looking_value_stays_critical():
    """A real-shaped key in a template still gets reported as Critical."""
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = "VERDICT: real\nRealistic Anthropic key shape."

    findings = [_finding(file=".env.local.example", line=1)]
    hits = [_hit("anthropic", file=".env.local.example", line=1)]
    files = {".env.local.example": "X=sk-ant-api03-<80 chars of random>\n"}

    out = verify_secret_findings(findings, hits, files, client)

    assert len(out) == 1
    assert out[0].severity == Severity.Critical


def test_verifier_prompt_includes_template_example_verdict():
    """Regression guard: all four verdicts must remain documented in the prompt."""
    from security_scanner.shared.verification.secrets import _VERIFY_SYSTEM_PROMPT

    for verdict_line in (
        "VERDICT: real",
        "VERDICT: test_fixture",
        "VERDICT: template_example",
        "VERDICT: false_positive",
    ):
        assert verdict_line in _VERIFY_SYSTEM_PROMPT, f"missing: {verdict_line}"


def test_verifier_prompt_warns_against_todo_comment_fp():
    """Regression guard: the prompt must keep the explicit TODO-rotate warning.

    The torture-test showed the LLM suppressing a real ghp_ token in a
    ``# TODO: rotate ...`` comment because the previous prompt invited it
    to treat comments as placeholders. The hardened prompt must keep this
    guidance — pin the substring so a future edit can't silently drop it.
    """
    from security_scanner.shared.verification.secrets import _VERIFY_SYSTEM_PROMPT

    assert "TODO rotate" in _VERIFY_SYSTEM_PROMPT
    # And vendor shapes must be enumerated so the LLM has a checklist
    # rather than vague guidance.
    for shape in ("ghp_", "sk-ant-", "AKIA", "hooks.slack.com"):
        assert shape in _VERIFY_SYSTEM_PROMPT, f"missing vendor shape: {shape}"


# --- Batching + parallelism config ----------------------------------------


def test_max_parallelism_default_is_2(monkeypatch):
    monkeypatch.delenv("SECRET_VERIFIER_PARALLELISM", raising=False)
    import importlib

    import security_scanner.shared.verification.secrets as secrets_mod
    importlib.reload(secrets_mod)
    assert secrets_mod._MAX_PARALLELISM == 2


def test_max_parallelism_env_var_override(monkeypatch):
    monkeypatch.setenv("SECRET_VERIFIER_PARALLELISM", "6")
    import importlib

    import security_scanner.shared.verification.secrets as secrets_mod
    importlib.reload(secrets_mod)
    assert secrets_mod._MAX_PARALLELISM == 6


def test_max_parallelism_env_var_clamped_and_validated(monkeypatch):
    import importlib

    import security_scanner.shared.verification.secrets as secrets_mod

    monkeypatch.setenv("SECRET_VERIFIER_PARALLELISM", "99")
    importlib.reload(secrets_mod)
    assert secrets_mod._MAX_PARALLELISM == 16  # clamped down to max

    monkeypatch.setenv("SECRET_VERIFIER_PARALLELISM", "-5")
    importlib.reload(secrets_mod)
    assert secrets_mod._MAX_PARALLELISM == 1  # clamped up to min

    monkeypatch.setenv("SECRET_VERIFIER_PARALLELISM", "not-a-number")
    importlib.reload(secrets_mod)
    assert secrets_mod._MAX_PARALLELISM == 2  # falls back to default

    # Restore default for subsequent tests.
    monkeypatch.delenv("SECRET_VERIFIER_PARALLELISM", raising=False)
    importlib.reload(secrets_mod)


def test_batch_of_three_findings_uses_one_llm_call():
    """Three LLM-bound findings fit in one batched call (BATCH_SIZE = 5)."""
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = (
        "VERDICT #1: real\nKey #1.\n"
        "VERDICT #2: real\nKey #2.\n"
        "VERDICT #3: real\nKey #3.\n"
    )

    findings = [_finding(file=f"f{i}.py", line=i) for i in (1, 2, 3)]
    hits = [_hit("config_secret", file=f"f{i}.py", line=i) for i in (1, 2, 3)]
    files = {h.filename: "stub\n" * 5 for h in hits}

    out = verify_secret_findings(findings, hits, files, client)

    assert len(out) == 3
    assert client.ask.call_count == 1


def test_batched_response_with_missing_verdict_keeps_finding_failsafe():
    """If the LLM omits a verdict for candidate #2, that finding is KEPT (fail-safe)."""
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = (
        "VERDICT #1: false_positive\nPlaceholder.\n"
        # No VERDICT #2 — should fail-safe to keep finding 2.
        "VERDICT #3: false_positive\nAlso placeholder.\n"
    )

    findings = [_finding(file=f"f{i}.py", line=i) for i in (1, 2, 3)]
    hits = [_hit("config_secret", file=f"f{i}.py", line=i) for i in (1, 2, 3)]
    files = {h.filename: "stub\n" * 5 for h in hits}

    out = verify_secret_findings(findings, hits, files, client)

    # #1 dropped (FP), #2 kept (no verdict → fail-safe), #3 dropped (FP).
    assert [f.affected_file for f in out] == ["f2.py"]


def test_batched_response_with_misordered_verdicts():
    """Index-aware parser routes out-of-order verdicts correctly."""
    client = MagicMock(spec=ClaudeClient)
    # LLM emits in reverse order.
    client.ask.return_value = (
        "VERDICT #3: real\nReal #3.\n"
        "VERDICT #1: false_positive\nPlaceholder #1.\n"
        "VERDICT #2: test_fixture\nFixture #2.\n"
    )

    findings = [_finding(file=f"f{i}.py", line=i) for i in (1, 2, 3)]
    hits = [_hit("config_secret", file=f"f{i}.py", line=i) for i in (1, 2, 3)]
    files = {h.filename: "stub\n" * 5 for h in hits}

    out = verify_secret_findings(findings, hits, files, client)

    severities = {(f.affected_file, f.severity) for f in out}
    assert severities == {("f2.py", Severity.Medium), ("f3.py", Severity.Critical)}


def test_unbatched_single_finding_response_still_parses():
    """A 1-candidate batch with the legacy ``VERDICT: real`` shape still works."""
    client = MagicMock(spec=ClaudeClient)
    client.ask.return_value = "VERDICT: real\nLegacy single-finding response."

    findings = [_finding(file="x.py", line=1)]
    hits = [_hit("config_secret", file="x.py", line=1)]
    files = {"x.py": "stub\n" * 5}

    out = verify_secret_findings(findings, hits, files, client)

    assert len(out) == 1
    assert out[0].severity == Severity.Critical
