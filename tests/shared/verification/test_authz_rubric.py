"""Tests for the authz verifier rubric (Section C)."""

from __future__ import annotations

from security_scanner.shared.verification.prompts import (
    build_authz_verifier_rubric,
    build_vuln_verifier_system_prompt,
)

# ---------------------------------------------------------------------------
# Literal phrases required by the plan (asserted character-for-character).
# ---------------------------------------------------------------------------

_PHRASE_1 = "Trace how this code is reached (route/middleware)"
_PHRASE_2 = "where (if at all) ownership or permission checks are enforced"
_PHRASE_3 = (
    "Treat missing ownership/permission checks on attacker-controlled identifiers as a real "
    "vulnerability, even if the data access call looks safe in isolation"
)


def test_authz_rubric_contains_trace_phrase():
    rubric = build_authz_verifier_rubric()
    assert _PHRASE_1 in rubric, f"Missing phrase: {_PHRASE_1!r}"


def test_authz_rubric_contains_ownership_phrase():
    rubric = build_authz_verifier_rubric()
    assert _PHRASE_2 in rubric, f"Missing phrase: {_PHRASE_2!r}"


def test_authz_rubric_contains_treat_missing_phrase():
    rubric = build_authz_verifier_rubric()
    assert _PHRASE_3 in rubric, f"Missing phrase: {_PHRASE_3!r}"


# ---------------------------------------------------------------------------
# System prompt inclusion / exclusion by vuln_class.
# ---------------------------------------------------------------------------

def test_auth_bypass_class_includes_rubric():
    prompt = build_vuln_verifier_system_prompt(vuln_class="auth_bypass")
    assert _PHRASE_1 in prompt
    assert _PHRASE_2 in prompt
    assert _PHRASE_3 in prompt


def test_idor_class_includes_rubric():
    prompt = build_vuln_verifier_system_prompt(vuln_class="idor")
    assert _PHRASE_1 in prompt
    assert _PHRASE_2 in prompt
    assert _PHRASE_3 in prompt


def test_sqli_class_excludes_rubric():
    prompt = build_vuln_verifier_system_prompt(vuln_class="sqli")
    assert _PHRASE_1 not in prompt
    assert _PHRASE_2 not in prompt
    assert _PHRASE_3 not in prompt


def test_xss_class_excludes_rubric():
    prompt = build_vuln_verifier_system_prompt(vuln_class="xss")
    assert _PHRASE_1 not in prompt


def test_no_class_excludes_rubric():
    """Existing no-arg call must still work and must NOT include the authz rubric."""
    prompt = build_vuln_verifier_system_prompt()
    assert _PHRASE_1 not in prompt


def test_case_insensitive_class():
    """vuln_class matching should be case-insensitive."""
    prompt_upper = build_vuln_verifier_system_prompt(vuln_class="IDOR")
    prompt_mixed = build_vuln_verifier_system_prompt(vuln_class="Auth_Bypass")
    assert _PHRASE_1 in prompt_upper
    assert _PHRASE_1 in prompt_mixed


def test_base_required_literal_still_present_with_authz_rubric():
    """The mandatory anti-excuse literal must still be present when rubric is appended."""
    _REQUIRED_LITERAL = (
        "Do NOT excuse this as a test fixture, demo, example, template, documentation, "
        "README, comment, or hypothetical. The code IS production code. Decide whether "
        "— running unchanged in production against attacker-controlled input — this is "
        "exploitable as written. Answer `real` only if you can name the exploit input "
        "and trace the data flow in the supplied code."
    )
    prompt = build_vuln_verifier_system_prompt(vuln_class="idor")
    assert _REQUIRED_LITERAL in prompt
