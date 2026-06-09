"""Tests for vuln_names.py — ID-to-name mapping."""

from security_scanner.shared.reports.vuln_names import vuln_display_name

# Full taxonomy from shared/scanners/normalize.py lines 10–15
_TAXONOMY = [
    "sqli",
    "xss",
    "command_injection",
    "path_traversal",
    "ssrf",
    "deserialization",
    "weak_crypto",
    "xxe",
    "csrf",
    "open_redirect",
    "auth_bypass",
    "code_injection",
    "insecure_random",
    "unsafe_yaml",
    "unsafe_file_upload",
    "injection_generic",
    "redos",
    "runtime_panic",
    "subprocess_usage",
    "insecure_network_config",
    "poor_error_handling",
    "info_disclosure",
    "insecure_design",
    "security_misconfiguration",
    "vulnerable_components",
    "logging_monitoring_failure",
    "memory_safety",
    "ldap_injection",
    "nosqli",
    "hardcoded_secret",
]


def test_known_owasp_ids_return_names() -> None:
    assert vuln_display_name("A01:2021") == "Broken Access Control"
    assert vuln_display_name("A02:2021") == "Cryptographic Failures"
    assert vuln_display_name("A03:2021") == "Injection"
    assert vuln_display_name("A05:2021") == "Security Misconfiguration"
    assert vuln_display_name("A10:2021") == "Server-Side Request Forgery"


def test_known_llm_ids_return_names() -> None:
    assert vuln_display_name("LLM01:2025") == "Prompt Injection"
    assert vuln_display_name("LLM06:2025") == "Excessive Agency"
    assert vuln_display_name("LLM10:2025") == "Unbounded Consumption"


def test_known_scanner_ids_return_names() -> None:
    assert vuln_display_name("XSS") == "Cross-Site Scripting"
    assert vuln_display_name("WEAK_CRYPTO") == "Weak Cryptography"
    assert vuln_display_name("SECRET-001") == "Hardcoded Credential"
    assert vuln_display_name("SQLI") == "SQL Injection"
    assert vuln_display_name("COMMAND_INJECTION") == "Command Injection"


def test_unknown_id_returns_empty_string() -> None:
    assert vuln_display_name("UNKNOWN_CODE") == ""
    assert vuln_display_name("") == ""
    assert vuln_display_name("B101") == ""


def test_all_taxonomy_members_covered() -> None:
    missing = [cls for cls in _TAXONOMY if not vuln_display_name(cls.upper())]
    assert missing == [], f"No display name for scanner IDs: {missing}"
