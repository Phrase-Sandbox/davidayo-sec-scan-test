"""Tests for the normalisation mapping tables."""

from __future__ import annotations

from security_scanner.shared.scanners.normalize import normalize


def test_bandit_b608_maps_to_sqli() -> None:
    assert normalize("bandit", "B608") == "sqli"


def test_bandit_b301_maps_to_deserialization() -> None:
    assert normalize("bandit", "B301") == "deserialization"


def test_bandit_b311_maps_to_insecure_random() -> None:
    assert normalize("bandit", "B311") == "insecure_random"


def test_gosec_g201_maps_to_sqli() -> None:
    assert normalize("gosec", "G201") == "sqli"


def test_gosec_g401_maps_to_weak_crypto() -> None:
    assert normalize("gosec", "G401") == "weak_crypto"


def test_gosec_g404_maps_to_insecure_random() -> None:
    assert normalize("gosec", "G404") == "insecure_random"


def test_semgrep_sqli_maps_to_sqli() -> None:
    assert normalize("semgrep", "python-sqli-string-format") == "sqli"


def test_semgrep_eval_maps_to_code_injection() -> None:
    assert normalize("semgrep", "python-eval-input") == "code_injection"


def test_eslint_sql_maps_to_sqli() -> None:
    assert normalize("eslint", "security/detect-sql-literal-injection") == "sqli"


def test_eslint_child_process_maps_to_command_injection() -> None:
    assert normalize("eslint", "security/detect-child-process") == "command_injection"


def test_unknown_rule_falls_back_gracefully() -> None:
    """Unknown rule IDs produce a sanitised string rather than raising."""
    result = normalize("bandit", "B999")
    assert isinstance(result, str)
    assert len(result) > 0


def test_unknown_tool_falls_back_gracefully() -> None:
    """Unknown tool names produce a sanitised string rather than raising."""
    result = normalize("unknown_tool", "SOME-RULE")
    assert isinstance(result, str)


def test_case_insensitive_tool() -> None:
    """Tool names are normalised to lowercase."""
    assert normalize("Bandit", "B608") == "sqli"
    assert normalize("BANDIT", "B608") == "sqli"


# ---------------------------------------------------------------------------
# V3: unsafe_file_upload taxonomy additions
# ---------------------------------------------------------------------------

def test_semgrep_upload_attacker_filename_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-attacker-filename") == "unsafe_file_upload"


def test_semgrep_upload_extension_only_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-extension-only") == "unsafe_file_upload"


def test_semgrep_upload_mime_only_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-mime-only") == "unsafe_file_upload"


def test_semgrep_upload_zip_slip_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-zip-slip") == "unsafe_file_upload"


def test_semgrep_upload_risky_parser_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-risky-parser") == "unsafe_file_upload"


def test_semgrep_upload_webroot_storage_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-webroot-storage") == "unsafe_file_upload"


def test_bandit_b202_maps_to_unsafe_file_upload() -> None:
    """B202 tarfile_unsafe_extract must map to unsafe_file_upload."""
    assert normalize("bandit", "B202") == "unsafe_file_upload"


def test_semgrep_upload_no_size_limit_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-no-size-limit") == "unsafe_file_upload"


def test_semgrep_upload_blocklist_maps_to_unsafe_file_upload() -> None:
    assert normalize("semgrep", "upload-blocklist-ext") == "unsafe_file_upload"


def test_bandit_b701_maps_to_xss() -> None:
    assert normalize("bandit", "B701") == "xss"


def test_semgrep_python_jinja2_autoescape_false_maps_to_xss() -> None:
    assert normalize("semgrep", "python-jinja2-autoescape-false") == "xss"


def test_semgrep_jinja2_safe_filter_maps_to_xss() -> None:
    assert normalize("semgrep", "jinja2-safe-filter") == "xss"


def test_semgrep_sqli_percent_format_assign_maps_to_sqli() -> None:
    assert normalize("semgrep", "python-sqli-percent-format-assign") == "sqli"


def test_semgrep_sqli_format_method_maps_to_sqli() -> None:
    assert normalize("semgrep", "python-sqli-format-method") == "sqli"


# ---------------------------------------------------------------------------
# V4: taxonomy precision — redos, runtime_panic, auth_bypass for localStorage
# ---------------------------------------------------------------------------

def test_semgrep_localstorage_sensitive_maps_to_auth_bypass() -> None:
    assert normalize("semgrep", "js-localstorage-sensitive") == "auth_bypass"


def test_eslint_non_literal_regexp_maps_to_redos() -> None:
    assert normalize("eslint", "security/detect-non-literal-regexp") == "redos"


def test_eslint_unsafe_regex_maps_to_redos() -> None:
    assert normalize("eslint", "security/detect-unsafe-regex") == "redos"


def test_gosec_g601_maps_to_runtime_panic() -> None:
    assert normalize("gosec", "G601") == "runtime_panic"


def test_gosec_g602_maps_to_runtime_panic() -> None:
    assert normalize("gosec", "G602") == "runtime_panic"


# ---------------------------------------------------------------------------
# V5: taxonomy precision — subprocess_usage, insecure_network_config,
#     poor_error_handling, info_disclosure, insecure_design,
#     security_misconfiguration, vulnerable_components,
#     logging_monitoring_failure, memory_safety
# ---------------------------------------------------------------------------

def test_bandit_b404_maps_to_subprocess_usage() -> None:
    assert normalize("bandit", "B404") == "subprocess_usage"


def test_bandit_b507_maps_to_weak_crypto() -> None:
    assert normalize("bandit", "B507") == "weak_crypto"


def test_gosec_g102_maps_to_insecure_network_config() -> None:
    assert normalize("gosec", "G102") == "insecure_network_config"


def test_gosec_g104_maps_to_poor_error_handling() -> None:
    assert normalize("gosec", "G104") == "poor_error_handling"


def test_gosec_g108_maps_to_info_disclosure() -> None:
    assert normalize("gosec", "G108") == "info_disclosure"


def test_owasp_a04_maps_to_insecure_design() -> None:
    assert normalize("owasp", "a04:2021") == "insecure_design"


def test_owasp_a05_maps_to_security_misconfiguration() -> None:
    assert normalize("owasp", "a05:2021") == "security_misconfiguration"


def test_owasp_a06_maps_to_vulnerable_components() -> None:
    assert normalize("owasp", "a06:2021") == "vulnerable_components"


def test_owasp_a09_maps_to_logging_monitoring_failure() -> None:
    assert normalize("owasp", "a09:2021") == "logging_monitoring_failure"


def test_eslint_detect_new_buffer_maps_to_memory_safety() -> None:
    assert normalize("eslint", "security/detect-new-buffer") == "memory_safety"


def test_eslint_detect_buffer_noassert_maps_to_memory_safety() -> None:
    assert normalize("eslint", "security/detect-buffer-noassert") == "memory_safety"


def test_eslint_detect_object_injection_maps_to_auth_bypass() -> None:
    assert normalize("eslint", "security/detect-object-injection") == "auth_bypass"
