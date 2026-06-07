"""Tests for upload-security.yaml Semgrep rules.

Each test verifies that the rule ID normalizes to ``unsafe_file_upload``.
Skipped cleanly if the Semgrep binary is missing.
"""

from __future__ import annotations

import shutil

import pytest

from security_scanner.shared.scanners.normalize import normalize

# ---------------------------------------------------------------------------
# Skip the whole module if semgrep is not installed.
# (normalize tests don't need it, but keep the skip marker as documented.)
# ---------------------------------------------------------------------------

# Individual rule-ID → expected vuln_class mapping tests.
# These only test the normalize() function, not the actual semgrep execution.


@pytest.mark.parametrize("rule_id,expected", [
    # Direct ID matches for upload-security.yaml rules
    ("upload-attacker-filename", "unsafe_file_upload"),
    ("upload-extension-only", "unsafe_file_upload"),
    ("upload-mime-only", "unsafe_file_upload"),
    ("upload-blocklist-ext", "unsafe_file_upload"),
    ("upload-webroot-storage", "unsafe_file_upload"),
    ("upload-no-size-limit", "unsafe_file_upload"),
    ("upload-zip-slip", "unsafe_file_upload"),
    ("upload-risky-parser", "unsafe_file_upload"),
    # Prefix-based matching (semgrep prefixes rule IDs with config name)
    ("upload-attacker-filename-django", "unsafe_file_upload"),
    ("upload-attacker-filename-js", "unsafe_file_upload"),
    ("upload-tar-slip", "unsafe_file_upload"),
    ("upload-risky-parser-yaml", "unsafe_file_upload"),
    ("upload-risky-parser-xml", "unsafe_file_upload"),
    ("upload-webroot-storage-flask", "unsafe_file_upload"),
    # Bandit B202 — tarfile unsafe extraction
    ("B202", "unsafe_file_upload"),
])
def test_rule_maps_to_unsafe_file_upload(rule_id: str, expected: str) -> None:
    """Each upload rule ID must normalize to unsafe_file_upload."""
    assert normalize("semgrep", rule_id) == expected, (
        f"normalize('semgrep', {rule_id!r}) = {normalize('semgrep', rule_id)!r}, expected {expected!r}"
    )


def test_bandit_b202_maps_to_unsafe_file_upload() -> None:
    assert normalize("bandit", "B202") == "unsafe_file_upload"


@pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep binary not installed — skipping runtime scan tests",
)
class TestSemgrepUploadRulesExecution:
    """Integration tests that actually run semgrep. Skipped when binary absent."""

    def test_upload_security_yaml_exists(self) -> None:
        """Verify the upload-security.yaml config file exists at the expected path."""
        from pathlib import Path
        config = (
            Path(__file__).parents[3]
            / "semgrep_configs"
            / "upload-security.yaml"
        )
        assert config.exists(), f"upload-security.yaml not found at {config}"

    def test_upload_security_yaml_is_valid_yaml(self) -> None:
        """The config must be valid YAML."""
        from pathlib import Path

        import yaml
        config = (
            Path(__file__).parents[3]
            / "semgrep_configs"
            / "upload-security.yaml"
        )
        with config.open() as fh:
            data = yaml.safe_load(fh)
        assert "rules" in data
        assert len(data["rules"]) >= 8, "Expected at least 8 rule families"

    def test_upload_rules_have_required_metadata(self) -> None:
        """Each rule must declare vuln_class in metadata."""
        from pathlib import Path

        import yaml
        config = (
            Path(__file__).parents[3]
            / "semgrep_configs"
            / "upload-security.yaml"
        )
        with config.open() as fh:
            data = yaml.safe_load(fh)
        for rule in data.get("rules", []):
            rule_id = rule.get("id", "<unknown>")
            metadata = rule.get("metadata", {})
            assert "vuln_class" in metadata, (
                f"Rule {rule_id!r} missing 'vuln_class' in metadata"
            )
            assert metadata["vuln_class"] == "unsafe_file_upload", (
                f"Rule {rule_id!r}: vuln_class={metadata['vuln_class']!r} != 'unsafe_file_upload'"
            )
