"""Tests for the local pre-push skill mode (LocalFilesClient + phrase-sec-scan).

The real ``ScanPipeline`` runs end-to-end (strip, filter, validate,
post-filter, gate decision, patch generation). Only ``ClaudeClient`` is
mocked so no network call is made — same approach as
``tests/acceptance/test_acceptance.py``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from security_scanner.shared.claude.client import ClaudeClient
from security_scanner.skill import local_cli
from security_scanner.skill.local_files import LocalFilesClient

_SQLI = """\
import sqlite3


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    query = f"SELECT id FROM users WHERE name = '{username}'"
    cur.execute(query)
    return cur.fetchone()
"""

# Same shape as the acceptance AC2 fixture — the stripper detects this.
_SECRET = (
    "# config — must never hold real creds\n"
    'ANTHROPIC_API_KEY = "sk-ant-abcdef1234567890abcdef1234567890"\n'
    'LOG_LEVEL = "INFO"\n'
)


def _finding(affected_file: str) -> dict:
    return {
        "vulnerability_id": "A03:2021",
        "severity": "High",
        "confidence": "High",
        "cvss_band": "7.0-8.9",
        "affected_file": affected_file,
        "affected_lines": "7",
        "description": "Raw string interpolation builds the SQL query.",
        "suggested_fix": (
            "Use a parameterised query:\n"
            '```python\n    cur.execute("SELECT id FROM users WHERE name = ?", (username,))\n```'
        ),
        "owasp_reference": "https://owasp.org/Top10/A03_2021-Injection/",
        "patch_file_path": "patches/x.patch",
        "exploit_scenario": (
            f"Attacker submits username=admin' OR '1'='1 as a payload to "
            f"{affected_file}, bypassing the WHERE clause and returning all rows."
        ),
        "verification_status": "unverified",
    }


def _fake_claude(findings: list[dict]) -> MagicMock:
    mock = MagicMock(spec=ClaudeClient)
    mock.analyse.return_value = findings
    mock.ask.return_value = "VERDICT: yes"
    return mock


# --- LocalFilesClient ------------------------------------------------------


def test_local_files_client_reads_source_and_skips_noise(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("print('hi')\n")
    (tmp_path / "security-scan-report.md").write_text("old report\n")
    (tmp_path / "abc_0_db.patch").write_text("--- a\n+++ b\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / "logo.bin").write_bytes(b"\x00\x01\x02\x80\x81")

    files = LocalFilesClient(tmp_path).get_repo_files()

    assert "app/db.py" in files
    assert "security-scan-report.md" not in files  # our own output
    assert "abc_0_db.patch" not in files  # generated patch
    assert not any(p.startswith(".git/") for p in files)  # VCS dir pruned
    assert "logo.bin" not in files  # binary skipped


# --- phrase-sec-scan CLI ---------------------------------------------------


def test_cli_writes_report_and_patch_for_sqli(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-not-used-mock")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(_SQLI)

    fake = _fake_claude([_finding("app/db.py")])
    monkeypatch.setattr(local_cli, "ClaudeClient", lambda **_: fake)

    rc = local_cli.main(["--local", str(tmp_path)])

    report = tmp_path / "vuln-result" / "security-scan-report.md"
    assert report.exists()
    assert "A03:2021" in report.read_text()
    patches = list(tmp_path.glob("*.patch"))
    assert patches, "expected at least one .patch file written into the project"
    assert "app/db.py" in patches[0].read_text()
    # High finding present ⇒ non-zero exit (usable as a pre-commit hook).
    assert rc == 1
    # on_demand mode ⇒ BR-009 verification (.ask) must NOT run.
    fake.ask.assert_not_called()


def test_cli_flags_hardcoded_secret_as_secret_001(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-not-used-mock")
    (tmp_path / "config.py").write_text(_SECRET)

    fake = _fake_claude([])  # Claude finds nothing; secret strip is pre-Claude
    monkeypatch.setattr(local_cli, "ClaudeClient", lambda **_: fake)

    rc = local_cli.main(["--local", str(tmp_path)])

    report_text = (tmp_path / "vuln-result" / "security-scan-report.md").read_text()
    assert "SECRET-001" in report_text
    assert rc == 1  # SECRET-001 is Critical


def test_cli_errors_without_api_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rc = local_cli.main(["--local", str(tmp_path)])
    assert rc == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err
