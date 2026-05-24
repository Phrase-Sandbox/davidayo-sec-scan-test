"""Tests for the local pre-push skill mode (LocalFilesClient + phrase-sec-scan).

The real ``ScanPipeline`` runs end-to-end (strip, filter, validate,
post-filter, gate decision, patch generation). Only ``ClaudeClient`` is
mocked so no network call is made — same approach as
``tests/acceptance/test_acceptance.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

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
    # Pipeline calls analyse_async / ask_async; spec= alone does not
    # auto-create AsyncMocks for non-async-def methods on the real class,
    # so wire them explicitly.
    mock.analyse_async = AsyncMock(return_value=findings)
    mock.ask_async = AsyncMock(return_value="VERDICT: yes")
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


# --- .gitignore filtering --------------------------------------------------


def test_gitignore_excludes_matching_file(tmp_path):
    (tmp_path / ".gitignore").write_text("secrets.env\n")
    (tmp_path / "secrets.env").write_text("PROD_PW=hunter2\n")
    (tmp_path / "app.py").write_text("print('hi')\n")

    files = LocalFilesClient(tmp_path).get_repo_files()

    assert "app.py" in files
    assert "secrets.env" not in files


def test_gitignore_directory_pattern_prunes_subtree(tmp_path):
    (tmp_path / ".gitignore").write_text("build/\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "output.txt").write_text("generated\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hi')\n")

    files = LocalFilesClient(tmp_path).get_repo_files()

    assert "src/main.py" in files
    assert not any(p.startswith("build/") for p in files)


def test_gitignore_negation_reincludes_file(tmp_path):
    (tmp_path / ".gitignore").write_text("*.env\n!keep.env\n")
    (tmp_path / "secret.env").write_text("PROD_PW=hunter2\n")
    (tmp_path / "keep.env").write_text("KEEP=1\n")

    files = LocalFilesClient(tmp_path).get_repo_files()

    assert "keep.env" in files
    assert "secret.env" not in files


def test_gitignore_absent_collects_normally(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    (tmp_path / "config.yaml").write_text("port: 8080\n")

    files = LocalFilesClient(tmp_path).get_repo_files()

    assert "app.py" in files
    assert "config.yaml" in files


def test_respect_gitignore_false_collects_all(tmp_path):
    (tmp_path / ".gitignore").write_text("secrets.env\n")
    (tmp_path / "secrets.env").write_text("PROD_PW=hunter2\n")
    (tmp_path / "app.py").write_text("print('hi')\n")

    files = LocalFilesClient(tmp_path, respect_gitignore=False).get_repo_files()

    assert "app.py" in files
    assert "secrets.env" in files


def test_malformed_gitignore_is_treated_as_empty(tmp_path, caplog):
    # Bytes that can't decode as UTF-8 — the loader must log + return None.
    (tmp_path / ".gitignore").write_bytes(b"\xff\xfe\xfd\xfc invalid utf-8\n")
    (tmp_path / "app.py").write_text("print('hi')\n")

    files = LocalFilesClient(tmp_path).get_repo_files()

    assert "app.py" in files
    # No exception; the unreadable gitignore is silently treated as empty
    # (the warning is logged via stdlib logging; we don't assert the message
    # because the logger isn't necessarily captured here — what matters is
    # the scan completes and didn't drop anything).


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
    # on_demand mode ⇒ the vuln verifier runs (Fix #6), so .ask MAY be
    # called by verify_vuln_candidates.  BR-009 (verify_critical_findings)
    # does NOT run on the skill path — the finding is High, not Critical,
    # so BR-009 would never fire anyway.  We just confirm findings arrived.
    assert len(report.read_text()) > 0


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


def test_cli_local_mode_writes_both_md_and_html(tmp_path, monkeypatch):
    """Local pre-push mode now writes ``security-scan-report.html`` next to the .md."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-not-used-mock")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(_SQLI)

    fake = _fake_claude([_finding("app/db.py")])
    monkeypatch.setattr(local_cli, "ClaudeClient", lambda **_: fake)

    local_cli.main(["--local", str(tmp_path)])

    md = tmp_path / "vuln-result" / "security-scan-report.md"
    html = tmp_path / "vuln-result" / "security-scan-report.html"
    assert md.exists()
    assert html.exists()
    html_text = html.read_text()
    assert html_text.startswith("<!DOCTYPE html>")
    assert "A03:2021" in html_text


def test_cli_remote_mode_writes_both_md_and_html(tmp_path, monkeypatch):
    """Remote mode writes both files when the server returns both fields."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    fake_payload = {
        "markdown": "# Security Scan Report\n\n(remote-rendered markdown)\n",
        "html": "<!DOCTYPE html>\n<html><body>remote-rendered html</body></html>\n",
        "findings_count": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "findings": [],
    }

    import json
    from urllib import request as _ureq

    class _FakeResp:
        def __init__(self, payload: dict) -> None:
            self._body = json.dumps(payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read(self) -> bytes:
            return self._body

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_kw: _FakeResp(fake_payload))

    local_cli.main([str(tmp_path)])

    md = tmp_path / "vuln-result" / "security-scan-report.md"
    html = tmp_path / "vuln-result" / "security-scan-report.html"
    assert md.read_text() == fake_payload["markdown"]
    assert html.read_text() == fake_payload["html"]


def test_cli_remote_mode_handles_legacy_server_without_html(tmp_path, monkeypatch):
    """Old servers don't return ``html`` — CLI still writes the .md cleanly."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    legacy_payload = {
        "markdown": "# Security Scan Report\n\n(old server)\n",
        "findings_count": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "findings": [],
    }

    import json
    from urllib import request as _ureq

    class _FakeResp:
        def __init__(self, payload: dict) -> None:
            self._body = json.dumps(payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read(self) -> bytes:
            return self._body

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_kw: _FakeResp(legacy_payload))

    rc = local_cli.main([str(tmp_path)])

    assert rc == 0
    md = tmp_path / "vuln-result" / "security-scan-report.md"
    html = tmp_path / "vuln-result" / "security-scan-report.html"
    assert md.exists()
    assert not html.exists()  # no html field → no html file


def test_cli_retries_once_on_429_with_retry_after(tmp_path, monkeypatch):
    """If the server returns 429+Retry-After, the CLI sleeps then retries once."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    success_payload = {
        "markdown": "# OK\n",
        "html": "<html>OK</html>",
        "findings_count": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "findings": [],
    }

    import json
    from urllib import error as _uerr
    from urllib import request as _ureq

    sleeps: list[int] = []
    monkeypatch.setattr(local_cli.time, "sleep", lambda s: sleeps.append(s))

    call_n = {"i": 0}

    class _Headers(dict):
        def get(self, k, default=None):  # type: ignore[override]
            return super().get(k, default)

    class _Success:
        def __init__(self, payload: dict) -> None:
            self._body = json.dumps(payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read(self) -> bytes:
            return self._body

    class _BusyError(_uerr.HTTPError):
        def __init__(self) -> None:
            super().__init__(
                url="http://fake-scanner/scan/local",
                code=429,
                msg="busy",
                hdrs=_Headers({"Retry-After": "2"}),  # type: ignore[arg-type]
                fp=None,
            )
        def read(self) -> bytes:
            return b"scanner busy"

    def _fake_urlopen(req, *_a, **_kw):
        call_n["i"] += 1
        if call_n["i"] == 1:
            raise _BusyError()
        return _Success(success_payload)

    monkeypatch.setattr(_ureq, "urlopen", _fake_urlopen)

    rc = local_cli.main([str(tmp_path)])

    assert rc == 0  # second attempt succeeded with 0 Critical/High
    assert call_n["i"] == 2  # exactly one retry
    assert sleeps == [2]  # honoured Retry-After


def test_cli_no_gitignore_flag_disables_gitignore_filter(tmp_path, monkeypatch):
    """``--no-gitignore`` opts out of the gitignore filter end-to-end via the CLI."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-not-used-mock")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("print('ignored')\n")
    (tmp_path / "kept.py").write_text("print('kept')\n")

    fake = _fake_claude([])
    monkeypatch.setattr(local_cli, "ClaudeClient", lambda **_: fake)

    # Spy what files the pipeline receives. The pipeline calls
    # client.get_repo_files() — wrap LocalFilesClient to capture its output.
    captured: dict[str, str] = {}
    orig = LocalFilesClient.get_repo_files

    def _spy(self, *args, **kwargs):
        files = orig(self, *args, **kwargs)
        captured.update(files)
        return files

    monkeypatch.setattr(LocalFilesClient, "get_repo_files", _spy)

    local_cli.main(["--local", "--no-gitignore", str(tmp_path)])

    assert "ignored.py" in captured
    assert "kept.py" in captured
