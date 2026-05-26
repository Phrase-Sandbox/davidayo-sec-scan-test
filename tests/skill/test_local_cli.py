"""Tests for the ``phrase-sec-scan`` CLI.

All scans POST to ``${scanner_url}/scan/local`` with a bearer token. The
server resolves the user's LLM settings from the DB — no API key is ever
stored or sent by the CLI. These tests mock ``urllib.request.urlopen`` so
no real HTTP is made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

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


def _fake_server_response(
    findings: list[dict] | None = None,
    *,
    markdown: str = "# Security Scan Report\n",
    html: str | None = "<!DOCTYPE html>\n<html><body>ok</body></html>",
) -> dict:
    """Build a mock /scan/local response payload."""
    findings = findings or []
    severity_count = lambda sev: sum(  # noqa: E731
        1 for f in findings if f.get("severity") == sev
    )
    return {
        "markdown": markdown,
        **({"html": html} if html is not None else {}),
        "findings_count": len(findings),
        "critical": severity_count("Critical"),
        "high": severity_count("High"),
        "medium": severity_count("Medium"),
        "low": severity_count("Low"),
        "findings": findings,
    }


def _install_fake_urlopen(monkeypatch, response_payload: dict) -> dict:
    """Patch ``urllib.request.urlopen`` and return a dict that captures the
    request body the CLI sent (for assertions in the test)."""
    from urllib import request as _ureq

    captured: dict = {}

    class _Resp:
        def __init__(self, payload: dict) -> None:
            self._body = json.dumps(payload).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read(self) -> bytes:
            return self._body

    def _fake_urlopen(req, *_a, **_kw):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8")) if req.data else None
        return _Resp(response_payload)

    monkeypatch.setattr(_ureq, "urlopen", _fake_urlopen)
    return captured


# --- LocalFilesClient -------------------------------------------------------


def test_local_files_client_reads_source_and_skips_noise(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(_SQLI)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n\trepositorformatversion = 0\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "db.cpython-311.pyc").write_bytes(b"\x00\x01\x02")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lodash.js").write_text("//js\n")
    (tmp_path / "app" / "secret.yaml").write_text(_SECRET)

    client = LocalFilesClient(tmp_path)
    files = client.get_repo_files()
    assert "app/db.py" in files
    assert all("__pycache__" not in k for k in files)
    assert all(".git/" not in k for k in files)
    assert all("node_modules" not in k for k in files)
    assert "app/db.py" in files


def test_gitignore_excludes_matching_file(tmp_path):
    (tmp_path / ".gitignore").write_text("secret.yaml\n")
    (tmp_path / "app.py").write_text("print(1)\n")
    (tmp_path / "secret.yaml").write_text("key: value\n")
    files = LocalFilesClient(tmp_path).get_repo_files()
    assert "app.py" in files
    assert "secret.yaml" not in files


def test_gitignore_directory_pattern_prunes_subtree(tmp_path):
    (tmp_path / ".gitignore").write_text("dist/\n")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("packed\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("x=1\n")
    files = LocalFilesClient(tmp_path).get_repo_files()
    assert "src/main.py" in files
    assert all("dist" not in k for k in files)


def test_gitignore_negation_reincludes_file(tmp_path):
    (tmp_path / ".gitignore").write_text("*.log\n!important.log\n")
    (tmp_path / "debug.log").write_text("noise\n")
    (tmp_path / "important.log").write_text("needed\n")
    files = LocalFilesClient(tmp_path).get_repo_files()
    assert "important.log" in files
    assert "debug.log" not in files


def test_gitignore_absent_collects_normally(tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n")
    files = LocalFilesClient(tmp_path).get_repo_files()
    assert "app.py" in files


def test_respect_gitignore_false_collects_all(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("x=1\n")
    (tmp_path / "kept.py").write_text("y=2\n")
    files = LocalFilesClient(tmp_path, respect_gitignore=False).get_repo_files()
    assert "ignored.py" in files
    assert "kept.py" in files


def test_malformed_gitignore_is_treated_as_empty(tmp_path, caplog):
    (tmp_path / ".gitignore").write_bytes(b"\xff\xfe")
    (tmp_path / "app.py").write_text("print(1)\n")
    files = LocalFilesClient(tmp_path).get_repo_files()
    assert "app.py" in files


# --- CLI: payload shape -------------------------------------------------------


def test_cli_scan_sends_minimal_payload_without_api_key(tmp_path, monkeypatch):
    """The payload contains only files/triggered_by/directory/repo_url.

    No API key, no provider, no model is ever sent by the CLI — the server
    resolves those from the user's stored settings.
    """
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    rc = local_cli.main([str(tmp_path)])

    assert rc == 0
    body = captured["body"]
    assert "app.py" in body["files"]
    # No key or provider fields — server handles those from DB settings.
    assert "llm_override" not in body
    assert "provider_override" not in body
    assert "api_key" not in body
    assert body["triggered_by"] == "tester@phrase.com"


def test_cli_writes_md_and_html_when_server_returns_both(tmp_path, monkeypatch):
    """Server response with markdown + html → both files written, exit 1 on High."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(_SQLI)

    _install_fake_urlopen(
        monkeypatch,
        _fake_server_response(
            [_finding("app/db.py")],
            markdown="# Security Scan Report\n\nA03:2021 SQLi in app/db.py:7\n",
        ),
    )

    rc = local_cli.main([str(tmp_path)])

    md = tmp_path / "vuln-result" / "security-scan-report.md"
    html = tmp_path / "vuln-result" / "security-scan-report.html"
    assert md.exists()
    assert html.exists()
    assert "A03:2021" in md.read_text()
    assert rc == 1  # High finding → exit 1


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


# --- CLI: gitignore flags ---------------------------------------------------


def test_cli_no_gitignore_flag_disables_gitignore_filter(tmp_path, monkeypatch):
    """``--no-gitignore`` ships ignored files to the scanner."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("print('ignored')\n")
    (tmp_path / "kept.py").write_text("print('kept')\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    local_cli.main(["--no-gitignore", str(tmp_path)])

    files_sent = captured["body"]["files"]
    assert "ignored.py" in files_sent
    assert "kept.py" in files_sent


def test_cli_gitignore_default_excludes_ignored_files(tmp_path, monkeypatch):
    """Without --no-gitignore, gitignored files are filtered before upload."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("print('ignored')\n")
    (tmp_path / "kept.py").write_text("print('kept')\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    local_cli.main([str(tmp_path)])

    files_sent = captured["body"]["files"]
    assert "kept.py" in files_sent
    assert "ignored.py" not in files_sent


# --- CLI: 429 backpressure --------------------------------------------------


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


# --- CLI: auth error handling (401 / 412) -----------------------------------


def _make_http_error(code: int, body_bytes: bytes):
    from urllib import error as _uerr

    class _Err(_uerr.HTTPError):
        def __init__(self) -> None:
            super().__init__(
                url="http://fake-scanner/scan/local",
                code=code,
                msg="err",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            )
        def read(self) -> bytes:
            return body_bytes

    return _Err


def test_cli_401_expired_shows_reissue_message(tmp_path, monkeypatch, capsys):
    """401 with 'expired' in detail → token-expired + portal re-issue hint."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    from urllib import request as _ureq

    body = json.dumps({"detail": "Your scanner token has expired (30-day TTL). Visit /portal/ to re-issue."}).encode()
    ErrCls = _make_http_error(401, body)

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_kw: (_ for _ in ()).throw(ErrCls()))

    rc = local_cli.main([str(tmp_path)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "expired" in err.lower()
    assert "/portal/" in err


def test_cli_401_deactivated_shows_admin_message(tmp_path, monkeypatch, capsys):
    """401 with 'deactivated' in detail → account deactivated + admin contact."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    from urllib import request as _ureq

    body = json.dumps({"detail": "Your account has been deactivated. Contact your administrator."}).encode()
    ErrCls = _make_http_error(401, body)

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_kw: (_ for _ in ()).throw(ErrCls()))

    rc = local_cli.main([str(tmp_path)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "deactivated" in err.lower()
    assert "administrator" in err.lower()


def test_cli_401_generic_shows_login_hint(tmp_path, monkeypatch, capsys):
    """Generic 401 → suggest re-running login."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    from urllib import request as _ureq

    body = json.dumps({"detail": "Local scan authentication failed (token)."}).encode()
    ErrCls = _make_http_error(401, body)

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_kw: (_ for _ in ()).throw(ErrCls()))

    rc = local_cli.main([str(tmp_path)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "login" in err.lower()


def test_cli_412_no_settings_shows_portal_settings_hint(tmp_path, monkeypatch, capsys):
    """412 Precondition Failed → user hasn't saved LLM settings → portal pointer."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    from urllib import request as _ureq

    body = json.dumps({
        "detail": (
            "No LLM provider configured for your account. "
            "Visit /portal/settings to choose a provider and save your API key."
        )
    }).encode()
    ErrCls = _make_http_error(412, body)

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_kw: (_ for _ in ()).throw(ErrCls()))

    rc = local_cli.main([str(tmp_path)])

    assert rc == 2
    err = capsys.readouterr().err
    assert "portal/settings" in err
    assert "provider" in err.lower()


# --- CLI: 502 upstream errors -----------------------------------------------


def test_cli_502_quota_exhausted_shows_topup_message(tmp_path, monkeypatch, capsys):
    """When 502 detail.error == 'llm_quota_exhausted', show a top-up message."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    from urllib import error as _uerr
    from urllib import request as _ureq

    class _QuotaError(_uerr.HTTPError):
        def __init__(self) -> None:
            super().__init__(
                url="http://fake-scanner/scan/local",
                code=502,
                msg="Bad Gateway",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            )

        def read(self) -> bytes:
            return (
                b'{"detail":{"error":"llm_quota_exhausted",'
                b'"provider":"gemini","message":"RESOURCE_EXHAUSTED",'
                b'"scan_id":"abc"}}'
            )

    monkeypatch.setattr(_ureq, "urlopen", lambda *_a, **_kw: (_ for _ in ()).throw(_QuotaError()))

    rc = local_cli.main([str(tmp_path)])

    assert rc == 3
    err = capsys.readouterr().err
    assert "gemini" in err.lower()
    assert "quota" in err.lower()
    assert "top up" in err.lower() or "wait for" in err.lower()


def test_cli_502_from_server_exits_3(tmp_path, monkeypatch, capsys):
    """Server returns 502 (mid-scan LLM parse error) → CLI exits 3, not 2."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    (tmp_path / "app.py").write_text("print(1)\n")

    from urllib import error as _uerr
    from urllib import request as _ureq

    class _UpstreamError(_uerr.HTTPError):
        def __init__(self) -> None:
            super().__init__(
                url="http://fake-scanner/scan/local",
                code=502,
                msg="Bad Gateway",
                hdrs=None,  # type: ignore[arg-type]
                fp=None,
            )

        def read(self) -> bytes:
            return b'{"detail":{"error":"scanner_upstream_error","message":"Unterminated string","scan_id":"abc"}}'

    def _fake_urlopen(_req, *_a, **_kw):
        raise _UpstreamError()

    monkeypatch.setattr(_ureq, "urlopen", _fake_urlopen)

    rc = local_cli.main([str(tmp_path)])

    assert rc == 3
    err = capsys.readouterr().err
    assert "scanner failed mid-scan" in err.lower()
