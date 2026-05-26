"""Tests for the `phrase-sec-scan` CLI.

Both default and ``--local`` modes POST to the remote scanner. ``--local``
adds the developer's personal LLM API key to the request body as
``llm_override``; the server uses that key for the LLM call instead of its
org credentials. These tests mock ``urllib.request.urlopen`` so no real
HTTP is made.
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


def test_cli_local_mode_forwards_llm_override_in_body(tmp_path, monkeypatch):
    """`--local` POSTs to remote scanner with llm_override populated."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-personal-key-xyz")
    (tmp_path / "app.py").write_text("print(1)\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    rc = local_cli.main(["--local", str(tmp_path)])

    assert rc == 0
    assert captured["url"].endswith("/scan/local")
    body = captured["body"]
    assert "llm_override" in body
    assert body["llm_override"]["provider"] == "claude"
    assert body["llm_override"]["api_key"] == "sk-ant-personal-key-xyz"


def test_cli_default_mode_omits_llm_override_from_body(tmp_path, monkeypatch):
    """Default mode (no --local) sends no llm_override — server uses org creds."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-be-sent")
    (tmp_path / "app.py").write_text("print(1)\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    rc = local_cli.main([str(tmp_path)])

    assert rc == 0
    body = captured["body"]
    assert "llm_override" not in body, (
        "default mode must not forward the user's personal API key"
    )


def test_cli_local_mode_with_explicit_api_key_flag(tmp_path, monkeypatch):
    """`--local --api-key X --provider gemini` overrides env + config."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    (tmp_path / "app.py").write_text("print(1)\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    rc = local_cli.main([
        "--local", "--provider", "gemini",
        "--api-key", "AIza-flag-supplied", "--model", "gemini-2.5-flash",
        str(tmp_path),
    ])

    assert rc == 0
    body = captured["body"]
    assert body["llm_override"] == {
        "provider": "gemini",
        "api_key": "AIza-flag-supplied",
        "model": "gemini-2.5-flash",
    }


def test_cli_writes_md_and_html_when_server_returns_both(tmp_path, monkeypatch):
    """Server response with markdown + html → both files written."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-personal-key-xyz")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(_SQLI)

    _install_fake_urlopen(
        monkeypatch,
        _fake_server_response(
            [_finding("app/db.py")],
            markdown="# Security Scan Report\n\nA03:2021 SQLi in app/db.py:7\n",
        ),
    )

    rc = local_cli.main(["--local", str(tmp_path)])

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


def test_cli_no_gitignore_flag_disables_gitignore_filter(tmp_path, monkeypatch):
    """``--no-gitignore`` ships ignored files to the scanner."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-personal-xyz")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("print('ignored')\n")
    (tmp_path / "kept.py").write_text("print('kept')\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    local_cli.main(["--local", "--no-gitignore", str(tmp_path)])

    files_sent = captured["body"]["files"]
    assert "ignored.py" in files_sent
    assert "kept.py" in files_sent


def test_cli_gitignore_default_excludes_ignored_files(tmp_path, monkeypatch):
    """Without --no-gitignore, gitignored files are filtered before upload."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-personal-xyz")
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("print('ignored')\n")
    (tmp_path / "kept.py").write_text("print('kept')\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    local_cli.main(["--local", str(tmp_path)])

    files_sent = captured["body"]["files"]
    assert "kept.py" in files_sent
    assert "ignored.py" not in files_sent


# --- Phase A2: BYO provider / model / key resolution -------------------------


def test_resolve_provider_config_flag_beats_env_beats_config_beats_default(monkeypatch):
    """CLI flag > env var > config > default."""
    import argparse

    from security_scanner.skill.local_cli import _resolve_provider_config

    # Flag wins over everything.
    monkeypatch.setenv("SCANNER_LLM_PROVIDER", "gemini")
    args = argparse.Namespace(provider="claude", model=None, api_key=None)
    config = {"provider": "gemini"}
    resolved = _resolve_provider_config(args, config)
    assert resolved["provider"] == "claude"

    # Env beats config + default when no flag.
    args2 = argparse.Namespace(provider=None, model=None, api_key=None)
    resolved2 = _resolve_provider_config(args2, config)
    assert resolved2["provider"] == "gemini"

    # Config beats default when no flag / env.
    monkeypatch.delenv("SCANNER_LLM_PROVIDER", raising=False)
    config3 = {"provider": "gemini"}
    resolved3 = _resolve_provider_config(args2, config3)
    assert resolved3["provider"] == "gemini"

    # Default when nothing is set.
    resolved4 = _resolve_provider_config(args2, {})
    assert resolved4["provider"] == "claude"


def test_resolve_provider_config_model_precedence(monkeypatch):
    import argparse

    from security_scanner.skill.local_cli import _resolve_provider_config

    monkeypatch.setenv("SCANNER_LLM_MODEL", "env-model")
    args = argparse.Namespace(provider=None, model="flag-model", api_key=None)
    resolved = _resolve_provider_config(args, {"model": "config-model"})
    assert resolved["model"] == "flag-model"

    args2 = argparse.Namespace(provider=None, model=None, api_key=None)
    resolved2 = _resolve_provider_config(args2, {"model": "config-model"})
    assert resolved2["model"] == "env-model"

    monkeypatch.delenv("SCANNER_LLM_MODEL", raising=False)
    resolved3 = _resolve_provider_config(args2, {"model": "config-model"})
    assert resolved3["model"] == "config-model"

    resolved4 = _resolve_provider_config(args2, {})
    assert resolved4["model"] is None


def test_resolve_provider_config_api_key_for_gemini(monkeypatch):
    import argparse

    from security_scanner.skill.local_cli import _resolve_provider_config

    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    args = argparse.Namespace(provider="gemini", model=None, api_key="flag-key")
    resolved = _resolve_provider_config(args, {})
    assert resolved["api_key"] == "flag-key"

    args2 = argparse.Namespace(provider="gemini", model=None, api_key=None)
    monkeypatch.setenv("GOOGLE_API_KEY", "env-google-key")
    resolved2 = _resolve_provider_config(args2, {})
    assert resolved2["api_key"] == "env-google-key"

    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    resolved3 = _resolve_provider_config(args2, {"google_api_key": "config-google-key"})
    assert resolved3["api_key"] == "config-google-key"


def test_cli_missing_key_exits_2(tmp_path, monkeypatch, capsys):
    """--local without an LLM API key anywhere → exit 2 with a helpful message."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    # Empty config — no anthropic_api_key, no google_api_key
    monkeypatch.setattr(local_cli, "_load_config", lambda: {})
    rc = local_cli.main(["--local", str(tmp_path)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "--local requires an LLM API key" in captured.err


def test_cli_missing_gemini_key_exits_2(tmp_path, monkeypatch, capsys):
    """--local --provider gemini without a Google key → exit 2."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setattr(local_cli, "_load_config", lambda: {})
    rc = local_cli.main(["--local", "--provider", "gemini", str(tmp_path)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "--local requires an LLM API key" in captured.err


def test_login_writes_anthropic_key_to_config(tmp_path, monkeypatch):
    """login --api-key writes anthropic_api_key to config.yaml without browser flow."""
    fake_config = tmp_path / ".phrase-sec-scan" / "config.yaml"
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".phrase-sec-scan")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", fake_config)

    rc = local_cli.main(["login", "--provider", "claude", "--api-key", "sk-ant-TEST"])
    assert rc == 0
    assert fake_config.exists()
    contents = fake_config.read_text()
    assert "anthropic_api_key" in contents
    assert "sk-ant-TEST" in contents


def test_login_writes_gemini_key_to_config(tmp_path, monkeypatch):
    """login --provider gemini --api-key writes google_api_key to config.yaml."""
    fake_config = tmp_path / ".phrase-sec-scan" / "config.yaml"
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".phrase-sec-scan")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", fake_config)

    rc = local_cli.main(["login", "--provider", "gemini", "--api-key", "AIza-TEST"])
    assert rc == 0
    contents = fake_config.read_text()
    assert "google_api_key" in contents
    assert "AIza-TEST" in contents


def test_cli_provider_flag_claude_uses_anthropic_key(tmp_path, monkeypatch):
    """--provider claude with ANTHROPIC_API_KEY set → key forwarded as override."""
    monkeypatch.setattr(
        local_cli, "_resolve_endpoint", lambda: ("http://fake-scanner", "tok")
    )
    monkeypatch.setattr(local_cli, "_triggered_by", lambda _root: "tester@phrase.com")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    (tmp_path / "app.py").write_text("print(1)\n")

    captured = _install_fake_urlopen(monkeypatch, _fake_server_response())

    rc = local_cli.main(["--local", "--provider", "claude", str(tmp_path)])
    assert rc == 0  # no findings → exit 0
    body = captured["body"]
    assert body["llm_override"]["provider"] == "claude"
    assert body["llm_override"]["api_key"] == "sk-ant-test"
