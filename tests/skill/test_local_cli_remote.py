"""Tests for the remote-mode CLI flow (login / scan / logout)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from security_scanner.skill import local_cli

# --- Config persistence -----------------------------------------------------


def test_save_and_load_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".phrase-sec-scan")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".phrase-sec-scan" / "config.yaml")
    local_cli._save_config({"scanner_url": "https://scanner.test", "token": "phs_local_x"})
    cfg = local_cli._load_config()
    assert cfg["scanner_url"] == "https://scanner.test"
    assert cfg["token"] == "phs_local_x"
    # File permissions must be owner-only-readable.
    mode = (tmp_path / ".phrase-sec-scan" / "config.yaml").stat().st_mode & 0o777
    assert mode == 0o600


def test_resolve_endpoint_env_overrides_file(tmp_path, monkeypatch):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    local_cli._save_config({"scanner_url": "https://from-file", "token": "tok-file"})
    monkeypatch.setenv("SCANNER_URL", "https://from-env")
    monkeypatch.setenv("SCANNER_TOKEN", "tok-env")
    url, tok = local_cli._resolve_endpoint()
    assert url == "https://from-env"
    assert tok == "tok-env"


# --- Login (manual mode skips browser flow) ---------------------------------


def test_login_manual_writes_config(tmp_path, monkeypatch):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    monkeypatch.setattr("builtins.input", lambda *_: "phs_local_tok-abc_xyz")
    rc = local_cli._login("https://scanner.test", manual=True)
    assert rc == 0
    cfg = local_cli._load_config()
    assert cfg["scanner_url"] == "https://scanner.test"
    assert cfg["token"] == "phs_local_tok-abc_xyz"


def test_login_manual_rejects_empty_token(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    monkeypatch.setattr("builtins.input", lambda *_: "  ")
    rc = local_cli._login("https://scanner.test", manual=True)
    assert rc == 2
    assert "no token" in capsys.readouterr().err.lower()


# --- Logout -----------------------------------------------------------------


def test_logout_removes_config_and_revokes(tmp_path, monkeypatch):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    local_cli._save_config({"scanner_url": "https://scanner.test", "token": "phs_local_x"})

    called = {}

    def fake_urlopen(req, timeout=0, context=None):  # noqa: ARG001
        called["url"] = req.full_url
        called["auth"] = req.headers.get("Authorization")
        resp = MagicMock()
        resp.read.return_value = b""
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda *_: None
        return resp

    monkeypatch.setattr(local_cli.urllib.request, "urlopen", fake_urlopen)
    rc = local_cli._logout(revoke_remote=True)
    assert rc == 0
    assert called["url"].endswith("/portal/tokens/revoke")
    assert called["auth"] == "Bearer phs_local_x"
    assert not (tmp_path / ".cfg" / "config.yaml").exists()


def test_logout_when_already_logged_out(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    rc = local_cli._logout(revoke_remote=False)
    assert rc == 0
    assert "Already logged out" in capsys.readouterr().out


# --- Remote scan POSTs the right body & writes the report -------------------


def test_remote_scan_posts_and_writes_report(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("print('hi')\n")

    captured = {}

    def fake_urlopen(req, timeout=0, context=None):  # noqa: ARG001
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        captured["auth"] = req.headers.get("Authorization")
        payload = {
            "markdown": "# Security Scan Report\n\nNo findings.\n",
            "findings_count": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "findings": [],
        }
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda *_: None
        return resp

    monkeypatch.setattr(local_cli.urllib.request, "urlopen", fake_urlopen)

    rc = local_cli._scan_remote(
        root=tmp_path,
        directory="",
        scanner_url="https://scanner.test",
        token="phs_local_tok-abc_xyz",
    )
    assert rc == 0
    assert captured["url"] == "https://scanner.test/scan/local"
    assert captured["auth"] == "Bearer phs_local_tok-abc_xyz"
    assert "app/main.py" in captured["body"]["files"]
    assert (tmp_path / "vuln-result" / "security-scan-report.md").exists()


def test_remote_scan_returns_1_on_critical_findings(tmp_path, monkeypatch):
    (tmp_path / "main.py").write_text("print('hi')\n")

    payload = {
        "markdown": "report",
        "findings_count": 1,
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 0,
        "findings": [],
    }

    def fake_urlopen(req, timeout=0, context=None):  # noqa: ARG001
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda *_: None
        return resp

    monkeypatch.setattr(local_cli.urllib.request, "urlopen", fake_urlopen)
    rc = local_cli._scan_remote(
        root=tmp_path,
        directory="",
        scanner_url="https://scanner.test",
        token="t",
    )
    assert rc == 1


def test_remote_scan_401_says_run_login(tmp_path, monkeypatch, capsys):
    (tmp_path / "main.py").write_text("print('hi')\n")

    def fake_urlopen(req, timeout=0, context=None):  # noqa: ARG001
        from io import BytesIO
        from urllib.error import HTTPError

        raise HTTPError(req.full_url, 401, "Unauthorized", {}, BytesIO(b"nope"))

    monkeypatch.setattr(local_cli.urllib.request, "urlopen", fake_urlopen)
    rc = local_cli._scan_remote(
        root=tmp_path, directory="", scanner_url="https://scanner.test", token="bad"
    )
    assert rc == 2
    assert "login" in capsys.readouterr().err.lower()


# --- main() routing ---------------------------------------------------------


def test_main_scan_without_login_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    monkeypatch.delenv("SCANNER_URL", raising=False)
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)
    rc = local_cli.main([str(tmp_path)])
    assert rc == 2
    assert "login" in capsys.readouterr().err.lower()


def test_main_login_requires_scanner_url(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    monkeypatch.delenv("SCANNER_URL", raising=False)
    rc = local_cli.main(["login"])
    assert rc == 2
    assert "scanner-url" in capsys.readouterr().err.lower()


def test_main_dispatches_login(tmp_path, monkeypatch):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    monkeypatch.setattr("builtins.input", lambda *_: "phs_local_tok-abc_xyz")
    rc = local_cli.main(["login", "--scanner-url", "https://scanner.test", "--manual"])
    assert rc == 0
    assert local_cli._load_config()["scanner_url"] == "https://scanner.test"


def test_main_routes_remote_scan_via_config(tmp_path, monkeypatch):
    monkeypatch.setattr(local_cli, "_CONFIG_DIR", tmp_path / ".cfg")
    monkeypatch.setattr(local_cli, "_CONFIG_FILE", tmp_path / ".cfg" / "config.yaml")
    local_cli._save_config({"scanner_url": "https://scanner.test", "token": "tok"})
    monkeypatch.delenv("SCANNER_URL", raising=False)
    monkeypatch.delenv("SCANNER_TOKEN", raising=False)

    (tmp_path / "src.py").write_text("print('hi')\n")

    payload = {
        "markdown": "ok",
        "findings_count": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "findings": [],
    }

    with patch.object(local_cli.urllib.request, "urlopen") as mock_open:
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda *_: None
        mock_open.return_value = resp
        rc = local_cli.main([str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "vuln-result" / "security-scan-report.md").exists()
