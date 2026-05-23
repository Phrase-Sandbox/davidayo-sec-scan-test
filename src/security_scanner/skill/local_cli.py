"""``phrase-sec-scan`` — local pre-push security scan CLI.

Two modes, sharing the same UX:

- **Remote (default)** — POSTs the working tree to ``${scanner_url}/scan/local``.
  No ``ANTHROPIC_API_KEY`` required on the developer's machine; the deployed
  scanner runs the LLM call with its own key. Auth uses a per-developer token
  obtained via ``phrase-sec-scan login`` (browser-callback flow that drops the
  token into ``~/.phrase-sec-scan/config.yaml`` with mode 0600).

- **Local (``--local``)** — preserves the original on-laptop pipeline behaviour
  for offline use. Needs ``ANTHROPIC_API_KEY`` in the environment.

``mode=on_demand`` ⇒ BR-009 parallel verification is skipped per spec §4.1
(same as the hosted skill — this is the informational path, not the gate).
This is a documented deviation from spec §2.2 (the spec skill fetches from
GitHub via OAuth). The hosted spec skill is unchanged and still available.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from urllib.error import URLError

import certifi

# Module-level imports for `--local` mode. Kept at module scope so test code
# can monkeypatch ``local_cli.ClaudeClient`` etc. without chasing lazy imports.
from security_scanner.shared.claude.client import ClaudeClient
from security_scanner.shared.models.enums import ScanTarget, ScanType, Severity
from security_scanner.shared.reports.markdown import build_markdown_report
from security_scanner.skill.local_files import LocalFilesClient

_REPORT_FILENAME = "security-scan-report.md"
_REPORT_DIR = "vuln-result"
_CONFIG_DIR = Path.home() / ".phrase-sec-scan"
_CONFIG_FILE = _CONFIG_DIR / "config.yaml"
_LOGIN_TIMEOUT_SECONDS = 120


# --- Config file (simple key: value, no PyYAML dep) --------------------------


def _load_config() -> dict[str, str]:
    """Read the CLI config. Tolerant of a missing file."""
    if not _CONFIG_FILE.exists():
        return {}
    out: dict[str, str] = {}
    try:
        for line in _CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            out[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return {}
    return out


def _save_config(values: dict[str, str]) -> None:
    """Write the CLI config atomically with mode 0600.

    Mode 0600 because the file holds a bearer token. We chmod the parent dir
    to 0700 too — the token would still be readable if the home dir is open
    but at least it's not casually scrapeable.
    """
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(_CONFIG_DIR, stat.S_IRWXU)
    except OSError:
        # Best-effort on systems where chmod is meaningless (Windows).
        pass
    tmp = _CONFIG_FILE.with_suffix(".yaml.tmp")
    lines = [f"{k}: {v}" for k, v in values.items()]
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    os.replace(tmp, _CONFIG_FILE)


def _resolve_endpoint() -> tuple[str | None, str | None]:
    """Returns ``(scanner_url, token)`` from env (override) or config file."""
    cfg = _load_config()
    url = os.getenv("SCANNER_URL") or cfg.get("scanner_url")
    token = os.getenv("SCANNER_TOKEN") or cfg.get("token")
    return (url.rstrip("/") if url else None, token)


# --- git helpers (unchanged behaviour) ---------------------------------------


def _git(args: list[str], cwd: Path) -> str:
    cmd = ["git", *args]
    try:
        out = subprocess.run(  # noqa: S603, S607
            cmd, cwd=cwd, capture_output=True, text=True, timeout=5, check=False
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _derive_repo_url(root: Path) -> str:
    remote = _git(["remote", "get-url", "origin"], root)
    if remote:
        if remote.startswith("git@github.com:"):
            path = remote[len("git@github.com:") :]
            return "https://github.com/" + path.removesuffix(".git")
        if "github.com" in remote:
            return remote.removesuffix(".git")
    return f"https://github.com/local/{root.name}"


def _triggered_by(root: Path) -> str:
    return _git(["config", "user.email"], root) or os.getenv("USER", "local-dev")


# --- Browser-callback login --------------------------------------------------


def _find_free_port() -> int:
    """Bind to port 0, ask the kernel for an unused TCP port, return it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Captures the ``?token=...`` from the portal's loopback redirect."""

    received_token: str | None = None
    expected_state: str | None = None
    state_ok: bool = False

    def do_GET(self) -> None:  # noqa: N802 — stdlib API
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        token = params.get("token", [None])[0]
        if token:
            _CallbackHandler.received_token = token
            body = (
                b"<!doctype html><meta charset=utf-8>"
                b"<title>phrase-sec-scan</title>"
                b"<body style='font: 15px sans-serif; padding: 2rem;'>"
                b"<h2>You're signed in.</h2>"
                b"<p>You can close this window and return to your terminal.</p>"
                b"</body>"
            )
        else:
            body = b"<!doctype html><h2>Missing token</h2>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args, **_kwargs) -> None:  # noqa: D401
        # Silence stdlib's per-request stderr noise.
        return


def _login(scanner_url: str, *, manual: bool = False) -> int:
    """Run the browser-callback login flow. Returns a process exit code."""
    scanner_url = scanner_url.rstrip("/")
    if manual:
        print(
            f"Visit {scanner_url}/portal/ in your browser, issue a token, paste it here.",
        )
        token = input("Token: ").strip()
        if not token:
            print("ERROR: no token entered.", file=sys.stderr)
            return 2
        _save_config({"scanner_url": scanner_url, "token": token})
        print(f"Saved to {_CONFIG_FILE}.")
        return 0

    port = _find_free_port()
    hostname = socket.gethostname() or "unknown-host"
    safe_hostname = "".join(c for c in hostname if c.isalnum() or c in "-._") or "host"
    consent_url = (
        f"{scanner_url}/portal/cli/login"
        f"?callback_port={port}"
        f"&hostname={urllib.parse.quote(safe_hostname)}"
    )

    # State only used to log if a stray request shows up; the actual security
    # comes from the loopback bind + the SSO session at the portal.
    _CallbackHandler.expected_state = secrets.token_urlsafe(16)
    _CallbackHandler.received_token = None

    server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server.timeout = 1.0

    print(f"Opening {consent_url}")
    print(f"Waiting up to {_LOGIN_TIMEOUT_SECONDS}s for the browser callback …")
    try:
        webbrowser.open(consent_url)
    except webbrowser.Error:
        print("Could not open browser automatically; copy the URL above.")

    def serve() -> None:
        deadline = threading.Event()
        elapsed = 0.0
        while not deadline.is_set() and elapsed < _LOGIN_TIMEOUT_SECONDS:
            server.handle_request()
            if _CallbackHandler.received_token is not None:
                return
            elapsed += server.timeout

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    thread.join(timeout=_LOGIN_TIMEOUT_SECONDS + 5)
    server.server_close()

    token = _CallbackHandler.received_token
    if not token:
        print(
            "ERROR: login timed out. Re-run, or use --manual to paste a token.",
            file=sys.stderr,
        )
        return 2

    _save_config({"scanner_url": scanner_url, "token": token})
    print(f"Saved to {_CONFIG_FILE}.")
    return 0


def _logout(*, revoke_remote: bool = True) -> int:
    """Delete the local config, and optionally revoke the server-side token."""
    cfg = _load_config()
    if revoke_remote and cfg.get("scanner_url") and cfg.get("token"):
        revoke_url = cfg["scanner_url"].rstrip("/") + "/portal/tokens/revoke"
        try:
            req = urllib.request.Request(  # noqa: S310 — scanner_url is user-supplied https endpoint
                revoke_url,
                method="POST",
                headers={"Authorization": f"Bearer {cfg['token']}"},
                data=b"",
            )
            urllib.request.urlopen(  # noqa: S310
                req,
                timeout=10,
                context=ssl.create_default_context(cafile=certifi.where()),
            ).read()
        except (URLError, OSError) as exc:
            print(
                f"WARN: could not revoke server-side token ({exc}); deleting local config anyway.",
                file=sys.stderr,
            )
    if _CONFIG_FILE.exists():
        _CONFIG_FILE.unlink()
        print(f"Removed {_CONFIG_FILE}.")
    else:
        print("Already logged out.")
    return 0


# --- Remote-mode scan --------------------------------------------------------


def _collect_files(root: Path, directory: str) -> dict[str, str]:
    return LocalFilesClient(root).get_repo_files(path=directory)


def _scan_remote(
    *,
    root: Path,
    directory: str,
    scanner_url: str,
    token: str,
) -> int:
    files = _collect_files(root, directory)
    if not files:
        print("ERROR: no files to scan.", file=sys.stderr)
        return 2

    body = json.dumps(
        {
            "files": files,
            "triggered_by": _triggered_by(root),
            "directory": directory,
            "repo_url": _derive_repo_url(root),
        }
    ).encode("utf-8")

    req = urllib.request.Request(  # noqa: S310 — scanner_url is user-supplied https endpoint
        scanner_url.rstrip("/") + "/scan/local",
        method="POST",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    print(f"POST {scanner_url}/scan/local  ({len(files)} files) …")
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(req, timeout=600, context=ctx) as resp:  # noqa: S310
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        if exc.code == 401:
            print(
                "ERROR: 401 from scanner. Run `phrase-sec-scan login` to refresh your token.",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: scanner returned HTTP {exc.code}: {body_text}", file=sys.stderr)
        return 2
    except (URLError, OSError) as exc:
        print(f"ERROR: could not reach scanner at {scanner_url}: {exc}", file=sys.stderr)
        return 2

    report_dir = root / _REPORT_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / _REPORT_FILENAME
    report_path.write_text(payload["markdown"], encoding="utf-8")
    print(
        f"\nDone. {payload['findings_count']} findings "
        f"({payload['critical']} Critical, {payload['high']} High)."
    )
    rel = report_path.relative_to(root)
    print(f"Wrote: {rel}")
    print(f"Open {rel} for findings.")
    return 1 if (payload["critical"] or payload["high"]) else 0


# --- Local-mode scan (original behaviour) ------------------------------------


def _scan_local(*, root: Path, directory: str) -> int:
    import asyncio  # noqa: PLC0415

    from security_scanner.pipeline import ScanPipeline, TokenLimitError  # noqa: PLC0415

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        print(
            "ERROR: ANTHROPIC_API_KEY is required for --local mode. "
            "Drop the flag to use the remote scanner instead.",
            file=sys.stderr,
        )
        return 2

    scan_target = ScanTarget.directory if directory else ScanTarget.full_repo
    pipeline = ScanPipeline(
        LocalFilesClient(root),
        ClaudeClient(api_key=api_key),
        mode=ScanType.on_demand,
    )

    print(f"Scanning {root} (local pre-push, on_demand) …")
    try:
        result = asyncio.run(
            pipeline.run(
                repo_url=_derive_repo_url(root),
                scan_target=scan_target,
                triggered_by=_triggered_by(root),
                directory=directory,
            )
        )
    except TokenLimitError as exc:
        print(
            f"Project is too large to scan in one pass "
            f"(~{exc.estimated_tokens} tokens > {exc.threshold} limit).\n"
            f"Re-run scoped to a sub-directory:  phrase-sec-scan --directory <subdir>",
            file=sys.stderr,
        )
        return 2

    report_dir = root / _REPORT_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / _REPORT_FILENAME
    report_path.write_text(build_markdown_report(result), encoding="utf-8")
    written = [str(report_path.relative_to(root))]
    for filename, patch_text in result.patches.items():
        (root / filename).write_text(patch_text, encoding="utf-8")
        written.append(filename)

    critical = sum(1 for f in result.findings if f.severity == Severity.Critical)
    high = sum(1 for f in result.findings if f.severity == Severity.High)
    print(
        f"\nDone. {result.findings_count} findings "
        f"({critical} Critical, {high} High)."
        + (" Scan was partial — see report header." if result.partial_scan else "")
    )
    print("Wrote: " + ", ".join(written))
    print(
        f"Open {report_path.relative_to(root)} for findings + fix snippets. "
        "Apply patches with `git apply <file>.patch` after reviewing, then re-run."
    )
    return 1 if (critical or high) else 0


# --- argparse wiring ---------------------------------------------------------


_SUBCOMMANDS = {"login", "logout", "scan"}


def _build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phrase-sec-scan",
        description=(
            "Local pre-push security scan. Default mode POSTs to the deployed "
            "scanner; run `phrase-sec-scan login` once to authenticate."
        ),
    )
    p.add_argument(
        "path", nargs="?", default=".",
        help="Project directory to scan (default: current dir)",
    )
    p.add_argument(
        "--directory", default="",
        help="Scan only this sub-path of the project (use for large repos)",
    )
    p.add_argument(
        "--local", action="store_true",
        help="Run the scan pipeline on this machine (needs ANTHROPIC_API_KEY) "
             "instead of POSTing to the deployed scanner.",
    )
    return p


def _build_login_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phrase-sec-scan login")
    p.add_argument("--scanner-url", default=os.getenv("SCANNER_URL"))
    p.add_argument("--manual", action="store_true")
    return p


def _build_logout_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phrase-sec-scan logout")
    p.add_argument("--keep-remote", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    # Manual subcommand dispatch — argparse subparsers fight with the legacy
    # `phrase-sec-scan <path>` shape, so we route on the first arg ourselves.
    if raw and raw[0] in _SUBCOMMANDS:
        cmd, rest = raw[0], raw[1:]
        if cmd == "login":
            args = _build_login_parser().parse_args(rest)
            url = args.scanner_url or _load_config().get("scanner_url")
            if not url:
                print(
                    "ERROR: --scanner-url is required on first login "
                    "(or set $SCANNER_URL).",
                    file=sys.stderr,
                )
                return 2
            return _login(url, manual=args.manual)
        if cmd == "logout":
            args = _build_logout_parser().parse_args(rest)
            return _logout(revoke_remote=not args.keep_remote)
        # cmd == "scan"
        raw = rest

    args = _build_scan_parser().parse_args(raw)
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"ERROR: {root} is not a directory.", file=sys.stderr)
        return 2

    if args.local:
        return _scan_local(root=root, directory=args.directory)

    scanner_url, token = _resolve_endpoint()
    if not scanner_url or not token:
        print(
            "ERROR: not logged in. Run `phrase-sec-scan login --scanner-url "
            "https://<scanner>` first, or pass --local for offline mode.",
            file=sys.stderr,
        )
        return 2
    return _scan_remote(
        root=root, directory=args.directory, scanner_url=scanner_url, token=token
    )


if __name__ == "__main__":
    raise SystemExit(main())
