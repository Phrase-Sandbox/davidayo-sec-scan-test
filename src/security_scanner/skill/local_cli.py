"""``phrase-sec-scan`` — local pre-push security scan CLI.

POSTs the working tree to ``${scanner_url}/scan/local`` and prints the
report. Authentication: a personal scanner token issued through the
Okta-walled portal (``/portal/``). The CLI stores only the URL + token in
``~/.phrase-sec-scan/config.yaml`` (mode 0600). No API key is ever stored
on disk — the server resolves the user's LLM provider settings from the DB.

``mode=on_demand`` ⇒ BR-009 parallel verification is skipped per spec §4.1
(same as the hosted skill — this is the informational path, not the gate).
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
import time
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from urllib.error import URLError

import certifi

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


def _collect_files(
    root: Path, directory: str, *, respect_gitignore: bool = True
) -> dict[str, str]:
    return LocalFilesClient(
        root, respect_gitignore=respect_gitignore
    ).get_repo_files(path=directory)


def _scan_remote(
    *,
    root: Path,
    directory: str,
    scanner_url: str,
    token: str,
    respect_gitignore: bool = True,
) -> int:
    """POST the working tree to /scan/local and write the report.

    The server loads the user's LLM provider/model/key from the DB using the
    bearer token identity.  No API key is ever sent by the CLI.
    """
    files = _collect_files(root, directory, respect_gitignore=respect_gitignore)
    if not files:
        print("ERROR: no files to scan.", file=sys.stderr)
        return 2

    payload_obj: dict = {
        "files": files,
        "triggered_by": _triggered_by(root),
        "directory": directory,
        "repo_url": _derive_repo_url(root),
    }
    body = json.dumps(payload_obj).encode("utf-8")

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
    ctx = ssl.create_default_context(cafile=certifi.where())
    payload: dict | None = None
    for attempt in (1, 2):  # one retry on 429+Retry-After
        try:
            with urllib.request.urlopen(req, timeout=600, context=ctx) as resp:  # noqa: S310
                payload = json.loads(resp.read())
            break
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            if exc.code == 429 and attempt == 1:
                retry_after_raw = exc.headers.get("Retry-After", "10")
                try:
                    retry_after = max(1, min(int(retry_after_raw), 60))
                except ValueError:
                    retry_after = 10
                print(
                    f"Scanner is busy (429). Retrying in {retry_after}s …",
                    file=sys.stderr,
                )
                time.sleep(retry_after)
                continue
            if exc.code == 401:
                # Try to surface the server's specific reason (expired /
                # deactivated) so the user knows what to do.
                detail_text = ""
                try:
                    detail_text = json.loads(body_text).get("detail", "") or ""
                except (ValueError, TypeError):
                    detail_text = body_text
                detail_lower = detail_text.lower()
                if "expired" in detail_lower:
                    print(
                        "ERROR: your scanner token has expired (30-day TTL).\n"
                        f"  Visit {scanner_url.rstrip('/')}/portal/ to re-issue a new one.",
                        file=sys.stderr,
                    )
                elif "deactivated" in detail_lower:
                    print(
                        "ERROR: your account has been deactivated. "
                        "Contact your administrator.",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "ERROR: authentication failed. "
                        "Run `phrase-sec-scan login` to refresh your token.",
                        file=sys.stderr,
                    )
                return 2
            if exc.code == 412:
                # User hasn't saved their LLM settings in the portal yet.
                detail_text = ""
                try:
                    detail_text = json.loads(body_text).get("detail", "") or ""
                except (ValueError, TypeError):
                    detail_text = body_text
                print(
                    "ERROR: no LLM provider configured for your account.\n"
                    f"  Visit {scanner_url.rstrip('/')}/portal/settings to "
                    "choose a provider and save your API key.",
                    file=sys.stderr,
                )
                if detail_text:
                    print(f"  (Server: {detail_text})", file=sys.stderr)
                return 2
            if exc.code == 502:
                # Scanner couldn't complete the scan (parse error, LLM quota,
                # or other upstream failure). Distinct exit code so scripts can
                # distinguish from config/auth errors.
                detail_kind = ""
                detail_provider = ""
                detail_message = body_text
                try:
                    parsed = json.loads(body_text)
                    detail = parsed.get("detail") if isinstance(parsed, dict) else None
                    if isinstance(detail, dict):
                        detail_kind = str(detail.get("error") or "")
                        detail_provider = str(detail.get("provider") or "")
                        detail_message = str(detail.get("message") or body_text)
                except (ValueError, TypeError):
                    pass

                if detail_kind == "llm_quota_exhausted":
                    provider_name = detail_provider or "your LLM provider"
                    print(
                        f"ERROR: your {provider_name} API key has hit its quota. "
                        "No scan was performed — top up your account (or wait for "
                        "the daily reset on free tiers), then re-run.\n"
                        f"  Visit {scanner_url.rstrip('/')}/portal/settings to "
                        "update your API key if it has been rotated.",
                        file=sys.stderr,
                    )
                elif detail_kind == "llm_upstream_unavailable":
                    provider_name = detail_provider or "the LLM provider"
                    print(
                        f"ERROR: {provider_name} is unavailable right now. "
                        "Try again shortly; if it persists, check the provider's "
                        "status page or update your API key in the portal.",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "ERROR: scanner failed mid-scan (upstream LLM error). "
                        "Try again; if it persists, file a bug.",
                        file=sys.stderr,
                    )
                if detail_message:
                    print(f"  details: {detail_message}", file=sys.stderr)
                return 3
            print(f"ERROR: scanner returned HTTP {exc.code}: {body_text}", file=sys.stderr)
            return 2
        except (URLError, OSError) as exc:
            print(f"ERROR: could not reach scanner at {scanner_url}: {exc}", file=sys.stderr)
            return 2
    if payload is None:  # both attempts exhausted
        print("ERROR: scanner remained busy after retry; try again shortly.", file=sys.stderr)
        return 2

    report_dir = root / _REPORT_DIR
    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / _REPORT_FILENAME
    md_path.write_text(payload["markdown"], encoding="utf-8")
    written = [md_path.relative_to(root)]
    # Older servers may not ship the html field — guard so the CLI stays
    # compatible. Newer servers always include it.
    if payload.get("html"):
        html_path = report_dir / _REPORT_FILENAME.replace(".md", ".html")
        html_path.write_text(payload["html"], encoding="utf-8")
        written.append(html_path.relative_to(root))
    print(
        f"\nDone. {payload['findings_count']} findings "
        f"({payload['critical']} Critical, {payload['high']} High)."
    )
    print("Wrote: " + ", ".join(str(p) for p in written))
    print(f"Open {written[-1]} for findings.")
    return 1 if (payload["critical"] or payload["high"]) else 0


# --- argparse wiring ---------------------------------------------------------


_SUBCOMMANDS = {"login", "logout", "scan"}


def _build_scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phrase-sec-scan",
        description=(
            "Local pre-push security scan. POSTs your working tree to the "
            "deployed scanner, which runs the full pipeline under your stored "
            "LLM settings. Run `phrase-sec-scan login` once to authenticate.\n\n"
            "Provider/model/key are managed in the portal (/portal/settings) "
            "— no API key is ever stored or sent by this CLI."
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
        "--no-gitignore", action="store_true",
        help="Do NOT exclude files matched by .gitignore at the scan root. "
             "By default, gitignored files are skipped to avoid wasted work "
             "and false positives on intentionally-uncommitted secrets.",
    )
    return p


def _build_login_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phrase-sec-scan login",
        description=(
            "Authenticate with the scanner portal and save your personal token. "
            "Opens a browser to the portal's loopback login page. Use --manual "
            "to paste a token from the portal instead."
        ),
    )
    p.add_argument("--scanner-url", default=os.getenv("SCANNER_URL"))
    p.add_argument("--manual", action="store_true",
                   help="Paste a token from the portal instead of the browser flow.")
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

    respect_gitignore = not args.no_gitignore

    scanner_url, token = _resolve_endpoint()
    if not scanner_url or not token:
        print(
            "ERROR: not logged in. Run `phrase-sec-scan login --scanner-url "
            "https://<scanner>` first.",
            file=sys.stderr,
        )
        return 2

    return _scan_remote(
        root=root, directory=args.directory, scanner_url=scanner_url, token=token,
        respect_gitignore=respect_gitignore,
    )


if __name__ == "__main__":
    raise SystemExit(main())
