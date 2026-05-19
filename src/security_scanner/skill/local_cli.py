"""``phrase-sec-scan`` — local pre-push security scan CLI.

Runs the SAME ``ScanPipeline`` as the on-demand skill, but against the
developer's local working directory instead of a GitHub fetch, and writes
the Markdown report + one ``.patch`` per fixable finding INTO the project
folder so the developer can review and fix *before* pushing.

``mode=on_demand`` ⇒ BR-009 parallel verification is skipped per spec §4.1
(same as the hosted skill — this is the informational path, not the gate).

This is a documented deviation from spec §2.2 (the spec skill fetches from
GitHub via OAuth). The hosted spec skill is unchanged and still available.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
from pathlib import Path

from security_scanner.pipeline import ScanPipeline, TokenLimitError
from security_scanner.shared.claude.client import ClaudeClient
from security_scanner.shared.models.enums import ScanTarget, ScanType, Severity
from security_scanner.shared.reports.markdown import build_markdown_report
from security_scanner.skill.local_files import LocalFilesClient

_REPORT_FILENAME = "security-scan-report.md"


def _git(args: list[str], cwd: Path) -> str:
    # Fixed argv (no shell); git is intentionally resolved from PATH.
    cmd = ["git", *args]
    try:
        out = subprocess.run(  # noqa: S603, S607
            cmd, cwd=cwd, capture_output=True, text=True, timeout=5, check=False
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _derive_repo_url(root: Path) -> str:
    """A parseable GitHub URL so the pipeline's URL check passes.

    The ``LocalFilesClient`` ignores owner/repo entirely (same as the test
    mock), so a synthetic URL is harmless when there is no real remote.
    """
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="phrase-sec-scan",
        description="Local pre-push security scan (writes a report + patches into the project).",
    )
    parser.add_argument(
        "path", nargs="?", default=".", help="Project directory to scan (default: current dir)"
    )
    parser.add_argument(
        "--directory",
        default="",
        help="Scan only this sub-path of the project (use for large repos)",
    )
    args = parser.parse_args(argv)

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY is not set in the environment.", file=sys.stderr)
        return 2

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"ERROR: {root} is not a directory.", file=sys.stderr)
        return 2

    scan_target = ScanTarget.directory if args.directory else ScanTarget.full_repo
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
                directory=args.directory,
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

    report_path = root / _REPORT_FILENAME
    report_path.write_text(build_markdown_report(result), encoding="utf-8")
    written = [report_path.name]
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
        f"Open {_REPORT_FILENAME} for findings + fix snippets. "
        "Apply patches with `git apply <file>.patch` after reviewing, then re-run."
    )
    # Non-zero exit if blocking-grade findings exist, so this is also usable
    # as a local pre-commit hook. Informational only — never enforced server-side.
    return 1 if (critical or high) else 0


if __name__ == "__main__":
    raise SystemExit(main())
