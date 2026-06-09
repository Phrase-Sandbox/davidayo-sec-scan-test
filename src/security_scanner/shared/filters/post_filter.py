"""Post-processing filter for Claude findings (§4.1 build notes, §12, §13.5).

The prompt-level filter rules in ``shared/prompts/system.py`` instruct Claude
to skip certain findings, but the model occasionally emits them anyway. This
module enforces the same rules **programmatically** as a backstop, in two
ordered passes:

1. **Test / fixture / mock paths** — code under these directories is not
   production code. Findings there are noise even when correctly identified.
2. **Lockfiles and vendored dependencies** — never developer-authored, never
   the right place to apply a fix.

Low-confidence findings are **not** dropped here. They flow to the verifier
where the ``ADVISORY_CONFIDENCES`` setting routes them to non-blocking advisory
status. This matches scanner-only findings, which are always promoted to Medium
before reaching the verifier and would otherwise have an unfair asymmetric
advantage.

Each drop emits one structured log line containing only ``affected_file``,
``vulnerability_id`` and ``rule``. Finding *content* — descriptions, exploit
scenarios, suggested fixes — is never logged (spec §11, "What NOT to Do" #1).
"""

from __future__ import annotations

from posixpath import basename, normpath

from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.models.finding import VulnerabilityFinding

log = get_logger(__name__)

TEST_PATH_MARKERS: frozenset[str] = frozenset(
    {
        "/test/",
        "/tests/",
        "/spec/",
        "/specs/",
        "/__tests__/",
        "/fixtures/",
        "/mocks/",
        "/stubs/",
    }
)

TEST_FILE_SUFFIXES: tuple[str, ...] = (
    "_test.py",
    "_spec.rb",
    ".test.js",
    ".test.ts",
    ".spec.js",
    ".spec.ts",
)

DEPENDENCY_PATH_MARKERS: frozenset[str] = frozenset(
    {"/node_modules/", "/vendor/", "/third_party/"}
)

LOCKFILE_NAMES: frozenset[str] = frozenset(
    {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}
)


def filter_findings(
    findings: list[VulnerabilityFinding],
) -> list[VulnerabilityFinding]:
    """Return only findings that survive the three mechanical drop rules.

    The input list is not mutated.
    """
    survivors: list[VulnerabilityFinding] = []
    for finding in findings:
        rule = _drop_rule(finding)
        if rule is None:
            survivors.append(finding)
            continue
        log.info(
            "post-filter dropped finding",
            affected_file=finding.affected_file,
            vulnerability_id=finding.vulnerability_id,
            rule=rule,
        )
    return survivors


def _drop_rule(finding: VulnerabilityFinding) -> str | None:
    """Return the name of the first rule that matches, or ``None`` if the finding survives."""
    if _is_test_path(finding.affected_file):
        return "test_or_fixture_path"
    if _is_dependency_path(finding.affected_file):
        return "lockfile_or_vendored"
    return None


def _is_test_path(path: str) -> bool:
    # Normalise so that "tests/foo.py" matches the "/tests/" marker.
    normalized = "/" + normpath(path).lstrip("/")
    if any(marker in normalized for marker in TEST_PATH_MARKERS):
        return True
    return basename(path).endswith(TEST_FILE_SUFFIXES)


def _is_dependency_path(path: str) -> bool:
    normalized = "/" + normpath(path).lstrip("/")
    if any(marker in normalized for marker in DEPENDENCY_PATH_MARKERS):
        return True
    return basename(path) in LOCKFILE_NAMES
