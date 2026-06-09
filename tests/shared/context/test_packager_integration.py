"""End-to-end integration tests for ContextPackager."""

from __future__ import annotations

from security_scanner.shared.context.models import ContextBundle
from security_scanner.shared.context.packager import ContextPackager, is_high_risk_path
from security_scanner.shared.scanners.types import CandidateForVerification


def _candidate(
    file: str = "app/views.py",
    vuln_class: str = "idor",
    line_start: int = 10,
    line_end: int = 20,
) -> CandidateForVerification:
    return CandidateForVerification(
        file=file,
        vuln_class=vuln_class,
        line_start=line_start,
        line_end=line_end,
        severity="High",
        confidence="High",
    )


FLASK_APP = """\
from flask import Flask, request, g
app = Flask(__name__)

@app.route('/documents/<int:doc_id>', methods=['GET'])
@login_required
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    return jsonify(doc.to_dict())
"""

IDOR_APP = """\
from flask import Flask, request
app = Flask(__name__)

@app.route('/docs/<int:doc_id>')
def get_doc(doc_id):
    # No ownership check
    doc = Document.query.filter_by(id=doc_id).first()
    return jsonify(doc.to_dict())
"""


def test_attach_returns_bundle_for_each_candidate():
    packager = ContextPackager()
    c1 = _candidate("app/views.py", "idor", 4, 10)
    c2 = _candidate("app/api.py", "sqli", 20, 30)
    files = {
        "app/views.py": FLASK_APP,
        "app/api.py": "def query(id):\n    db.execute(f'SELECT * FROM t WHERE id={id}')\n",
    }
    bundles = packager.attach([c1, c2], files)
    assert id(c1) in bundles
    assert id(c2) in bundles


def test_bundle_contains_correct_file():
    packager = ContextPackager()
    c = _candidate("app/views.py", "idor", 4, 10)
    bundles = packager.attach([c], {"app/views.py": FLASK_APP})
    bundle = bundles[id(c)]
    assert bundle.file == "app/views.py"
    assert bundle.vuln_class == "idor"


def test_bundle_has_route_when_flask_route_present():
    packager = ContextPackager()
    c = _candidate("app/views.py", "idor", 6, 10)
    bundles = packager.attach([c], {"app/views.py": FLASK_APP})
    bundle = bundles[id(c)]
    assert len(bundle.route_definitions) >= 1
    assert any(r.path == "/documents/<int:doc_id>" for r in bundle.route_definitions)


def test_bundle_has_ownership_check_when_present():
    packager = ContextPackager()
    c = _candidate("app/views.py", "idor", 6, 10)
    bundles = packager.attach([c], {"app/views.py": FLASK_APP})
    bundle = bundles[id(c)]
    # The Flask app has a current_user.id comparison.
    assert len(bundle.ownership_checks) >= 1


def test_bundle_missing_ownership_on_idor_app():
    packager = ContextPackager()
    c = _candidate("app/idor.py", "idor", 5, 8)
    bundles = packager.attach([c], {"app/idor.py": IDOR_APP})
    bundle = bundles[id(c)]
    # No ownership check in this file.
    cu_checks = [o for o in bundle.ownership_checks if o.current_user_derived]
    assert len(cu_checks) == 0


def test_empty_bundle_on_extractor_exception():
    """Packager must degrade to empty bundle, not raise."""
    packager = ContextPackager()
    c = _candidate("nonexistent.py", "idor", 1, 5)
    # File not in dict — should produce empty bundle, not raise.
    bundles = packager.attach([c], {})
    bundle = bundles[id(c)]
    assert isinstance(bundle, ContextBundle)
    assert bundle.file == "nonexistent.py"


def test_snippet_truncated_to_budget():
    # Create a 200-line file.
    big_content = "\n".join(f"x_{i} = {i}" for i in range(200))
    packager = ContextPackager()
    c = _candidate("app/big.py", "sqli", 50, 60)
    bundles = packager.attach([c], {"app/big.py": big_content})
    bundle = bundles[id(c)]
    snippet_lines = bundle.snippet.splitlines()
    assert len(snippet_lines) <= 30  # _MAX_SNIPPET_LINES


def test_is_high_risk_path_auth():
    assert is_high_risk_path("auth/login.py")
    assert is_high_risk_path("src/auth/login.py")


def test_is_high_risk_path_admin():
    assert is_high_risk_path("admin/views.py")


def test_is_not_high_risk_path():
    assert not is_high_risk_path("utils/helpers.py")
    assert not is_high_risk_path("internal/parsing.py")


def test_attach_empty_candidates():
    packager = ContextPackager()
    bundles = packager.attach([], {"app.py": "x = 1"})
    assert bundles == {}


# ---------------------------------------------------------------------------
# V7: source-aware snippet window
# ---------------------------------------------------------------------------


def _candidate_with_sources(
    sources: list[str],
    line_start: int = 20,
    line_end: int = 20,
) -> CandidateForVerification:
    return CandidateForVerification(
        file="app.py",
        vuln_class="sqli",
        line_start=line_start,
        line_end=line_end,
        severity="High",
        confidence="Medium",
        sources=sources,
    )


def _fifty_line_file() -> str:
    return "\n".join(f"line_{i:03d} = {i}" for i in range(1, 51))


def test_scanner_only_gets_wider_snippet_than_claude_finding():
    """Scanner-only candidates get ±14 lines; Claude/merged get ±8 lines."""
    content = _fifty_line_file()
    files = {"app.py": content}
    packager = ContextPackager()

    scanner_cand = _candidate_with_sources(["bandit"], line_start=25, line_end=25)
    claude_cand = _candidate_with_sources(["claude"], line_start=25, line_end=25)

    bundles = packager.attach([scanner_cand, claude_cand], files)

    scanner_lines = len(bundles[id(scanner_cand)].snippet.splitlines())
    claude_lines = len(bundles[id(claude_cand)].snippet.splitlines())

    assert scanner_lines > claude_lines, (
        f"scanner-only snippet ({scanner_lines} lines) should be wider "
        f"than claude snippet ({claude_lines} lines)"
    )


def test_merged_finding_gets_narrow_snippet():
    """Merged findings (claude + scanner) use the ±8 window, not the wider ±14."""
    content = _fifty_line_file()
    files = {"app.py": content}
    packager = ContextPackager()

    merged_cand = _candidate_with_sources(["claude", "bandit"], line_start=25, line_end=25)
    scanner_cand = _candidate_with_sources(["bandit"], line_start=25, line_end=25)

    bundles = packager.attach([merged_cand, scanner_cand], files)

    merged_lines = len(bundles[id(merged_cand)].snippet.splitlines())
    scanner_lines = len(bundles[id(scanner_cand)].snippet.splitlines())

    assert scanner_lines >= merged_lines


def test_scanner_only_snippet_still_capped_at_max_snippet_lines():
    """Even with ±14 expansion the snippet must not exceed _MAX_SNIPPET_LINES (30)."""
    content = _fifty_line_file()
    packager = ContextPackager()
    cand = _candidate_with_sources(["semgrep"], line_start=25, line_end=25)
    bundles = packager.attach([cand], {"app.py": content})
    assert len(bundles[id(cand)].snippet.splitlines()) <= 30
