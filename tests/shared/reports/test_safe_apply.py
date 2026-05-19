"""Tests for scripts/lib/safe_apply.py — the auto-fix-PR safety gauntlet.

safe_apply.py is intentionally outside the package (the reusable workflow
runs it inside the calling repo's checkout), so it is imported by path.
"""

from __future__ import annotations

import json
import pathlib
import sys

_LIB = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "lib"
sys.path.insert(0, str(_LIB))

import safe_apply  # noqa: E402


def _finding(**kw):
    base = {
        "vulnerability_id": "A03:2021",
        "affected_file": "app/db.py",
        "affected_lines": "2",
        "description": "SQL injection via string concatenation",
        "owasp_reference": "https://owasp.org/Top10/A03_2021",
        "suggested_fix": "",
    }
    base.update(kw)
    return base


# --- pure helpers -----------------------------------------------------------


def test_extract_code_block_and_range():
    assert safe_apply.extract_code_block("```py\nx = 1\n```") == "x = 1"
    assert safe_apply.extract_code_block("no fence here") is None
    assert safe_apply.parse_line_range("42") == (42, 42)
    assert safe_apply.parse_line_range("42-55") == (42, 55)
    assert safe_apply.parse_line_range("42–55") == (42, 55)  # en-dash
    assert safe_apply.parse_line_range(None) is None
    assert safe_apply.parse_line_range("nope") is None


def test_is_sketch():
    assert safe_apply.is_sketch(None) is True
    assert safe_apply.is_sketch("    ...") is True
    assert safe_apply.is_sketch("# rest of the code unchanged") is True
    assert safe_apply.is_sketch("API_KEY = os.environ['X']\n# add this") is True
    assert safe_apply.is_sketch("value = sanitize(raw)") is False


def test_manual_only_category():
    assert safe_apply.is_manual_only_category("A07:2021", "", "") is not None  # auth
    assert safe_apply.is_manual_only_category("A02:2021", "", "") is not None  # crypto
    assert safe_apply.is_manual_only_category("A01:2021", "", "") is not None  # access ctl
    assert safe_apply.is_manual_only_category("A08:2021", "", "") is not None  # integrity
    assert (
        safe_apply.is_manual_only_category("LLM01:2025", "", "uses pickle.loads on input")
        is not None
    )
    assert safe_apply.is_manual_only_category("A03:2021", "url", "SQL injection") is None


def test_protected_path():
    assert safe_apply.is_protected_path("src/auth/login.py") is True
    assert safe_apply.is_protected_path("services/middleware/cors.py") is True
    assert safe_apply.is_protected_path("config.py") is True
    assert safe_apply.is_protected_path("settings.py") is True
    assert safe_apply.is_protected_path("Dockerfile") is True
    assert safe_apply.is_protected_path("k8s/deployment.yaml") is True
    assert safe_apply.is_protected_path("src/handlers/query.py") is False


def test_protected_variable():
    assert safe_apply.touches_protected_variable("DEBUG = False", "DEBUG = True") == "DEBUG"
    assert safe_apply.touches_protected_variable("x = 1", 'SECRET_KEY = "a"') == "SECRET_KEY"
    assert safe_apply.touches_protected_variable("a = 1", "b = 2") is None


def test_introduced_forbidden_is_introduced_only():
    # Newly introduced -> flagged.
    assert safe_apply.introduced_forbidden("safe_eval(x)", "eval(x)") == "eval("
    assert safe_apply.introduced_forbidden("run()", "run(shell=True)") == "shell=True"
    assert (
        safe_apply.introduced_forbidden("a", "data = yaml.load(s)")
        == "yaml.load( without Loader="
    )
    # Already present in the replaced lines -> not this fix's regression.
    assert safe_apply.introduced_forbidden("eval(old)", "eval(new)") is None
    # Safe yaml.load with Loader -> fine.
    assert safe_apply.introduced_forbidden("a", "yaml.load(s, Loader=yaml.SafeLoader)") is None
    assert safe_apply.introduced_forbidden("x = 1", "x = sanitize(1)") is None


# Representative per category — every entry is an unambiguous weakening that
# a fix must never introduce (v1.8 exhaustive anti-pattern table).
_BLOCK_CASES = [
    ("requests.get(u)", "requests.get(u, verify=False)"),
    ("c(ssl=True)", "c(ssl=False)"),
    ("x=1", "client(check_hostname=False)"),
    ("x=1", "ctx = ssl._create_unverified_context()"),
    ("x=1", 'allow_origins=["*"]'),
    ("x=1", "CORS_ORIGIN_ALLOW_ALL = True"),
    ("x=1", "auth_disabled=True"),
    ("x=1", "@csrf_exempt"),
    ("x=1", "WTF_CSRF_ENABLED = False"),
    ("x=1", "SESSION_COOKIE_SECURE = False"),
    ("x=1", "permission_classes = [AllowAny]"),
    ("x=1", "authentication_classes = []"),
    ("x=1", 'jwt.decode(t, k, algorithm="none")'),
    ("x=1", "jwt.decode(t, options={'verify_signature': False})"),
    ("h=sha256()", "h=hashlib.md5(b)"),
    ("x=1", "cipher = AES.new(k, MODE_ECB)"),
    ("x=1", "ctx = ssl.PROTOCOL_TLSv1"),
    ("x=1", "data = pickle.loads(b)"),
    ("x=1", "m = marshal.loads(b)"),
    ("x=1", "os.system(cmd)"),
    ("x=1", "obj = torch.load(p)"),
    ("x=1", "os.chmod(p, 0o777)"),
    ("x=1", "t = tempfile.mktemp()"),
    ("x=1", "tar.extractall(path)"),
    ("x=1", "app.run(debug=True)"),
    ("run()", "run(shell=True)"),
    ("safe_eval(x)", "eval(x)"),
]

# Must NOT hard-block: safe forms, the 3 deliberately-excluded ambiguous
# patterns, introduced-only (already present), and look-alikes.
_ALLOW_CASES = [
    ("x=1", "y = ast.literal_eval(s)"),          # not eval(
    ("x=1", "requests.get(u, verify=True)"),
    ("x=1", "client(ssl=ssl_ctx)"),
    ("x=1", "h = hashlib.md5(b, usedforsecurity=False)"),
    ("x=1", "yaml.safe_load(s)"),
    ("x=1", "yaml.load(s, Loader=yaml.SafeLoader)"),
    ("x=1", 'app.run(host="0.0.0.0")'),          # EXCLUDED (bind-all)
    ("x=1", "n = random.randint(1, 9)"),         # EXCLUDED (bare random)
    ("x=1", "root = etree.fromstring(xml)"),      # EXCLUDED (broad XML)
    ("x=1", "ctx = ssl.PROTOCOL_TLSv1_2"),       # TLS1.2 is fine
    ("cursor.execute(q)", "cursor.execute(q, p)"),  # .execute != exec(
    ("x=1", "algorithm = 'HS256'"),               # only "none" is bad
    ("requests.get(u, verify=False)", "requests.get(u, verify=False, timeout=5)"),  # pre-existing
]


def test_forbidden_table_blocks_every_introduced_anti_pattern():
    for old, new in _BLOCK_CASES:
        label = safe_apply.introduced_forbidden(old, new)
        assert label, f"should block introduced anti-pattern: {new!r}"


def test_forbidden_table_allows_safe_excluded_and_preexisting():
    for old, new in _ALLOW_CASES:
        label = safe_apply.introduced_forbidden(old, new)
        assert label is None, f"should NOT block {new!r}; got {label!r}"


def test_excluded_ambiguous_patterns_are_not_hard_blocked():
    # Documented v1.8 scope decision: routinely-legitimate patterns are left
    # to the post-apply bandit self-check, not this pre-splice hard gate.
    assert safe_apply.introduced_forbidden("x", 'uvicorn.run(host="0.0.0.0")') is None
    assert safe_apply.introduced_forbidden("x", "token = random.getrandbits(32)") is None
    assert safe_apply.introduced_forbidden("x", "ET.fromstring(untrusted)") is None


def test_changed_line_count():
    assert safe_apply.changed_line_count(10, 10, "one line") == 1
    assert safe_apply.changed_line_count(10, 12, "a") == 3  # replaced wider
    assert safe_apply.changed_line_count(10, 10, "a\nb\nc\nd") == 4  # added wider


# --- classify_and_apply integration ----------------------------------------


def _write(root: pathlib.Path, rel: str, body: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_clean_fix_is_applied_and_compiles(tmp_path):
    _write(
        tmp_path,
        "app/db.py",
        "def q(u):\n"
        "    cur.execute(\"SELECT * FROM t WHERE u='\" + u + \"'\")\n"
        "    return cur.fetchall()\n",
    )
    fx = _finding(
        suggested_fix='```python\n    cur.execute("SELECT * FROM t WHERE u=?", (u,))\n```'
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert len(res["applied"]) == 1
    assert res["changed_files"] == ["app/db.py"]
    new = (tmp_path / "app/db.py").read_text()
    assert "?" in new and "+ u +" not in new
    import ast

    ast.parse(new)  # the kept file always compiles


def test_syntax_breaking_fix_is_rolled_back(tmp_path):
    original = "def q(u):\n    return run(u)\n"
    _write(tmp_path, "app/db.py", original)
    fx = _finding(suggested_fix="```python\n    def broken(\n```")
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert res["applied"] == []
    assert any("syntax error after fix" in m for m in res["manual"])
    assert (tmp_path / "app/db.py").read_text() == original  # untouched


def test_secret_finding_is_never_edited(tmp_path):
    original = 'API_KEY = "sk-live-abc123"\n'
    _write(tmp_path, "settings_x.py", original)
    fx = _finding(
        vulnerability_id="SECRET-001",
        affected_file="settings_x.py",
        affected_lines="1",
        suggested_fix='```python\nAPI_KEY = os.environ["API_KEY"]\n```',
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert res["applied"] == []
    assert res["secret_files"] == ["settings_x.py"]
    assert (tmp_path / "settings_x.py").read_text() == original  # untouched


def test_manual_category_strict_posture_suppresses(tmp_path):
    # propose_all=False = the legacy D-11 strict posture (still supported).
    _write(tmp_path, "app/login.py", "def check(p):\n    return p == stored\n")
    fx = _finding(
        vulnerability_id="A07:2021",
        affected_file="app/login.py",
        affected_lines="2",
        description="authentication bypass",
        suggested_fix="```python\n    return constant_time_eq(p, stored)\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path), propose_all=False)
    assert res["applied"] == []
    assert any("manual-review category" in m for m in res["manual"])


def test_manual_category_human_review_default_applies_with_risk_note(tmp_path):
    # D-13 default: the auth fix IS proposed on the branch, flagged sensitive.
    _write(tmp_path, "app/login.py", "def check(p):\n    return p == stored\n")
    fx = _finding(
        vulnerability_id="A07:2021",
        affected_file="app/login.py",
        affected_lines="2",
        description="authentication bypass",
        suggested_fix="```python\n    return constant_time_eq(p, stored)\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))  # propose_all=True
    assert any("A07:2021" in a for a in res["applied"])
    key = next(a for a in res["applied"] if "A07:2021" in a)
    assert "manual-review category" in res["risk_notes"][key]
    assert "constant_time_eq" in (tmp_path / "app/login.py").read_text()


def test_protected_path_strict_posture_suppresses(tmp_path):
    _write(tmp_path, "config.py", "VALUE = 'x'\nNAME = 'x'\n")
    fx = _finding(
        vulnerability_id="A05:2021",
        affected_file="config.py",
        affected_lines="2",
        description="misconfiguration",
        suggested_fix="```python\nNAME = 'y'\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path), propose_all=False)
    assert res["applied"] == []
    assert any("protected path" in m for m in res["manual"])


def test_protected_path_human_review_default_applies_with_risk_note(tmp_path):
    _write(tmp_path, "config.py", "VALUE = 'x'\nNAME = 'x'\n")
    fx = _finding(
        vulnerability_id="A05:2021",
        affected_file="config.py",
        affected_lines="2",
        description="misconfiguration",
        suggested_fix="```python\nNAME = 'y'\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert any("config.py" in a for a in res["applied"])
    key = next(a for a in res["applied"] if "config.py" in a)
    assert "protected path" in res["risk_notes"][key]


def test_oversized_fix_routed_to_manual(tmp_path):
    _write(tmp_path, "app/big.py", "x = 1\n")
    big = "```python\n" + "\n".join(f"a{i} = {i}" for i in range(40)) + "\n```"
    fx = _finding(
        affected_file="app/big.py", affected_lines="1", suggested_fix=big
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert res["applied"] == []
    assert any("fix too large" in m for m in res["manual"])


def test_protected_variable_strict_posture_suppresses(tmp_path):
    _write(tmp_path, "app/srv.py", "PORT = 8000\nDEBUG = True\n")
    fx = _finding(
        vulnerability_id="A05:2021",
        affected_file="app/srv.py",
        affected_lines="2",
        description="misconfig",
        suggested_fix="```python\nDEBUG = False\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path), propose_all=False)
    assert res["applied"] == []
    assert any("protected variable DEBUG" in m for m in res["manual"])


def test_protected_variable_human_review_default_applies_with_risk_note(tmp_path):
    _write(tmp_path, "app/srv.py", "PORT = 8000\nDEBUG = True\n")
    fx = _finding(
        vulnerability_id="A05:2021",
        affected_file="app/srv.py",
        affected_lines="2",
        description="misconfig",
        suggested_fix="```python\nDEBUG = False\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert any("app/srv.py" in a for a in res["applied"])
    key = next(a for a in res["applied"] if "app/srv.py" in a)
    assert "touches DEBUG" in res["risk_notes"][key]
    assert "DEBUG = False" in (tmp_path / "app/srv.py").read_text()


def test_floor_holds_in_human_review_default(tmp_path):
    # The non-negotiable floor still blocks even in propose_all=True:
    # a fix that introduces a new anti-pattern, or won't parse, is NOT applied.
    _write(tmp_path, "app/a.py", "def f(u):\n    return clean(u)\n")
    _write(tmp_path, "app/b.py", "def g(u):\n    return ok(u)\n")
    regress = _finding(
        affected_file="app/a.py", affected_lines="2",
        suggested_fix="```python\n    return eval(u)\n```",
    )
    broken = _finding(
        affected_file="app/b.py", affected_lines="2",
        suggested_fix="```python\n    def (:\n```",
    )
    res = safe_apply.classify_and_apply([regress, broken], root=str(tmp_path))
    assert res["applied"] == []
    assert any("introduces `eval(`" in m for m in res["manual"])
    assert any("syntax error after fix" in m for m in res["manual"])
    assert (tmp_path / "app/a.py").read_text() == "def f(u):\n    return clean(u)\n"


def test_introduced_forbidden_blocks_apply(tmp_path):
    _write(tmp_path, "app/run.py", "def go(c):\n    return parse(c)\n")
    fx = _finding(
        affected_file="app/run.py",
        affected_lines="2",
        suggested_fix="```python\n    return eval(c)\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert res["applied"] == []
    assert any("introduces `eval(`" in m for m in res["manual"])
    assert (tmp_path / "app/run.py").read_text() == "def go(c):\n    return parse(c)\n"


def test_security_weakening_fix_routed_to_manual_not_applied(tmp_path):
    original = "def fetch(u):\n    return requests.get(u, timeout=5)\n"
    _write(tmp_path, "app/net.py", original)
    fx = _finding(
        vulnerability_id="A05:2021",
        affected_file="app/net.py",
        affected_lines="2",
        description="misconfiguration",
        suggested_fix="```python\n    return requests.get(u, timeout=5, verify=False)\n```",
    )
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert res["applied"] == []
    assert any("verify=False" in m for m in res["manual"])
    assert (tmp_path / "app/net.py").read_text() == original  # untouched


def test_out_of_bounds_range_routed_to_manual(tmp_path):
    _write(tmp_path, "app/db.py", "x = 1\n")
    fx = _finding(affected_lines="50", suggested_fix="```python\nx = 2\n```")
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert res["applied"] == []
    assert any("out of bounds" in m for m in res["manual"])


def test_no_unrelated_file_is_ever_touched(tmp_path):
    _write(tmp_path, "app/db.py", "x = 1\n")
    _write(tmp_path, "app/other.py", "untouched = True\n")
    fx = _finding(affected_lines="1", suggested_fix="```python\nx = 2\n```")
    res = safe_apply.classify_and_apply([fx], root=str(tmp_path))
    assert res["changed_files"] == ["app/db.py"]
    assert (tmp_path / "app/other.py").read_text() == "untouched = True\n"


# --- re-scan regression check ----------------------------------------------


def _bf(file, vid, sev="High", conf="High", ver="verified"):
    return {
        "affected_file": file,
        "vulnerability_id": vid,
        "severity": sev,
        "confidence": conf,
        "verification_status": ver,
    }


def test_is_blocking_rules():
    assert safe_apply.is_blocking(_bf("a.py", "A03:2021")) is True
    assert safe_apply.is_blocking(_bf("a.py", "A03:2021", conf="Low")) is False
    assert safe_apply.is_blocking(_bf("a.py", "A03:2021", sev="Medium")) is False
    # Critical needs verification_status == verified (BR-009).
    assert safe_apply.is_blocking(_bf("a.py", "A01:2021", sev="Critical")) is True
    assert (
        safe_apply.is_blocking(
            _bf("a.py", "A01:2021", sev="Critical", ver="conflicting")
        )
        is False
    )


def test_regression_reasons():
    before = [_bf("a.py", "A03:2021"), _bf("b.py", "A05:2021")]
    # All resolved -> no regression.
    assert safe_apply.regression_reasons(before, []) == []
    # Same finding still blocking -> unresolved.
    r = safe_apply.regression_reasons(before, [_bf("a.py", "A03:2021")])
    assert any("unresolved" in x for x in r)
    # Brand-new blocking finding -> regression.
    r = safe_apply.regression_reasons([], [_bf("c.py", "A03:2021")])
    assert any("new blocking finding" in x for x in r)
    # Severity got worse.
    r = safe_apply.regression_reasons(
        [_bf("a.py", "A03:2021", sev="High")],
        [_bf("z.py", "A01:2021", sev="Critical")],
    )
    assert any("severity increased" in x for x in r)
    # Non-blocking (low-confidence) noise never counts as a regression.
    assert safe_apply.regression_reasons([], [_bf("n.py", "A03:2021", conf="Low")]) == []


def test_pr_body_human_review_framing():
    res = {
        "applied": ["app/db.py:2 (A03:2021)", "app/login.py:9 (A07:2021)"],
        "manual": ["x.py:1 (A07:2021) — no usable drop-in (see suggestion)"],
        "secret_files": ["config.py"],
        "explanations": [("app/db.py:2 (A03:2021)", "SQL injection via concatenation")],
        "risk_notes": {"app/login.py:9 (A07:2021)": "manual-review category (A07:2021)"},
    }
    body = safe_apply.build_pr_body(res, "http://run/1")
    # secrets stay instruction-only via 1Password
    assert "1Password" in body and "op://" in body and "ROTATE" in body
    # human-review-branch framing + never auto-merged (twice: top + footer)
    assert "review, then merge if you agree" in body
    assert "NEVER auto-merged" in body
    assert body.count("auto-merged") >= 2
    # applied section + risk label on the sensitive one
    assert "Suggested fixes on this branch (2)" in body
    assert "why: SQL injection" in body
    assert "⚠️ **sensitive (manual-review category (A07:2021))**" in body
    # manual section reframed
    assert "Couldn't be applied cleanly — apply manually (1)" in body


# --- D-14: security_findings/ append-only numbered audit trail -------------


def test_next_report_index(tmp_path):
    # No folder, then an empty folder → first report is 1.
    assert safe_apply.next_report_index(str(tmp_path)) == 1
    d = tmp_path / "security_findings"
    d.mkdir()
    assert safe_apply.next_report_index(str(tmp_path)) == 1
    # max(existing n) + 1, across BOTH the review and the report files.
    (d / "SECURITY-REVIEW.1.md").write_text("x", encoding="utf-8")
    (d / "security-scan-report.1.json").write_text("{}", encoding="utf-8")
    assert safe_apply.next_report_index(str(tmp_path)) == 2
    (d / "SECURITY-REVIEW.2.md").write_text("x", encoding="utf-8")
    assert safe_apply.next_report_index(str(tmp_path)) == 3
    # A gap is fine — the max wins (never reuse a number).
    (d / "security-scan-report.5.json").write_text("{}", encoding="utf-8")
    assert safe_apply.next_report_index(str(tmp_path)) == 6
    # Unnumbered / unrelated names are ignored.
    (d / "SECURITY-REVIEW.md").write_text("x", encoding="utf-8")
    (d / "notes.txt").write_text("x", encoding="utf-8")
    assert safe_apply.next_report_index(str(tmp_path)) == 6


def _report_json(tmp_path: pathlib.Path, findings: list[dict]) -> str:
    p = tmp_path / "scan.json"
    p.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(p)


_SECRET_FINDING = {
    "vulnerability_id": "SECRET-001",
    "affected_file": "config.py",
    "affected_lines": "1",
    "description": "hardcoded secret",
    "owasp_reference": "",
    "suggested_fix": "",
}


def test_main_writes_numbered_into_security_findings(tmp_path):
    report = _report_json(tmp_path, [dict(_SECRET_FINDING)])
    root = tmp_path / "repo"
    root.mkdir()
    out = tmp_path / "out"
    out.mkdir()

    assert safe_apply.main([report, str(out), str(root)]) == 0

    fd = root / "security_findings"
    assert (fd / "SECURITY-REVIEW.1.md").is_file()
    assert (fd / "security-scan-report.1.json").is_file()
    # The numbered report is a faithful copy of the raw scan JSON.
    assert json.loads((fd / "security-scan-report.1.json").read_text()) == json.loads(
        pathlib.Path(report).read_text()
    )
    # PR body still produced for the caller; root SECURITY-REVIEW.md is gone.
    assert (out / "pr_body.md").is_file()
    assert not (root / "SECURITY-REVIEW.md").exists()


def test_main_increments_and_preserves_history(tmp_path):
    report = _report_json(tmp_path, [dict(_SECRET_FINDING)])
    root = tmp_path / "repo"
    root.mkdir()
    out = tmp_path / "out"
    out.mkdir()

    assert safe_apply.main([report, str(out), str(root)]) == 0
    assert safe_apply.main([report, str(out), str(root)]) == 0

    fd = root / "security_findings"
    # Run 2 ADDS .2 and KEEPS .1 — append-only audit trail.
    assert (fd / "SECURITY-REVIEW.1.md").is_file()
    assert (fd / "SECURITY-REVIEW.2.md").is_file()
    assert (fd / "security-scan-report.1.json").is_file()
    assert (fd / "security-scan-report.2.json").is_file()
    assert safe_apply.next_report_index(str(root)) == 3
