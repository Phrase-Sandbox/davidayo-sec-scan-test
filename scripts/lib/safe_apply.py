"""Single source of truth for the opt-in auto-fix-PR splice + safety gauntlet.

Appendix D-8/D-9/D-10/D-11 (DEVIATION — pending Security/Legal sign-off).

Why this file exists
--------------------
The "apply the model's suggested fix to the real file, then open a PR" logic
used to be **duplicated** in two hand-synced heredocs
(``.github/workflows/security-scan-reusable.yml`` and
``scripts/open_fix_pr.sh``). That duplication already shipped one bug. This
module is now the ONLY copy: both callers run it. It mirrors the diff source
of truth ``src/security_scanner/shared/reports/patch.py`` (``_CODE_BLOCK_RE``,
``_LINE_RANGE_RE``, the ``lines[:s-1] + fix + lines[e:]`` splice).

It is intentionally **pure standard library** (no ``import security_scanner``):
the reusable workflow runs inside the *calling* repo's checkout where our
package is not installed, and so it can be unit-tested in isolation.

The gauntlet — every finding runs this in order; ANY failure routes the
finding to "Needs manual fix" with a precise reason. A file is never
corrupted and a finding is never silently dropped:

1. ``SECRET-001`` — never edited; recorded for the 1Password remove/rotate
   section (secrets are instruction-only, spec §14).
2. Manual-only category (auth / authz / crypto / deserialization /
   subprocess / session / permissions) — never auto-applied.
3. Protected path (auth/ security/ middleware/ jwt/ sessions/ config/
   deployment/ docker/ k8s/, plus settings/config files).
4. Code-block extract + line-range parse + SKETCH guard.
5. Protected variable (SECRET_KEY/JWT_SECRET/SESSION_COOKIE/CSRF/DEBUG/
   ALLOWED_HOSTS/CORS) anywhere in the replaced or replacement lines.
6. Regression blocker — reject if the replacement *introduces* a dangerous
   construct the replaced lines did not have (introduced-only, so we never
   punish pre-existing dev debt).
7. Diff-size cap — a single fix may not rewrite more than N lines.
8. Splice + deterministic ``ast.parse()`` rollback for ``.py`` (D-10).

The independent post-apply re-scan + bandit/ruff self-check lives in the
callers (it needs the scanner / external tools); this module reports which
files it changed so the caller can check exactly those.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import sys

CODE_BLOCK = re.compile(r"```(?:[A-Za-z0-9_+\-]*)?[\r\n]+(.*?)[\r\n]*```", re.DOTALL)
LINE_RANGE = re.compile(r"^\s*(\d+)\s*(?:[-–]\s*(\d+))?\s*$")

# "Be picky": refuse anything that reads as an illustrative SKETCH rather
# than an exact drop-in replacement.
SKETCH = re.compile(
    r"^\s*\.\.\.\s*$"
    r"|^\s*#\s*(in|add|then|todo|note|rest|replace|example|your)\b"
    r"|<[A-Z][A-Z0-9_]{1,}>"
    r"|\brest of (the )?(code|file|function)\b"
    r"|\btruncated for brevity\b",
    re.I | re.M,
)

# Manual-review-only vulnerability classes (Phase 6 #15). These are never
# auto-applied even when the model returns a clean drop-in: the blast radius
# of a wrong "fix" here is unacceptable.
#
# Classification is driven primarily by the OWASP id (a controlled value),
# NOT by loose substring matching of the free-text description — matching
# bare "session"/"jwt"/"crypto" in prose wrongly flagged an A03 SQL-injection
# fix because the code used `db.session.execute`. The keyword pass therefore
# requires unambiguous multi-token vuln-class PHRASES, never library/attribute
# tokens, so SQL-injection / missing-header fixes stay auto-eligible.
_MANUAL_ID_PREFIXES = (
    "A01:",  # Broken Access Control — authz / permissions
    "A02:",  # Cryptographic Failures — crypto
    "A07:",  # Identification & Authentication Failures — auth
    "A08:",  # Software & Data Integrity Failures — (de)serialization
)
_MANUAL_KEYWORDS = re.compile(
    r"(command injection|os command|remote code execution|"
    r"insecure deserialization|deserializ\w+|\bpickle\b|"
    r"session fixation|session management|broken authentication|"
    r"auth(?:entication|orization) bypass|privilege escalation|"
    r"access control|broken access)",
    re.I,
)

# Protected path segments / filenames (Phase 4 #10). Never auto-edit code that
# lives in these areas — a human reviews any change there.
_PROTECTED_SEGMENTS = frozenset(
    {
        "auth",
        "security",
        "middleware",
        "jwt",
        "jwts",
        "session",
        "sessions",
        "config",
        "configs",
        "deployment",
        "deploy",
        "docker",
        "k8s",
        "kubernetes",
    }
)
_PROTECTED_BASENAMES = re.compile(
    r"^(settings|config|conf|configuration)\.[A-Za-z0-9_]+$"
    r"|^dockerfile$"
    r"|^docker-compose[.\w-]*\.ya?ml$",
    re.I,
)

# Protected variables (Phase 4 #11). If the replaced OR replacement lines so
# much as mention one of these, only suggest — never auto-modify.
_PROTECTED_VARS = re.compile(
    r"\b(SECRET_KEY|JWT_SECRET\w*|SESSION_COOKIE\w*|CSRF\w*|DEBUG|"
    r"ALLOWED_HOSTS|CORS\w*)\b"
)

# Regression blocker (Phase 1 #2, expanded v1.8): security anti-patterns that
# must never be *introduced* by a fix. Each rule is
#   (label, danger_regex, safe_regex_or_None)
# and is evaluated INTRODUCED-ONLY and MITIGATION-AWARE by
# introduced_forbidden(): flagged iff the replacement is "bad" (danger present
# AND the in-block safe form absent) while the replaced lines were not already
# "bad" — so pre-existing developer debt is never punished (that is the
# post-apply re-scan/bandit's job) and an in-block mitigation
# (`Loader=`, `usedforsecurity=False`) is honoured.
#
# Scope decision (v1.8): every entry here is an UNAMBIGUOUS weakening — no
# legitimate security *fix* introduces one. Patterns that are routinely
# legitimate in normal code (`0.0.0.0` bind, bare `random.*`, broad XML) are
# DELIBERATELY NOT here — they would cause noisy false "manual" routings; the
# post-apply bandit self-check (S104/S311/S314…) is their backstop. ruff-"S"
# / bandit also re-cover eval/pickle/ssl post-apply: intentional defense in
# depth (this gate is the deterministic *pre-splice* line).
_FORBIDDEN_RULES: list[tuple[str, re.Pattern[str], re.Pattern[str] | None]] = [
    # --- TLS / certificate verification disabled ---------------------------
    ("verify=False (TLS verification off)", re.compile(r"\bverify\s*=\s*False\b", re.I), None),
    (
        "ssl/verify_ssl=False (TLS off)",
        re.compile(r"\b(?:ssl|use_ssl|ssl_verify|verify_ssl|sslverify)\s*=\s*False\b", re.I),
        None,
    ),
    ("check_hostname=False", re.compile(r"\bcheck_hostname\s*=\s*False\b", re.I), None),
    ("ssl.CERT_NONE", re.compile(r"\bCERT_NONE\b"), None),
    ("ssl._create_unverified_context", re.compile(r"_create_unverified_context"), None),
    (
        "rejectUnauthorized:false (node TLS off)",
        re.compile(r"rejectUnauthorized\s*[:=]\s*false", re.I),
        None,
    ),
    (
        "NODE_TLS_REJECT_UNAUTHORIZED=0",
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", re.I),
        None,
    ),
    ("--insecure flag", re.compile(r"--insecure\b"), None),
    # --- CORS wildcard -----------------------------------------------------
    (
        'allow_origins=["*"] (CORS wildcard)',
        re.compile(r"allow_origins\s*=\s*[\[(]\s*['\"]\*['\"]", re.I),
        None,
    ),
    (
        "Access-Control-Allow-Origin: * (CORS wildcard)",
        re.compile(r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]?\*", re.I),
        None,
    ),
    (
        "CORS_ORIGIN_ALLOW_ALL=True",
        re.compile(r"\bCORS_ORIGIN_ALLOW_ALL\s*=\s*True\b", re.I),
        None,
    ),
    # --- Authentication / CSRF / secure-cookie disabled --------------------
    ("auth_disabled=True", re.compile(r"\bauth_disabled\s*=\s*True\b", re.I), None),
    (
        "authentication/login disabled",
        re.compile(r"\b(?:authentication(?:_required)?|login_required)\s*=\s*False\b", re.I),
        None,
    ),
    ("csrf_exempt", re.compile(r"\bcsrf_exempt\b|@?\s*csrf\.exempt", re.I), None),
    ("WTF_CSRF_ENABLED=False", re.compile(r"\bWTF_CSRF_ENABLED\s*=\s*False\b", re.I), None),
    (
        "SESSION_COOKIE_SECURE=False",
        re.compile(r"\bSESSION_COOKIE_SECURE\s*=\s*False\b", re.I),
        None,
    ),
    ("CSRF_COOKIE_SECURE=False", re.compile(r"\bCSRF_COOKIE_SECURE\s*=\s*False\b", re.I), None),
    (
        "SESSION_COOKIE_HTTPONLY=False",
        re.compile(r"\bSESSION_COOKIE_HTTPONLY\s*=\s*False\b", re.I),
        None,
    ),
    ("SECURE_SSL_REDIRECT=False", re.compile(r"\bSECURE_SSL_REDIRECT\s*=\s*False\b", re.I), None),
    (
        "DRF permission_classes=[AllowAny]",
        re.compile(r"permission_classes\s*=\s*\[\s*AllowAny", re.I),
        None,
    ),
    (
        "DRF authentication_classes=[] (auth removed)",
        re.compile(r"authentication_classes\s*=\s*\[\s*\]", re.I),
        None,
    ),
    # --- JWT misconfiguration ---------------------------------------------
    (
        'JWT alg "none"',
        re.compile(r"\balg(?:orithm)?['\"]?\s*[:=]\s*['\"]?\s*none\b", re.I),
        None,
    ),
    ("JWT algorithms=[] (any alg accepted)", re.compile(r"\balgorithms\s*=\s*\[\s*\]", re.I), None),
    (
        "verify_signature=False",
        re.compile(r"['\"]?\bverify_signature\b['\"]?\s*[:=]\s*False\b", re.I),
        None,
    ),
    # --- Dangerous execution / deserialization ----------------------------
    ("eval(", re.compile(r"\beval\s*\("), None),
    ("exec(", re.compile(r"\bexec\s*\("), None),
    ("shell=True", re.compile(r"\bshell\s*=\s*True\b", re.I), None),
    ("os.system(", re.compile(r"\bos\.system\s*\("), None),
    ("pickle.load(s)(", re.compile(r"\b(?:cPickle|_pickle|pickle)\s*\.\s*loads?\s*\("), None),
    ("marshal.load(s)(", re.compile(r"\bmarshal\s*\.\s*loads?\s*\("), None),
    ("yaml.unsafe_load(", re.compile(r"\byaml\s*\.\s*unsafe_load\s*\("), None),
    (
        "yaml.load( without Loader=",
        re.compile(r"\byaml\s*\.\s*load\s*\("),
        re.compile(r"Loader\s*=|safe_load"),
    ),
    ("__import__(", re.compile(r"\b__import__\s*\("), None),
    ("dill.load(s)(", re.compile(r"\bdill\s*\.\s*loads?\s*\("), None),
    ("jsonpickle.decode(", re.compile(r"\bjsonpickle\s*\.\s*decode\b"), None),
    ("pandas.read_pickle(", re.compile(r"\b(?:pd|pandas)\s*\.\s*read_pickle\s*\("), None),
    ("torch.load( (pickle)", re.compile(r"\btorch\s*\.\s*load\s*\("), None),
    ("joblib.load(", re.compile(r"\bjoblib\s*\.\s*load\s*\("), None),
    # --- Weak crypto / TLS protocol ---------------------------------------
    (
        "hashlib.md5/sha1 (weak hash)",
        re.compile(r"\bhashlib\s*\.\s*(?:md5|sha1)\s*\("),
        re.compile(r"usedforsecurity\s*=\s*False"),
    ),
    (
        'hashlib.new("md5"/"sha1")',
        re.compile(r"\bhashlib\s*\.\s*new\s*\(\s*['\"](?:md5|sha1)['\"]", re.I),
        re.compile(r"usedforsecurity\s*=\s*False"),
    ),
    (
        "weak cipher (ECB/ARC4/DES/Blowfish)",
        re.compile(r"\b(?:MODE_ECB|ARC4|DES\.new|Blowfish)\b"),
        None,
    ),
    (
        "obsolete TLS protocol",
        re.compile(r"\bssl\s*\.\s*PROTOCOL_(?:SSLv2|SSLv3|TLSv1)(?:_1)?\b"),
        None,
    ),
    # --- Debug / info exposure --------------------------------------------
    ("debug=True", re.compile(r"\bdebug\s*=\s*True\b", re.I), None),
    ("FLASK_DEBUG=1", re.compile(r"\bFLASK_DEBUG\s*=\s*['\"]?1\b", re.I), None),
    (
        'SECRET_KEY = "random"/"test"',
        re.compile(r"""SECRET_KEY\s*=\s*['"](?:random|test)['"]""", re.I),
        None,
    ),
    # --- Filesystem / archive ---------------------------------------------
    ("chmod 0777", re.compile(r"chmod[^\n]*\b0o?777\b"), None),
    ("os.umask(0)", re.compile(r"\bos\s*\.\s*umask\s*\(\s*0\s*\)"), None),
    ("tempfile.mktemp(", re.compile(r"\btempfile\s*\.\s*mktemp\s*\("), None),
    ("archive .extractall( (path traversal)", re.compile(r"\.extractall\s*\("), None),
]

_DEFAULT_MAX_CHANGED = int(os.environ.get("FIX_MAX_CHANGED_LINES") or 20)

# Every scanned repo keeps an append-only audit trail of scans here, on the
# persistent security branch (D-14). Reports are numbered, never overwritten:
# SECURITY-REVIEW.<n>.md + security-scan-report.<n>.json, n incrementing.
_FINDINGS_DIR = "security_findings"
_REVIEW_INDEX_RE = re.compile(
    r"^(?:SECURITY-REVIEW|security-scan-report)\.(\d+)\.(?:md|json)$"
)


def extract_code_block(text: str | None) -> str | None:
    """Return the first fenced code block's body, or None."""
    if not text:
        return None
    m = CODE_BLOCK.search(text)
    return m.group(1) if m else None


def is_sketch(code: str | None) -> bool:
    """True if the block is missing or reads as an illustrative sketch."""
    return True if not code else bool(SKETCH.search(code))


def parse_line_range(value: object) -> tuple[int, int] | None:
    """Parse "42" / "42-55" / "42–55" → (start, end); else None."""
    if not isinstance(value, str):
        return None
    m = LINE_RANGE.match(value)
    if not m:
        return None
    s = int(m.group(1))
    e = int(m.group(2)) if m.group(2) else s
    return (s, e)


def is_manual_only_category(vid: str, owasp: str, description: str) -> str | None:
    """Return the manual-review category label, or None if auto-eligible."""
    if any(vid.startswith(p) for p in _MANUAL_ID_PREFIXES):
        return f"manual-review category ({vid})"
    hay = f"{vid}\n{owasp}\n{description}"
    m = _MANUAL_KEYWORDS.search(hay)
    return f"manual-review category ({m.group(1).lower()})" if m else None


def is_protected_path(path: str) -> bool:
    """True if the file lives in a protected area or is a settings/config file."""
    norm = path.replace("\\", "/").lower()
    parts = [p for p in norm.split("/") if p]
    if any(seg in _PROTECTED_SEGMENTS for seg in parts[:-1]):
        return True
    base = parts[-1] if parts else norm
    return bool(_PROTECTED_BASENAMES.match(base))


def touches_protected_variable(old_text: str, new_text: str) -> str | None:
    """Return the protected variable name if either side references one."""
    m = _PROTECTED_VARS.search(old_text) or _PROTECTED_VARS.search(new_text)
    return m.group(1) if m else None


def _is_bad(text: str, danger: re.Pattern[str], safe: re.Pattern[str] | None) -> bool:
    """A construct is 'bad' iff the danger is present and any in-line/in-block
    mitigation (e.g. ``Loader=``, ``usedforsecurity=False``) is absent."""
    if not danger.search(text):
        return False
    return not (safe is not None and safe.search(text))


def introduced_forbidden(old_text: str, new_text: str) -> str | None:
    """Return a label if the replacement *introduces* a security anti-pattern.

    Introduced-only + mitigation-aware: flagged iff the replacement is bad
    while the lines it replaces were not already bad. A pattern that was
    already there (pre-existing developer debt) is not this fix's regression
    — that is the post-apply re-scan / bandit's job, not this pre-splice gate.
    """
    for label, danger, safe in _FORBIDDEN_RULES:
        if _is_bad(new_text, danger, safe) and not _is_bad(old_text, danger, safe):
            return label
    return None


def changed_line_count(start: int, end: int, new_block: str) -> int:
    """Worst-case lines touched by this single fix."""
    replaced = end - start + 1
    added = len(new_block.splitlines()) or 1
    return max(replaced, added)


# --- post-apply re-scan regression check (#4, and #13 realized) ------------
#
# Mirrors src/security_scanner/shared/severity/mapping.py::should_block so the
# "did the patch actually help, and not make things worse?" gate uses the
# exact same blocking rule the live gate uses. An independent re-scan of the
# patched code that re-applies should_block IS the second-pass review (#13),
# realized deterministically instead of as a free-text model verdict.

_SEV_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def is_blocking(f: dict) -> bool:
    """BR-001 + BR-001-A + BR-009 on a plain finding dict."""
    if f.get("severity") not in ("Critical", "High"):
        return False
    if f.get("confidence") != "High":
        return False
    if f.get("severity") == "Critical":
        return f.get("verification_status") == "verified"
    return True


def _key(f: dict) -> tuple[str, str]:
    return (f.get("affected_file", "") or "", f.get("vulnerability_id", "") or "")


def regression_reasons(before: list[dict], after: list[dict]) -> list[str]:
    """Reasons the patched code must NOT be opened as a PR.

    Fail the patch if any finding that was blocking before is still blocking
    in the same file, if a brand-new blocking finding appeared, or if the
    worst blocking severity got worse.
    """
    reasons: list[str] = []
    before_block = [f for f in before if is_blocking(f)]
    after_block = [f for f in after if is_blocking(f)]
    before_keys = {_key(f) for f in before_block}
    after_keys = {_key(f) for f in after_block}

    for k in sorted(before_keys & after_keys):
        reasons.append(f"unresolved: {k[0]} {k[1]} still blocking after the fix")
    for k in sorted(after_keys - before_keys):
        reasons.append(f"new blocking finding introduced: {k[0]} {k[1]}")

    def worst(fs: list[dict]) -> int:
        return max((_SEV_RANK.get(f.get("severity", ""), 0) for f in fs), default=0)

    if after_block and worst(after_block) > worst(before_block):
        reasons.append("max blocking severity increased after the fix")
    return reasons


def _block_with_newline(code: str) -> str:
    return code if code.endswith("\n") else code + "\n"


def classify_and_apply(
    findings: list[dict],
    root: str = ".",
    max_changed: int = _DEFAULT_MAX_CHANGED,
    propose_all: bool = True,
) -> dict:
    """Run the gauntlet and apply surviving edits to files under *root*.

    Two postures:

    - ``propose_all=True`` (default — the human-review-branch model, D-13):
      sensitive-category / protected-path / protected-variable findings are
      NOT suppressed — their suggested fix is applied to the branch and an
      advisory ``risk_note`` is attached so the PR can flag it "review
      carefully". The developer reviews and merges; nothing is auto-merged.
    - ``propose_all=False`` (the strict D-11 posture): those gates hard-route
      to "manual" and are never written. Kept for callers that want it.

    The safety FLOOR holds in both: a fix that can't be expressed as a clean
    drop-in (no code / sketch / bad range / oversized), introduces a NEW
    anti-pattern (regression blocker), or breaks ``ast.parse`` is never
    written — it is listed under "manual" with its reason. Secrets are never
    rewritten as code (instruction-only).

    Returns ``applied`` / ``manual`` / ``secret_files`` / ``changed_files`` /
    ``explanations`` and ``risk_notes`` ({"loc (vid)": "why it's sensitive"}).
    """
    secret_files: list[str] = []
    manual: list[str] = []
    applied: list[str] = []
    explanations: list[tuple[str, str]] = []  # (loc+vid, description)
    risk_notes: dict[str, str] = {}
    # (start, end, code, vid, loc, risk_note|None)
    edits: dict[str, list[tuple[int, int, str, str, str, str | None]]] = {}

    for f in findings:
        vid = f.get("vulnerability_id", "") or ""
        path = f.get("affected_file", "") or ""
        owasp = f.get("owasp_reference", "") or ""
        desc = f.get("description", "") or ""
        loc = f"{path}:{f.get('affected_lines')}"

        # 1. Secrets — never rewritten as code (instruction-only).
        if vid == "SECRET-001":
            if path and path not in secret_files:
                secret_files.append(path)
            continue

        # 2/3. Sensitive class / protected path. Strict posture hard-routes
        # to manual; the human-review model keeps the fix but flags it.
        risk_bits: list[str] = []
        cat = is_manual_only_category(vid, owasp, desc)
        if cat:
            if not propose_all:
                manual.append(f"{loc} ({vid}) — {cat}, suggest only")
                continue
            risk_bits.append(cat)
        if path and is_protected_path(path):
            if not propose_all:
                manual.append(f"{loc} ({vid}) — protected path, not auto-edited")
                continue
            risk_bits.append("protected path")

        # 4. Block + range + sketch — genuinely not applicable → manual
        # (FLOOR, both postures).
        rng = parse_line_range(f.get("affected_lines"))
        code = extract_code_block(f.get("suggested_fix", ""))
        abspath = os.path.join(root, path) if path else ""
        if not path or rng is None or code is None or not os.path.isfile(abspath):
            manual.append(f"{loc} ({vid}) — no usable drop-in (see suggestion)")
            continue
        if is_sketch(code):
            manual.append(f"{loc} ({vid}) — sketch, not auto-applied")
            continue

        # 7. Diff-size cap — keep the diff reviewable (FLOOR).
        n_changed = changed_line_count(rng[0], rng[1], code)
        if n_changed > max_changed:
            manual.append(
                f"{loc} ({vid}) — fix too large "
                f"({n_changed} lines > {max_changed}), manual review"
            )
            continue

        risk = "; ".join(risk_bits) or None
        edits.setdefault(abspath, []).append((rng[0], rng[1], code, vid, loc, risk))
        explanations.append((f"{loc} ({vid})", desc))

    changed_files: list[str] = []
    for abspath, lst in edits.items():
        rel = os.path.relpath(abspath, root)
        with open(abspath, encoding="utf-8", errors="surrogateescape") as fh:
            lines = fh.read().splitlines(keepends=True)
        n = len(lines)
        ok = [(s, e, c, v, lo, rk) for (s, e, c, v, lo, rk) in lst if 1 <= s <= e <= n]
        for (s, e, _c, v, lo, _rk) in lst:
            if not (1 <= s <= e <= n):
                manual.append(f"{lo} ({v}) — line range out of bounds")
        is_py = abspath.endswith(".py")
        changed = False
        # Bottom-to-top so earlier line numbers stay valid as we splice.
        for (s, e, c, v, lo, rk) in sorted(ok, key=lambda t: t[0], reverse=True):
            old_seg = "".join(lines[s - 1 : e])
            note = rk
            # 5. Protected variable. Strict: hard-route. Human-review: keep
            # the fix but flag it (the dev sees & decides).
            pv = touches_protected_variable(old_seg, c)
            if pv:
                if not propose_all:
                    manual.append(
                        f"{lo} ({v}) — touches protected variable {pv}, suggest only"
                    )
                    continue
                note = "; ".join(x for x in (note, f"touches {pv}") if x)
            # 6. Regression blocker (introduced-only) — FLOOR, both postures.
            bad = introduced_forbidden(old_seg, c)
            if bad:
                manual.append(f"{lo} ({v}) — fix introduces `{bad}`, not auto-applied")
                continue
            prev = lines
            blk = _block_with_newline(c)
            lines = lines[: s - 1] + blk.splitlines(keepends=True) + lines[e:]
            # 8. Deterministic parse gate for Python — FLOOR, both postures.
            if is_py:
                try:
                    ast.parse("".join(lines))
                except SyntaxError:
                    lines = prev
                    manual.append(f"{lo} ({v}) — syntax error after fix, not auto-applied")
                    continue
            applied.append(f"{lo} ({v})")
            if note:
                risk_notes[f"{lo} ({v})"] = note
            changed = True
        if changed:
            with open(abspath, "w", encoding="utf-8", errors="surrogateescape") as fh:
                fh.write("".join(lines))
            changed_files.append(rel)

    applied_set = set(applied)
    kept_expl = [(k, d) for (k, d) in explanations if k in applied_set]
    return {
        "applied": applied,
        "manual": manual,
        "secret_files": secret_files,
        "changed_files": sorted(changed_files),
        "explanations": kept_expl,
        "risk_notes": risk_notes,
    }


def _short(text: str, limit: int = 280) -> str:
    """One-line, fence-free, length-capped summary for the PR body."""
    flat = " ".join(text.replace("`", "").split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def build_pr_body(result: dict, run_url: str) -> str:
    """Render the PR body for the human-review-branch model (D-13).

    These are AI-generated *suggestions* applied to this branch for a human
    to review and merge if they agree. Never auto-merged. Sensitive ones are
    flagged. Secrets get a 1Password remove/rotate section (never rewritten).
    """
    applied = result["applied"]
    manual = result["manual"]
    secret_files = result["secret_files"]
    expl = dict(result.get("explanations", []))
    risk = dict(result.get("risk_notes", {}))

    def sec(title: str, items: list[str]) -> str:
        if not items:
            return ""
        return "\n### " + title + "\n" + "\n".join(f"- `{i}`" for i in items) + "\n"

    p: list[str] = [
        "## Suggested security fixes — review, then merge if you agree\n",
        f"The security gate **blocked** [this scan]({run_url}). This branch "
        "carries **AI-generated suggested fixes** for the findings, so you "
        "can review a concrete diff and decide. They are a starting point, "
        "not a guarantee — **review every line**.\n",
        "\n> 🔒 **This PR is NEVER auto-merged.** Merging it is *your* "
        "explicit acceptance of these changes; the merge commit re-runs the "
        "security gate (and your own CI/tests).\n",
    ]
    if applied:
        p.append(f"\n### ✅ Suggested fixes on this branch ({len(applied)})\n")
        for a in applied:
            p.append(f"- `{a}`\n")
            why = expl.get(a)
            if why:
                p.append(f"  - why: {_short(why)}\n")
            rn = risk.get(a)
            if rn:
                p.append(
                    f"  - ⚠️ **sensitive ({rn})** — review this one extra "
                    "carefully before accepting.\n"
                )
            else:
                p.append("  - intentionally minimal; verify behaviour before merge.\n")
    if secret_files:
        p.append("\n### \U0001f511 Hardcoded secrets — remove & ROTATE (NOT auto-edited)\n")
        p.append(
            "These files contain hardcoded credentials. This PR does **not** "
            "change them — a wrong automated edit to a credential can break "
            "startup and the secret stays in git history anyway. For each:\n"
        )
        p.append(
            "\n1. Delete the hardcoded literal from source.\n"
            "2. Read it at runtime from **1Password** — e.g. an "
            "`op://<vault>/<item>/<field>` secret reference resolved by the "
            "1Password CLI / a 1Password Connect or Service-Account token — "
            "never from committed source.\n"
            "3. **Rotate** the exposed credential now (assume it is "
            "compromised the moment it was committed).\n"
        )
        for sf in secret_files:
            p.append(f"- `{sf}`\n")
    p.append(
        sec(
            f"\U0001f4dd Couldn't be applied cleanly — apply manually ({len(manual)})",
            manual,
        )
    )
    if manual:
        p.append(
            "\n_These had no safe drop-in (no/sketchy code, bad line range, "
            "too large, would introduce a new issue, or wouldn't compile). "
            "The full suggested fix for each is in this run's numbered "
            "`security_findings/SECURITY-REVIEW.<n>.md` on this branch (and "
            "the `security-scan-report` artifact)._\n"
        )
    p.append(
        "\n---\n> ⚠️ **Review every change. This PR is never auto-merged.** "
        "Merging is *your* decision to accept these AI suggestions; the merge "
        "commit re-runs the security gate and your own CI/tests.\n"
    )
    return "".join(p)


def next_report_index(root: str) -> int:
    """Next 1-based report number for ``<root>/security_findings/``.

    The security branch persists and accumulates a numbered history; each run
    appends ``SECURITY-REVIEW.<n>.md`` / ``security-scan-report.<n>.json``
    without overwriting prior ones. Returns ``max(existing n) + 1`` (1 when
    the folder is absent or empty). The caller restores the prior branch's
    ``security_findings/`` into the tree before calling so the count is
    cumulative across CI runs (D-14).
    """
    d = os.path.join(root, _FINDINGS_DIR)
    if not os.path.isdir(d):
        return 1
    highest = 0
    for name in os.listdir(d):
        m = _REVIEW_INDEX_RE.match(name)
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


def _load_findings(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh).get("findings", [])


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # Re-scan regression mode: safe_apply.py --regression BEFORE.json AFTER.json
    # Exit 0 = no regression (safe to open the PR); exit 3 = regression.
    if args and args[0] == "--regression":
        if len(args) < 3:
            print("usage: safe_apply.py --regression <before.json> <after.json>", file=sys.stderr)
            return 2
        reasons = regression_reasons(_load_findings(args[1]), _load_findings(args[2]))
        if reasons:
            print("REGRESSION")
            for r in reasons:
                print(f"  - {r}")
            return 3
        print("NO_REGRESSION")
        return 0

    if len(args) < 2:
        print("usage: safe_apply.py <report.json> <out_dir> [root]", file=sys.stderr)
        return 2
    report, out = args[0], args[1]
    root = args[2] if len(args) > 2 else "."
    run_url = os.environ.get("RUN_URL", "")

    result = classify_and_apply(_load_findings(report), root=root)
    body = build_pr_body(result, run_url)
    with open(os.path.join(out, "pr_body.md"), "w", encoding="utf-8") as fh:
        fh.write(body)

    # D-14: every scanned repo keeps an append-only audit trail under
    # security_findings/ on the persistent branch. The caller has already
    # restored the prior branch's folder into the tree, so the index is
    # cumulative; we add a NEW numbered review doc + a numbered copy of the
    # raw scan report and never overwrite earlier ones. The committed review
    # doc also guarantees the branch is non-empty/reviewable when 0 edits
    # were applied (D-13).
    findings_dir = os.path.join(root, _FINDINGS_DIR)
    os.makedirs(findings_dir, exist_ok=True)
    idx = next_report_index(root)
    review_rel = f"{_FINDINGS_DIR}/SECURITY-REVIEW.{idx}.md"
    report_rel = f"{_FINDINGS_DIR}/security-scan-report.{idx}.json"
    with open(os.path.join(root, review_rel), "w", encoding="utf-8") as fh:
        fh.write(body)
    try:
        shutil.copyfile(report, os.path.join(root, report_rel))
    except OSError:
        # The raw report copy is best-effort — never block the review doc.
        report_rel = ""

    print(f"REVIEW_FILE {review_rel}")
    if report_rel:
        print(f"REPORT_FILE {report_rel}")
    print(f"APPLIED {len(result['applied'])}")
    print(f"MANUAL {len(result['manual'])}")
    print(f"SECRETS {len(result['secret_files'])}")
    print(
        f"  applied={len(result['applied'])} manual={len(result['manual'])} "
        f"secret_files={len(result['secret_files'])}",
        file=sys.stderr,
    )
    # Machine-readable trailer: the files the caller must re-scan / lint.
    print("__CHANGED_FILES__")
    for cf in result["changed_files"]:
        print(cf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
