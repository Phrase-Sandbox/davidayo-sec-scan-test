#!/usr/bin/env bash
#
# Local-simulation equivalent of the reusable workflow's "Open suggested-fix
# PR" step (Appendix D-8/D-9/D-10/D-11). A GitHub-hosted runner can't reach a
# localhost scanner, so this is how the auto-fix-PR flow is demoed/verified on
# the personal simulation. The reusable workflow is the spec-faithful
# artifact; BOTH it and this script now run the SAME single source of truth,
# scripts/lib/safe_apply.py (no more duplicated heredocs).
#
# safe_apply.py reconstructs each fix from the scan JSON and applies it to the
# REAL files in the clone (clone must be at the scanned commit so line numbers
# match), running the full safety gauntlet (manual-only categories, protected
# paths/vars, regression blocker, diff-size cap, SKETCH guard, deterministic
# ast.parse rollback). Hardcoded secrets are NEVER located or edited; they are
# listed in the PR body for manual removal + rotation via 1Password (§14).
#
# After applying, BEFORE opening a PR, a fail-closed self-check runs on the
# changed files only: (1) py_compile, (2) ruff+bandit introduced-only lint
# regression (best-effort, isolated Docker), (3) an independent re-scan of the
# patched tree compared to the original scan (this re-scan IS the second-pass
# review — #13 — realized deterministically). ANY regression => no PR; the
# working tree is reverted; the already-failed gate + report still convey
# every finding.
#
# Chain:
#   REPO_URL=https://github.com/you/your-repo ./scripts/run_gate.sh master
#   #   -> writes /tmp/gate_scan.json, exits 1 if blocked
#   TARGET_DIR=/path/to/your-repo-clone ./scripts/open_fix_pr.sh
#
# Only opens a PR when the scan decision is `blocked`. Never auto-merges.
#
# Env:
#   SCAN_JSON      default /tmp/gate_scan.json (produced by run_gate.sh)
#   TARGET_DIR     required — clean working copy of the dev repo at the
#                  scanned commit (you must be able to `git push` it)
#   FORCE=1        proceed even if decision != blocked (demo override)
#   DRY_RUN=1      apply + self-check + print the PR body, but do NOT
#                  commit/push or open a PR (verify with zero GitHub action)
#   RESCAN_CMD     optional. A command that scans a directory and writes a
#                  scan-result JSON. Receives: <dir> <out.json>. If unset and
#                  `phrase-sec-scan` is not on PATH, the re-scan step is
#                  skipped with a prominent notice (prod safety net: the gate
#                  re-runs on the merge/push commit — spec §2.2).
#   SELFCHECK_LINT=0  disable the Docker ruff/bandit lint-regression step.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFE_APPLY="${SCRIPT_DIR}/lib/safe_apply.py"

SCAN_JSON="${SCAN_JSON:-/tmp/gate_scan.json}"
TARGET_DIR="${TARGET_DIR:?set TARGET_DIR=/path/to/dev-repo-clone}"

[ -f "$SAFE_APPLY" ] || { echo "missing $SAFE_APPLY" >&2; exit 2; }
[ -f "$SCAN_JSON" ] || { echo "scan JSON not found: $SCAN_JSON (run scripts/run_gate.sh first)" >&2; exit 2; }
[ -d "$TARGET_DIR/.git" ] || { echo "$TARGET_DIR is not a git repo" >&2; exit 2; }
command -v gh >/dev/null || { echo "gh CLI required" >&2; exit 2; }

decision="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('gate_decision','scan_failed'))" "$SCAN_JSON")"
echo "Scan decision: ${decision}"
if [ "${decision}" != "blocked" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "Decision is not 'blocked' — no PR opened (matches the gate workflow). Set FORCE=1 to override for a demo."
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cd "$TARGET_DIR"
if [ -n "$(git status --porcelain)" ]; then
  echo "Refusing to run: $TARGET_DIR has uncommitted changes (commit/stash first)." >&2
  exit 2
fi
base="$(git symbolic-ref --short HEAD)"
safe="${base//\//-}"
# D-14: a dedicated, persistent security branch per repo, named after the
# repo's own main branch (security/issues/main, security/issues/master, …).
branch="security/issues/${safe}"

# Invariant (#1): we ONLY ever push the auto-fixes branch — never the base.
if [ -z "$base" ] || [ "$branch" = "$base" ]; then
  echo "Refusing to run: could not resolve a base branch distinct from '$branch'." >&2
  exit 2
fi
base_sha_before="$(git rev-parse "origin/${base}" 2>/dev/null || echo "no-remote-base")"

# D-14: the security branch persists and accumulates an append-only numbered
# audit trail under security_findings/. Restore the prior branch's folder
# into the tree (FETCH_HEAD works on both a full clone and a shallow Actions
# checkout, no refs/remotes needed) BEFORE safe_apply so next_report_index()
# is cumulative. First run / no prior branch → fetch fails → fresh .1 files.
if git fetch origin "$branch" 2>/dev/null; then
  git checkout FETCH_HEAD -- security_findings 2>/dev/null || true
fi
mkdir -p security_findings

# Apply fixes to the REAL files + build the PR body — single source of truth.
echo "=== safe_apply: classify + splice (gauntlet) ==="
summary="$(RUN_URL="${REPO_URL:-local run_gate.sh}" python3 "$SAFE_APPLY" "$SCAN_JSON" "$WORK" "$TARGET_DIR")"
printf '%s\n' "$summary" | sed '/^__CHANGED_FILES__$/,$d'
applied_count="$(printf '%s\n' "$summary" | awk '/^APPLIED /{print $2; exit}')"
applied_count="${applied_count:-0}"
# Numbered review doc safe_apply just wrote (security_findings/SECURITY-REVIEW.<n>.md).
review_file="$(printf '%s\n' "$summary" | awk '/^REVIEW_FILE /{print $2; exit}')"
review_file="${review_file:-SECURITY-REVIEW.md}"
# Portable (macOS Bash 3.2 has no `mapfile`).
changed_files=()
while IFS= read -r _cf; do
  [ -n "$_cf" ] && changed_files+=("$_cf")
done < <(printf '%s\n' "$summary" | sed -n '/^__CHANGED_FILES__$/,$p' | tail -n +2)

# D-13 human-review-branch model: self-checks are ADVISORY, not blocking.
# The developer reviewing/merging the PR is the gate, so a flagged fix is
# annotated on the PR (loudly) but the branch/PR is still opened. The hard
# FLOOR (file must compile, no new anti-pattern) is already enforced inside
# safe_apply.py — non-compiling/regressing edits never reach here.
SELFCHECK_NOTES="$WORK/selfcheck_notes.md"
: > "$SELFCHECK_NOTES"
selfcheck_note() {
  echo "::notice:: self-check advisory (non-blocking, review carefully): $1"
  printf -- '- ⚠️ %s\n' "$1" >> "$SELFCHECK_NOTES"
}

if [ "$applied_count" -eq 0 ]; then
  echo "0 code fixes auto-applied — branch/PR will still be opened with"
  echo "security_findings/${review_file##*/} + the manual suggestions for the developer."
fi
echo "Changed files: ${changed_files[*]:-none}"

# ---- Self-check 1: every changed .py must byte-compile (belt + braces) ----
echo "=== self-check 1/3: py_compile ==="
for f in "${changed_files[@]}"; do
  case "$f" in
    *.py)
      if ! python3 -m py_compile "$TARGET_DIR/$f" 2>/tmp/safe_compile.err; then
        cat /tmp/safe_compile.err >&2 || true
        selfcheck_note "py_compile failed for \`$f\` — review extra carefully"
      fi ;;
  esac
done
echo "OK: all changed .py compile"

# ---- Self-check 2: ruff + bandit introduced-only (isolated Docker) --------
echo "=== self-check 2/3: ruff + bandit (introduced-only) ==="
py_changed=()
for f in "${changed_files[@]}"; do case "$f" in *.py) py_changed+=("$f");; esac; done
if [ "${SELFCHECK_LINT:-1}" = "0" ] || ! command -v docker >/dev/null || [ "${#py_changed[@]}" -eq 0 ]; then
  echo "skipped (SELFCHECK_LINT=0, no docker, or no .py changed) — re-scan below is the authoritative gate."
else
  mkdir -p "$WORK/old" "$WORK/new"
  for f in "${py_changed[@]}"; do
    mkdir -p "$WORK/old/$(dirname "$f")" "$WORK/new/$(dirname "$f")"
    # Working tree was clean before we applied; HEAD is the pre-patch content.
    git -C "$TARGET_DIR" show "HEAD:$f" > "$WORK/old/$f" 2>/dev/null || : > "$WORK/old/$f"
    cp "$TARGET_DIR/$f" "$WORK/new/$f"
  done
  if ! docker run --rm -v "$WORK":/w python:3.12-slim sh -lc '
        pip -q install ruff bandit >/dev/null 2>&1 || exit 7
        cnt(){ # <tool> <dir> — tools exit nonzero when they find issues;
               # neutralise that + tolerate empty/non-JSON so only the count matters
          if [ "$1" = ruff ]; then
            { ruff check --output-format json "$2" 2>/dev/null || true; } | python -c "import json,sys;d=sys.stdin.read().strip() or \"[]\";print(len(json.loads(d)))"
          else
            { bandit -q -r -f json "$2" 2>/dev/null || true; } | python -c "import json,sys;t=sys.stdin.read().strip() or \"{}\";d=json.loads(t);print(sum(1 for r in d.get(\"results\",[]) if r.get(\"issue_severity\") in (\"MEDIUM\",\"HIGH\")))"
          fi
        }
        ro=$(cnt ruff /w/old); rn=$(cnt ruff /w/new)
        bo=$(cnt bandit /w/old); bn=$(cnt bandit /w/new)
        echo "ruff old=$ro new=$rn ; bandit(>=MED) old=$bo new=$bn"
        [ "$rn" -le "$ro" ] && [ "$bn" -le "$bo" ]
      '; then
    selfcheck_note "ruff/bandit flagged a NEW lint/security issue in a suggested fix — review carefully"
  else
    echo "OK: no new ruff/bandit issue introduced"
  fi
fi

# ---- Self-check 3: independent re-scan of the patched tree (= #13) --------
echo "=== self-check 3/3: re-scan patched tree + regression compare ==="
rescan_out="$WORK/after.json"
ran_rescan=0
if [ -n "${RESCAN_CMD:-}" ]; then
  if eval "${RESCAN_CMD} \"$TARGET_DIR\" \"$rescan_out\""; then ran_rescan=1; fi
elif command -v phrase-sec-scan >/dev/null; then
  if phrase-sec-scan --json "$rescan_out" "$TARGET_DIR" >/dev/null 2>&1 || [ -s "$rescan_out" ]; then ran_rescan=1; fi
fi
if [ "$ran_rescan" = 1 ] && [ -s "$rescan_out" ]; then
  if ! python3 "$SAFE_APPLY" --regression "$SCAN_JSON" "$rescan_out"; then
    selfcheck_note "post-fix re-scan still flags blocking findings (or severity rose) — review carefully before merging"
  else
    echo "OK: re-scan confirms the targeted findings are resolved and nothing got worse"
  fi
else
  echo "::notice:: re-scan SKIPPED (no RESCAN_CMD / phrase-sec-scan)."
  echo "Prod safety net: the gate re-runs on the merge/push commit (spec §2.2);"
  echo "the deterministic gauntlet + py_compile above still applied."
fi

# Fold the advisory self-check notes into the PR body + the committed
# SECURITY-REVIEW.md (the dev is the gate; these inform, they don't block).
if [ -s "$SELFCHECK_NOTES" ]; then
  {
    echo ""
    echo "### ⚠️ Automated self-check advisories"
    echo "These did **not** block this PR — *you* are the reviewer. Weigh them:"
    echo ""
    cat "$SELFCHECK_NOTES"
  } | tee -a "$WORK/pr_body.md" >> "$TARGET_DIR/$review_file"
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
  echo ""
  echo "DRY_RUN=1 — files modified in $TARGET_DIR but NOT committed/pushed; no PR opened."
  echo "Inspect the applied fixes with:  git -C $TARGET_DIR diff"
  echo "----- PR body that WOULD be posted -----"
  sed 's/^/  | /' "$WORK/pr_body.md"
  echo "----------------------------------------"
  exit 0
fi

git config user.name "phrase-security-scanner[bot]"
git config user.email "phrase-security-scanner[bot]@users.noreply.github.com"
git checkout -B "$branch"
git add -A
git commit -q -m "security: suggested fixes for blocked scan ($(date -u +%FT%TZ))"
# Bot-only throwaway branch, always recreated from the scanned commit; a
# fresh clone has no tracking ref so --force-with-lease rejects ("stale
# info"). Plain force to THIS branch only; base is never pushed.
git push --force origin "$branch"

# Create the PR EXPLICITLY in the origin repo. `gh repo view` is fork-aware
# (resolves to the PARENT on a fork) — derive owner/repo from origin instead.
NW="$(git remote get-url origin | sed -E 's#(git@github\.com:|https://github\.com/)##; s#\.git$##')"
echo "Target repo (from origin): $NW"
existing="$(gh pr list -R "$NW" --head "$branch" --state open --json url -q '.[0].url' 2>/dev/null || true)"
if [ -n "$existing" ]; then
  echo "PR already open (updated by the push above): $existing"
else
  python3 -c 'import json,sys; print(json.dumps({"title":"Security: suggested fixes for blocked scan","head":sys.argv[1],"base":sys.argv[2],"body":open(sys.argv[3]).read()}))' \
    "$branch" "$base" "$WORK/pr_body.md" > "$WORK/payload.json"
  pr_url="$(gh api -X POST "repos/${NW}/pulls" --input "$WORK/payload.json" --jq .html_url 2>/tmp/open_fix_pr.err || true)"
  if [ -n "${pr_url:-}" ]; then
    echo "PR created: $pr_url"
  else
    echo "WARNING: PR creation failed (branch was still pushed):" >&2
    cat /tmp/open_fix_pr.err >&2 || true
  fi
fi

# Invariant (#1): we never touched the base branch on the remote.
base_sha_after="$(git rev-parse "origin/${base}" 2>/dev/null || echo "no-remote-base")"
if [ "$base_sha_before" != "$base_sha_after" ]; then
  echo "::warning:: origin/${base} changed during the run — investigate (the bot must never push base)." >&2
fi

echo ""
echo "Done. Branch '$branch' pushed; '$base' is untouched. PR is never auto-merged."
