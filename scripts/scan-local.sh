#!/usr/bin/env bash
#
# scan-local.sh — zero-install developer client for the LOCAL-ADVISORY
# jurisdiction (Appendix D-12).
#
# A developer runs this on their own machine to scan their working tree
# against the already-running scanner platform. It needs only `curl`,
# `python3`, and `git` (all standard) — NO Docker, NO Python env, NO GitHub
# App. It uploads the filtered source, gets a Markdown report back, writes it
# next to the code, and exits non-zero on Critical/High so it doubles as a
# pre-push hook.
#
# This jurisdiction is ADVISORY ONLY. It can never block a deployment or open
# a PR — that is the CI gate's job, reached with a different token. See the
# spec's two-jurisdiction design (Appendix D-12).
#
# Usage:
#   export SCANNER_URL=https://<your-running-scanner>
#   export LOCAL_SCAN_TOKEN=<the local-advisory token>
#   ./scripts/scan-local.sh [path]            # default: current directory
#
# Exit: 0 = no Critical/High, 1 = Critical/High found (advisory), 2 = error.

set -euo pipefail

ROOT="${1:-.}"
SCANNER_URL="${SCANNER_URL:?set SCANNER_URL=https://<running-scanner>}"
TOKEN="${LOCAL_SCAN_TOKEN:?set LOCAL_SCAN_TOKEN=<local-advisory token>}"

[ -d "$ROOT" ] || { echo "not a directory: $ROOT" >&2; exit 2; }
command -v curl    >/dev/null || { echo "curl required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 2; }

ROOT="$(cd "$ROOT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Prefer git's view (respects .gitignore, skips .git / build output). Fall
# back to a find when the tree is not a git repo.
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$ROOT" ls-files -z > "$WORK/list"
  LIST_MODE=git
else
  ( cd "$ROOT" && find . -type f -not -path './.git/*' -print0 ) > "$WORK/list"
  LIST_MODE=find
fi

# Build the upload JSON: read each candidate, skip binary / >1MB / unreadable.
# python3 only — never shells out with file contents.
ROOT="$ROOT" LIST="$WORK/list" python3 - "$WORK/payload.json" <<'PY'
import json, os, sys
root = os.environ["ROOT"]
raw = open(os.environ["LIST"], "rb").read()
names = [n.decode("utf-8", "surrogateescape") for n in raw.split(b"\0") if n]
files, skipped = {}, 0
MAX = 1_000_000
for rel in names:
    rel = rel.lstrip("./")
    p = os.path.join(root, rel)
    try:
        if not os.path.isfile(p) or os.path.getsize(p) > MAX:
            skipped += 1
            continue
        with open(p, "rb") as fh:
            blob = fh.read()
        if b"\0" in blob:           # binary — never useful to the scanner
            skipped += 1
            continue
        files[rel] = blob.decode("utf-8", "replace")
    except OSError:
        skipped += 1
payload = {
    "files": files,
    "triggered_by": "local-dev",
    "repo_url": "https://github.com/local/" + (os.path.basename(root) or "workspace"),
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
print(f"uploading {len(files)} files ({skipped} skipped: binary/>1MB)", file=sys.stderr)
PY

code="$(curl -sS -o "$WORK/resp.json" -w '%{http_code}' \
  --max-time 600 \
  -X POST "${SCANNER_URL%/}/scan/local" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary "@$WORK/payload.json" || true)"

if [ "$code" != "200" ]; then
  echo "scanner returned HTTP ${code:-000} — advisory scan could not complete." >&2
  head -c 400 "$WORK/resp.json" 2>/dev/null >&2 || true
  echo >&2
  exit 2
fi

# Write the report next to the code; print the summary; advisory exit code.
REPORT="$ROOT/security-scan-report.md" python3 - "$WORK/resp.json" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
open(os.environ["REPORT"], "w", encoding="utf-8").write(d.get("markdown", ""))
c, h = d.get("critical", 0), d.get("high", 0)
m, low = d.get("medium", 0), d.get("low", 0)
print(f"Advisory scan complete: {d.get('findings_count',0)} findings "
      f"({c} Critical, {h} High, {m} Medium, {low} Low).")
print(f"Report written to: {os.environ['REPORT']}")
print("Advisory only — this never blocks a deploy or opens a PR "
      "(that is the CI gate's separate jurisdiction).")
sys.exit(1 if (c or h) else 0)
PY
