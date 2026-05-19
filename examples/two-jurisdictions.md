# Using the scanner: two jurisdictions, one running platform

The scanner runs **once** (a deployed/exposed service). You call it two
different ways depending on who you are. The two ways are **strictly
separated** — different endpoint, different token — so they can never be
confused (spec Appendix D-12).

| | A developer, on their own code | The repo's CI pipeline |
|---|---|---|
| Endpoint | `POST /scan/local` | `POST /agent/scan` |
| Token | `LOCAL_SCAN_TOKEN` | `PHRASE_SCAN_TOKEN` |
| Pipeline | on-demand (no BR-009) | deployment-gate (BR-009) |
| Result | a **report**, advisory only | a **pass/block** decision |
| Can it block a deploy / open a PR? | **Never** | Yes (the gate; PR is opt-in) |
| Where you see it | `security-scan-report.md` on your machine | the repo's Actions tab (Job Summary) + artifact |

The local token is rejected by the CI gate and the CI token is rejected by
the local endpoint — the boundary is enforced by credentials, not trust.

## 1. Developer — scan my code right now (advisory, zero install)

No Docker, no Python env, no GitHub App. Just `curl` + `python3` + `git`:

```bash
export SCANNER_URL=https://<the-running-scanner>
export LOCAL_SCAN_TOKEN=<your local-advisory token>
./scripts/scan-local.sh .          # scans the working tree
# -> writes security-scan-report.md next to your code
# -> exits non-zero if Critical/High (use it as a pre-push hook)
```

It uploads only filtered source; the service scans it in memory, strips
secrets, and **persists nothing** (spec §12). It can never block anything —
it just tells *you* what to fix.

## 2. CI — gate a repo (enforcement + visible report)

Copy `examples/dev-repo-security-scan.yml` into the target repo at
`.github/workflows/security-scan.yml`, set the repo variable `SCANNER_URL`
to the running scanner and the secret `PHRASE_SCAN_TOKEN`. On every push/PR
the gate runs and, **whether or not a fix-PR is opened**, the findings are
written to that run's **Job Summary** (a readable table in the repo's own
Actions tab) and uploaded as an artifact. A blocked gate fails the check; an
infrastructure/API error is non-blocking (BR-006).

## Note (simulation)

In the personal simulation the service runs locally and is exposed with a
free Cloudflare quick-tunnel (`cloudflared tunnel --url
http://localhost:8000`); the URL is ephemeral. A real deployment uses a
stable host. The two-jurisdiction model itself is unchanged either way.
