# phrase-sec-scan

A security scanner for Phrase engineers. The `phrase-sec-scan` CLI sends your code to the Phrase scanner service, which runs a multi-layer analysis (Semgrep, Bandit, ESLint, gosec + LLM deep-dive) and returns a full security report. Your code is scanned server-side; findings are displayed locally.

The service is deployed on Phrase Launchpad (internal Kubernetes) and is only reachable on the Phrase network.

**Service URL:** `https://phrase-sec-scan.launchpad.phrase-internal.com`

Two channels, one pipeline:

| Channel | Who | Auth | LLM key |
|---------|-----|------|---------|
| **CLI** | Developer laptop | 30-day portal token | Your BYO key (portal settings) |
| **CI** | GitHub Actions | Org CI token | Org key (admin-managed) |

---

## What you need

- A Phrase Okta account (for portal login).
- Access to the Phrase internal network (office or VPN).
- An Anthropic or Google API key to save in the portal (so the scanner can run LLM analysis on your behalf).

---

## Developer onboarding (per-engineer — one-time)

### 1 — Install the CLI

**macOS (Apple Silicon):**

```bash
gh release download latest \
  -R Phrase-Launchpad/phrase-sec-scan \
  -p 'phrase-sec-scan-darwin-arm64' \
  -O /usr/local/bin/phrase-sec-scan
chmod +x /usr/local/bin/phrase-sec-scan
xattr -d com.apple.quarantine /usr/local/bin/phrase-sec-scan 2>/dev/null || true
```

**Linux (x86_64):**

```bash
gh release download latest \
  -R Phrase-Launchpad/phrase-sec-scan \
  -p 'phrase-sec-scan-linux-x86_64' \
  -O /usr/local/bin/phrase-sec-scan
chmod +x /usr/local/bin/phrase-sec-scan
```

**Windows (x86_64):** download `phrase-sec-scan-windows-x86_64.exe` from the [latest release](https://github.com/Phrase-Launchpad/phrase-sec-scan/releases/latest) and place it on your `PATH`.

### 2 — Log in (one-time)

```bash
phrase-sec-scan login --scanner-url https://phrase-sec-scan.launchpad.phrase-internal.com
```

This opens the portal login page in your browser. Sign in with Okta. The portal issues a 30-day personal token and writes it to `~/.phrase-sec-scan/config.yaml` automatically.

After the first login the URL is saved to config — subsequent `phrase-sec-scan` commands need no flags.

### 3 — Save your LLM API key (once, via portal)

Open [https://phrase-sec-scan.launchpad.phrase-internal.com/portal/settings](https://phrase-sec-scan.launchpad.phrase-internal.com/portal/settings) in a browser. Choose your provider (Anthropic Claude or Google Gemini), pick a model, and enter your API key. It is encrypted before storage and used only to run your scans.

No key saved → the CLI exits 2 with a link to this page.

### 4 — Scan your project

```bash
cd ~/your-project
phrase-sec-scan .
```

The CLI sends your files to the scanner, which authenticates your token, loads your LLM settings from the portal, runs the pipeline, and writes `security-scan-report.md` next to your code.

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No Critical or High findings. |
| `1` | At least one Critical or High finding — see the report. |
| `2` | Config or auth error. Re-run `phrase-sec-scan login`. |
| `3` | Scanner error (transient). Retry; if it persists, file a bug. |

---

## Scan history and usage

Every CLI scan is saved to the portal. Open [/portal/scans](https://phrase-sec-scan.launchpad.phrase-internal.com/portal/scans) to browse your history and view full reports.

Open [/portal/usage](https://phrase-sec-scan.launchpad.phrase-internal.com/portal/usage) to see a monthly breakdown of your LLM token consumption, estimated cost, and provider response IDs you can cross-reference with your Anthropic or Google billing console.

---

## Token lifecycle

| Event | What happens |
|-------|-------------|
| **Issue** | One `phs_local_…` token per user, generated in the portal. |
| **Rotate** | Old token invalidated immediately; new token shown once. |
| **Revoke** | Old token invalidated immediately; no new token. |
| **Expiry** | After 30 days, next scan returns 401 with a re-issue link. |
| **Deactivation** | Admin sets `is_active=false`; next scan returns 401. |

Tokens are stored as `SHA-256(full_token)` — the plaintext is shown exactly once in the portal and never persisted.

---

## CI pipeline

The CI channel uses a separate endpoint (`/agent/scan`) with the org's Anthropic/Google keys. Dev repos consume the scanner via the reusable workflow in `master-scanner-pipeline`:

```yaml
jobs:
  security:
    uses: Phrase-Sandbox/master-scanner-pipeline/.github/workflows/scanner.yml@v1
    # Optional: override the org default LLM provider for this run.
    # with:
    #   provider: gemini
```

The `gate_decision` field in the response (`"block"` or `"advisory"`) drives the CI pass/fail decision.

---

## Admin operations

All admin pages require Okta authentication (handled by the gateway).

| Task | URL |
|------|-----|
| Token registry | [/admin/tokens](https://phrase-sec-scan.launchpad.phrase-internal.com/admin/tokens) |
| User management (deactivate/reactivate) | [/admin/users](https://phrase-sec-scan.launchpad.phrase-internal.com/admin/users) |
| Org LLM keys + default provider | [/admin/org-settings](https://phrase-sec-scan.launchpad.phrase-internal.com/admin/org-settings) |
| Rotate CI token | [/admin/ci-token](https://phrase-sec-scan.launchpad.phrase-internal.com/admin/ci-token) |
| Audit log | [/admin/audit](https://phrase-sec-scan.launchpad.phrase-internal.com/admin/audit) |

---

## Releasing a new CLI binary

```bash
git tag v0.x.0
git push launchpad v0.x.0
```

GitHub Actions builds Linux x86_64, macOS ARM64, and Windows x86_64 binaries and attaches them to a new Release automatically.

---

## Building the CLI from source

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
PYTHON=.venv/bin/python3.12 ./build.sh
sudo mv dist/phrase-sec-scan /usr/local/bin/phrase-sec-scan
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Browser shows "not found" after Okta login | Clear cookies and try again; if it persists, check the OIDC PluginConfig is deployed. |
| `401 Token expired` from CLI | Open [/portal/](https://phrase-sec-scan.launchpad.phrase-internal.com/portal/) → Rotate token → `phrase-sec-scan login`. |
| `401 Account deactivated` | Contact your security administrator. |
| `412 No LLM provider configured` | Open [/portal/settings](https://phrase-sec-scan.launchpad.phrase-internal.com/portal/settings) and save your key. |
| `422` on CI scan | No org key for the requested provider. Open [/admin/org-settings](https://phrase-sec-scan.launchpad.phrase-internal.com/admin/org-settings). |
| `SCANNER_ENCRYPTION_KEY` error on startup | Regenerate the key and update the `SCANNER_ENCRYPTION_KEY` GitHub Actions secret, then redeploy. |
| Service unreachable | Confirm you are on the Phrase network (office or VPN). |
