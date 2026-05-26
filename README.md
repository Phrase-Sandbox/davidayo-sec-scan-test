# phrase-sec-scan

A security scanner for Phrase engineers. The `phrase-sec-scan` CLI sends
your code to the Phrase scanner service, which runs a multi-layer analysis
(Semgrep, Bandit, ESLint, gosec + LLM deep-dive) and returns a full
security report. Your code is scanned server-side; findings are displayed
locally.

Two channels, one pipeline:

| Channel | Who | Auth | LLM key |
|---------|-----|------|---------|
| **CLI** | Developer laptop | 30-day portal token | Your BYO key (portal settings) |
| **CI** | GitHub Actions | Org CI token | Org key (admin-managed) |

---

## What you need before you start

- A Phrase Okta account (for portal login).
- A Mac (Apple Silicon or Intel) or a Linux/Windows computer.
- An Anthropic or Google API key to save in the portal (so the scanner can
  run LLM analysis on your behalf).

Install one-time tools (macOS):

```bash
brew install git docker gh cloudflared python@3.12
```

Open the Docker Desktop app once after installing — let the whale icon in
the menu bar go steady before continuing.

---

## Setting up the scanner (ops — one-time per deployment)

### 1 — Clone and configure

```bash
gh repo clone Phrase-Sandbox/davidayo-sec-scan-test
cd davidayo-sec-scan-test
cp .env.local.example .env.local
```

Open `.env.local` and set:

```
# Fernet key for encrypting API keys at rest (REQUIRED).
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
SCANNER_ENCRYPTION_KEY=<your-fernet-key>

# GitHub App credentials (required for CI /agent/scan endpoint).
GITHUB_APP_ID=...
GITHUB_APP_PRIVATE_KEY=...
GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...

# CI gate token — set any non-empty string for local dev.
# Production: rotate via /admin/ci-token, then set this in GitHub Actions.
PHRASE_SCAN_TOKEN=local-test-token
```

The `ANTHROPIC_API_KEY` env var is only used as a bootstrap fallback when
no org settings have been saved yet via `/admin/org-settings`. Set it for
local dev; production uses DB-stored org keys.

### 2 — Start the scanner

```bash
docker compose --env-file .env.local up -d --build security-scanner
curl http://localhost:8000/healthz   # should return {"status":"ok"}
```

### 3 — Expose over the internet (local dev)

```bash
cloudflared tunnel --url http://localhost:8000
```

Copy the `https://random-fluffy-words.trycloudflare.com` URL — this is
your `<TUNNEL_URL>`.

### 4 — Configure org LLM keys (admin)

Open `<TUNNEL_URL>/admin/org-settings` in a browser (Okta required).
Enter your Anthropic and/or Google API keys and pick a default provider.
These keys are encrypted at rest (Fernet) and loaded on every CI scan.
Changes take effect on the next scan — no restart needed.

### 5 — Generate the CI token (admin)

Open `<TUNNEL_URL>/admin/ci-token` → click **Generate CI token**.
Copy the `phs_ci_…` value and save it as the `SCANNER_API_TOKEN` secret
in the `master-scanner-pipeline` GitHub Actions workflow.

---

## Developer onboarding (per-engineer — one-time)

### 1 — Install the CLI

```bash
gh release download latest \
  -R Phrase-Sandbox/davidayo-sec-scan-test \
  -p 'phrase-sec-scan-darwin-arm64' \
  -O /usr/local/bin/phrase-sec-scan
chmod +x /usr/local/bin/phrase-sec-scan
# Mac only: clear Gatekeeper
xattr -d com.apple.quarantine /usr/local/bin/phrase-sec-scan 2>/dev/null || true
```

### 2 — Log in (one-time)

```bash
phrase-sec-scan login --scanner-url <TUNNEL_URL>
```

This opens `<TUNNEL_URL>/portal/cli/login` in your browser. Sign in with
Okta. The portal issues a 30-day personal token and writes it to
`~/.phrase-sec-scan/config.yaml` automatically. **No API key is stored
on disk.**

### 3 — Save your LLM API key (once, via portal)

Open `<TUNNEL_URL>/portal/settings` in a browser. Choose your provider
(Anthropic Claude or Google Gemini), pick a model, and enter your API key.
It is encrypted with Fernet before storage and used only to run your scans.

No key saved → the CLI exits 2 with a link to this page.

### 4 — Scan your project

```bash
cd ~/your-project
phrase-sec-scan .
```

The CLI sends your files to the scanner, which authenticates your token,
loads your LLM settings from the portal, runs the pipeline, and writes
`security-scan-report.md` next to your code.

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No Critical or High findings. |
| `1` | At least one Critical or High finding — see the report. |
| `2` | Config or auth error. Re-run `phrase-sec-scan login`. |
| `3` | Scanner error (transient). Retry; if it persists, file a bug. |

---

## Scan history and usage

Every CLI scan is saved to the portal. Open `<TUNNEL_URL>/portal/scans`
to browse your history and view full reports.

Open `<TUNNEL_URL>/portal/usage` to see a monthly breakdown of your
LLM token consumption, estimated cost, and provider response IDs you can
cross-reference with your Anthropic or Google billing console.

---

## Token lifecycle

| Event | What happens |
|-------|-------------|
| **Issue** | One `phs_local_…` token per user, generated in the portal. |
| **Rotate** | Old token invalidated immediately; new token shown once. |
| **Revoke** | Old token invalidated immediately; no new token. |
| **Expiry** | After 30 days, next scan returns 401 with a re-issue link. |
| **Deactivation** | Admin sets `is_active=false`; next scan returns 401. |

Tokens are stored as `SHA-256(full_token)` — the plaintext is shown
exactly once in the portal and never persisted.

---

## CI pipeline

The CI channel uses a separate endpoint (`/agent/scan`) with the org's
Anthropic/Google keys. Dev repos consume the scanner via the reusable
workflow in `master-scanner-pipeline`:

```yaml
jobs:
  security:
    uses: Phrase-Sandbox/master-scanner-pipeline/.github/workflows/scanner.yml@v2
    # Optional: override the org default LLM provider for this run.
    # with:
    #   provider: gemini
```

The `gate_decision` field in the response (`"block"` or `"advisory"`)
drives the CI pass/fail decision. No client-side severity thresholding.

---

## Admin operations

| Task | URL |
|------|-----|
| Token registry | `/admin/tokens` |
| User management (deactivate/reactivate) | `/admin/users` |
| Org LLM keys + default provider | `/admin/org-settings` |
| Rotate CI token | `/admin/ci-token` |
| Audit log | `/admin/audit` |

---

## Stopping everything

```bash
docker compose down   # stops scanner + postgres (data preserved)
# Ctrl-C in the cloudflared terminal
```

To wipe the database (destructive — removes all tokens, audit log, settings):

```bash
docker compose down -v   # ⚠️ deletes postgres-data volume
```

---

## Building the CLI from source

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
PYTHON=.venv/bin/python3.12 ./build.sh
sudo mv dist/phrase-sec-scan /usr/local/bin/phrase-sec-scan
```

---

## Releasing a new CLI binary

```bash
git tag v0.6.0
git push origin v0.6.0
```

GitHub Actions builds Linux, macOS arm64, macOS x86_64, and Windows
binaries and attaches them to a new Release automatically.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `curl http://localhost:8000/healthz` → 503 | `docker compose --env-file .env.local up -d --build` |
| `401 Token expired` from CLI | Open `<TUNNEL_URL>/portal/` → Rotate token → `phrase-sec-scan login` |
| `401 Account deactivated` | Contact your security administrator. |
| `412 No LLM provider configured` | Open `<TUNNEL_URL>/portal/settings` and save your key. |
| `422` on CI scan | No org key for the requested provider. Open `/admin/org-settings`. |
| Cloudflare URL changed | Re-run `cloudflared tunnel ...`, then `phrase-sec-scan login --scanner-url <new-url>`. |
| `SCANNER_ENCRYPTION_KEY` error on startup | Generate a key and add it to `.env.local` (see Step 1). |
