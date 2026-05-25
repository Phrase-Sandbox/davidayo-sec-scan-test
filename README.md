# phrase-sec-scan

A security scanner you run on your own laptop. The `phrase-sec-scan` CLI
sends your code to a scanner service (also running on your laptop), and the
scanner returns a Markdown report with any security issues it found. Your
code never leaves machines you control.

This README is written for someone who has **never used GitHub or the
terminal before**. Copy-paste the commands one at a time.

---

## What you need before you start

You'll need a Mac (Apple Silicon or Intel) or a Linux/Windows computer.
Install these one-time tools:

**macOS** — open the "Terminal" app and paste:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install git docker gh cloudflared python@3.12
```

After `brew install docker` you also need to open the Docker Desktop app
once (Applications → Docker) and let it finish starting up. The whale icon
in the menu bar should be steady (not animated).

You also need:

- **An Anthropic API key.** Go to
  [console.anthropic.com](https://console.anthropic.com/), sign up, open
  "API Keys" in the sidebar, click "Create Key", and copy the value (starts
  with `sk-ant-`). Keep this window open — you'll paste it in Step 2.

---

## Step 1 — Get the code onto your computer

```bash
gh auth login
```

Pick "GitHub.com" → "HTTPS" → "Login with a web browser" and follow the
prompts. When it's done, run:

```bash
gh repo clone Phrase-Sandbox/davidayo-sec-scan-test
cd davidayo-sec-scan-test
```

You are now inside the project folder. Every command from here runs from
this folder unless we say otherwise.

---

## Step 2 — Start the scanner

```bash
cp .env.local.example .env.local
```

Open `.env.local` in any text editor (TextEdit, VS Code, nano — anything).
Find the line that says:

```
ANTHROPIC_API_KEY=sk-ant-replace-with-real-key
```

Replace `sk-ant-replace-with-real-key` with the key you copied from
console.anthropic.com. Save the file.

Now start the scanner:

```bash
docker compose --env-file .env.local up -d --build security-scanner
```

The first run downloads and builds an image — that can take a few minutes.
When it finishes, check that the scanner is alive:

```bash
curl http://localhost:8000/healthz
```

You should see `{"status":"ok"}`. If you get a connection error, wait 10
seconds and try again — the scanner is still starting.

---

## Step 3 — Make the scanner reachable over the internet

The scanner is running on your laptop. To talk to it from anywhere (or to
let the browser-based portal work), expose it through a free Cloudflare
tunnel. **Open a new terminal window** (leave the first one alone) and run:

```bash
cd ~/davidayo-sec-scan-test
cloudflared tunnel --url http://localhost:8000
```

A few seconds later Cloudflare prints a line like:

```
Your quick tunnel has been created! Visit it at:
https://random-fluffy-words.trycloudflare.com
```

Copy that URL. You will use it as `<TUNNEL_URL>` in the rest of this guide.

> The URL changes every time you restart `cloudflared` on the free plan.
> That's normal. Just paste the new one when it changes.

Keep this terminal window open. If you close it, the tunnel dies.

---

## Step 4 — Get your personal access token

In a web browser, open:

```
<TUNNEL_URL>/portal/
```

(replace `<TUNNEL_URL>` with the URL from Step 3).

Click **"Issue token"**. The page shows a long string that starts with
`phs_local_tok-...`. **Copy it now — it's only shown once.**

---

## Step 5 — Install the CLI on your laptop

Pick the right file for your computer:

| Your computer | File to download |
| --- | --- |
| Mac with M1/M2/M3 chip (Apple Silicon) | `phrase-sec-scan-darwin-arm64` |
| Mac with Intel chip | `phrase-sec-scan-darwin-x86_64` |
| Linux | `phrase-sec-scan-linux-x86_64` |
| Windows | `phrase-sec-scan-windows-x86_64.exe` |

For Mac (Apple Silicon), run:

```bash
gh release download v0.2.0 \
  -R Phrase-Sandbox/davidayo-sec-scan-test \
  -p 'phrase-sec-scan-darwin-arm64' \
  -O /usr/local/bin/phrase-sec-scan
chmod +x /usr/local/bin/phrase-sec-scan
```

(Swap the file name in the `-p` flag if you're on a different machine.)

**Mac only — one-time:** Apple blocks unsigned downloads. Clear the warning:

```bash
xattr -d com.apple.quarantine /usr/local/bin/phrase-sec-scan
```

If it says `No such xattr: com.apple.quarantine` — that's fine, it means
nothing to clear.

---

## Step 6 — Connect the CLI to your scanner

```bash
phrase-sec-scan login --scanner-url <TUNNEL_URL> --manual
```

It prompts for a token. Paste the one you copied in Step 4 and press
Enter. You should see `Saved config to ~/.phrase-sec-scan/config.yaml`.

---

## Step 7 — Scan some code

Go into any project folder and run:

```bash
cd ~/some-project-of-yours
phrase-sec-scan .
```

The CLI uploads the working tree to your scanner, the scanner runs, and a
report is written next to your code:

```
security-scan-report.md
```

Open it in any editor — it lists every issue found, with severity and a
suggested fix. The exit code tells you:

- `0` — no Critical or High findings (clean).
- `1` — at least one Critical or High finding.
- `2` — config or auth error (usually means run `login` again).

---

## Provider selection

The scanner supports two LLM backends: **Anthropic Claude** (the default,
spec-mandated, ZDR/DPA-confirmed) and **Google Gemini** (optional, sim-only,
pending Security/Legal sign-off — see Appendix D-15).

### Local-BYO mode (`--local`)

When you scan locally (no server), you supply your own API key and optionally
choose the provider and model:

```bash
# Default: uses ANTHROPIC_API_KEY from your environment
phrase-sec-scan --local .

# Explicit provider + model (env-based key)
phrase-sec-scan --local --provider claude --model claude-sonnet-4-6 .
phrase-sec-scan --local --provider gemini --model gemini-2.5-pro .

# Store your key once so you don't need the env var every time
phrase-sec-scan login --provider claude --api-key sk-ant-...
phrase-sec-scan login --provider gemini --api-key AIza-...

# After login you can just run
phrase-sec-scan --local .
```

**Resolution order** (highest wins):

| Source | Provider | Model | Key |
|--------|----------|-------|-----|
| CLI flag | `--provider` | `--model` | — |
| Env var | `SCANNER_LLM_PROVIDER` | `SCANNER_LLM_MODEL` | `ANTHROPIC_API_KEY` / `GOOGLE_API_KEY` |
| Config file (`~/.phrase-sec-scan/config.yaml`) | `provider:` | `model:` | `anthropic_api_key:` / `google_api_key:` |
| Built-in default | `claude` | provider default | — |

The config file is never required — env vars always work. Env vars take
precedence over the stored key, so per-shell overrides (`ANTHROPIC_API_KEY=sk-ant-... phrase-sec-scan --local .`) work without changing your config.

To install the Gemini SDK (not bundled by default):

```bash
pip install phrase-sec-scan[providers]
```

### Remote/org scan (default CLI mode + server)

When the CLI POSTs to the deployed scanner (the default, no `--local` flag),
the server picks the provider using its own environment variables. **The CLI
never forwards your personal API key to the server.** The server has its own
org-level credentials configured by the operator.

Server-side provider selection:

```bash
# In .env.local (or the server's environment)
SCANNER_LLM_PROVIDER=anthropic   # or: google
SCANNER_LLM_MODEL=claude-sonnet-4-6   # optional override
GOOGLE_API_KEY=AIza-...          # only if provider=google
```

Both `/agent/scan` (the CI gate path) and `/scan/local` (the on-demand
advisory path) use the same factory — a single `SCANNER_LLM_PROVIDER` env
var switches both endpoints consistently.

### Credential separation

| Mode | Who owns credentials | Where keys live |
|------|----------------------|-----------------|
| `--local` | Developer (BYO) | Developer's env / `~/.phrase-sec-scan/config.yaml` |
| Remote (default) | Organisation / operator | Server's `.env.local` / secrets manager |

The CLI client **never** forwards API keys to the server. The server **never**
reads the developer's local config. This separation is enforced by design —
there is no flag or config that bridges the two.

For CI/CD integration, see the `master-scanner-pipeline` sibling repo which
provides a reusable GitHub Actions workflow that calls this scanner's API.

---

## Stopping everything

```bash
phrase-sec-scan logout
```

Then go to the `cloudflared` terminal and press `Ctrl-C`. Then back in the
first terminal:

```bash
docker compose down
```

Everything is stopped. Run Step 2 + Step 3 + Step 6 next time to start
again.

---

## Troubleshooting

| Symptom | What to try |
| --- | --- |
| `curl http://localhost:8000/healthz` returns 503 | Open Docker Desktop and make sure it's running. Then `docker compose --env-file .env.local up -d --build security-scanner` again. |
| `Cannot connect to the Docker daemon` | Docker Desktop isn't running. Open the Docker app, wait for the whale icon to go steady, then retry. |
| `Error: address already in use` on port 8000 | Something else is using 8000. Either stop it, or edit `docker-compose.yml` and change `8000:8000` to e.g. `8080:8000`, then use `http://localhost:8080`. |
| `unauthorized: invalid API key` in the scanner logs | Your `ANTHROPIC_API_KEY` in `.env.local` is wrong or expired. Get a new key from `console.anthropic.com` and re-run Step 2. |
| `phrase-sec-scan: command not found` | Your shell can't find the binary. Run `which phrase-sec-scan`. If empty, redo Step 5 and make sure the download path is `/usr/local/bin/phrase-sec-scan`. |
| Cloudflare URL stops working after you restart your laptop | Free Cloudflare tunnels are temporary — re-run Step 3 to get a new URL, then `phrase-sec-scan login` again with the new URL. |

---

## Releasing a new CLI binary

When you change the CLI code and want to ship a new version:

```bash
git tag v0.2.1
git push origin v0.2.1
```

GitHub Actions (the `release-cli` workflow) builds the binary on Linux,
macOS Intel, macOS Apple Silicon, and Windows, and attaches each one to a
new GitHub Release automatically. Check the "Actions" tab in the GitHub
website to watch it run.
