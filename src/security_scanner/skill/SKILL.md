---
name: phrase-security-scanner
version: 0.1.0
description: >
  Scan a Phrase Launchpad repository for security vulnerabilities (OWASP Top 10
  and AI-specific risks). Returns a structured report plus one suggested patch
  per finding the developer can review and apply manually.
---

# Phrase Security Scanner

## What this does

You ask Claude to scan your code, and Claude reads it for security
vulnerabilities — SQL injection, hardcoded credentials, prompt injection in
LLM tool calls, and the rest of the OWASP Top 10 plus the OWASP LLM Top 10.
You get back a Markdown report of findings and a downloadable `.patch` file
for each fix that can be expressed as code. No data is stored after the
scan — when the conversation ends the report ends with it.

This is the **on-demand** path. Critical findings are flagged but not
double-verified by a second blind pass — that extra check is reserved for
the deployment gate (which blocks merges, not advisory scans).

## How to trigger this skill

Say any of these in plain English; Claude will start the scan flow:

- "scan my repo for security vulnerabilities"
- "check this code for security issues"
- "run a security scan on `<repo URL>`"
- "scan this diff for vulnerabilities"
- "are there any security problems in my code?"
- "check my latest commit for vulnerabilities"

## Local pre-push scan (no GitHub, no OAuth)

There are **two ways** to run this skill:

1. **Hosted (spec §2.2):** Claude fetches your repo from GitHub via OAuth and
   returns the report in this conversation. Use this for an already-pushed
   repo. Steps under "How to use the skill" below.
2. **Local pre-push (recommended while coding):** scan the code on your
   machine **before** you push it. Nothing is fetched from GitHub; the report
   and patch files are written **into your project folder** so you can fix
   issues and re-run until clean.

> The local mode is a documented deviation from the approved spec (which is
> GitHub-fetch only). The hosted path above is unchanged.

To run the local pre-push scan, ask Claude "scan my code before I push" (or
run it directly):

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # your key
phrase-sec-scan                          # scans the current directory
phrase-sec-scan --directory src/         # scope to a sub-dir if the repo is large
```

It writes into the project root:

- `security-scan-report.md` — findings, exploit scenarios, and fix snippets
  (overwritten each run).
- `<scan_id>_<n>_<file>.patch` — one per fixable finding. Review, then
  `git apply <file>.patch`, then re-run.

Add these to your `.gitignore` (they are per-run artifacts, not source):

```gitignore
security-scan-report.md
*.patch
```

Local mode runs in `on_demand` mode, so — like the hosted skill — it does
**not** run BR-009 blind verification. Exit code is non-zero if any
High/Critical finding is present (handy as a pre-commit hook).

## How to use the skill (hosted GitHub path)

### 1. Authorise GitHub access (first scan only)

Claude will ask you to click an OAuth link to authorise the
`phrase-security-scanner` GitHub App on the repository you want scanned. The
app requests **contents-read only** — it cannot push code, open PRs, or
modify your repo. Authorisation is per-session: the next time you start a
new conversation, you'll authorise again.

### 2. Tell Claude what to scan

Paste **one** of the following:

- **A repo URL** for a full-repo scan:
  `https://github.com/Phrase-Launchpad/your-service`
- **A diff** for a changed-files scan: paste the output of `git diff base...head`
  directly into the chat. Claude will scan only the changed files.
- **A directory path** if your repo is too large for a full scan (see
  Limitations below):
  `https://github.com/Phrase-Launchpad/your-service path: src/handlers/`

### 3. Read the report

Claude renders a Markdown report inline:

- **Header warnings** flag anything the developer should see first: partial
  scans, findings that were demoted to advisory, no-findings notes.
- **Findings table**: one row per vulnerability with ID, severity,
  confidence, file path, line range, and OWASP reference.
- **Finding details**: per-finding sections with a concrete exploit
  scenario, suggested fix, and a reference to the patch file.

### 4. Apply patches manually

For every finding where the fix is expressible as code, the skill returns a
`.patch` file as a downloadable attachment. Naming convention:
`<scan_id>_<finding_index>_<basename>.patch`.

Apply with `git apply <patch>` from your repo root after reviewing the
proposed change. **Do not auto-apply patches without reading them** —
machine-generated fixes can be subtly wrong.

Some findings (architectural issues, anything that requires changes in
multiple files, configuration changes) don't have a patch — the suggested
fix lives in the report text only.

## Limitations — what this skill does NOT do

- **Large repositories (>150,000 tokens)** cannot be scanned in one go. The
  skill will warn you and ask you to specify a single directory at a time
  (e.g. `src/handlers/` or `infrastructure/`). Roughly: any repo over
  ~600,000 characters of source code is over the limit.
- **No parallel verification.** Critical findings here are flagged but not
  re-verified by a second blind Claude call. If you need that extra check
  (lower false-positive rate at the cost of latency and tokens), use the
  CI/CD gate path — every push runs verification automatically.
- **No persistence.** Scan results, findings, and patches are not saved
  server-side. Once this conversation ends, the report is gone. Copy the
  patches you want to apply *before* closing the chat.
- **No automatic patch application.** The skill returns patch files; it
  does not run `git apply`, open PRs, or push anything to your repo.
- **No follow-up scans on past results.** Each scan is independent — the
  skill won't say "you fixed this finding from last time." Re-run a scan
  after applying patches to see the new state.
- **Cannot scan private content outside the authorised repo.** The OAuth
  scope is tied to the GitHub App's installation on the specific repository
  you authorise. Cross-repo dependencies, vendored code in `vendor/` and
  `node_modules/`, and lock files are excluded from analysis (they're not
  developer-authored source code).
- **No coverage guarantees.** The model can miss vulnerabilities the same
  way a human reviewer can. Treat the report as a starting point for
  review, not as proof the code is secure.

## When to use this skill vs the deployment gate

| If you want… | Use… |
|---|---|
| To check code on your machine before pushing | This skill — **local pre-push mode** (`phrase-sec-scan`) |
| A quick spot-check while developing | This skill |
| To explore findings in a part of the codebase | This skill (with directory scoping) |
| To produce evidence the code was reviewed before merge | The deployment gate (runs in CI/CD on every push) |
| The strongest false-positive guarantees on Critical findings | The deployment gate (it runs BR-009 verification) |

## Privacy and data handling

- Source code is sent to Anthropic for analysis under Phrase's existing Zero
  Data Retention (ZDR) agreement — your code is not stored after the response
  is returned and is not used for model training.
- Before any code leaves your repo for analysis, the skill strips obvious
  credentials (API keys, JWTs, PEM private keys, hardcoded passwords)
  locally. Detected credentials are reported as Critical findings — fix
  those first.
- Logs emitted by the scanner contain file paths and scan metadata only.
  Source code, prompts, and Claude responses are never logged.
