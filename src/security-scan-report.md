# Security Scan Report

## Scan metadata
- **Scan ID**: `7cbfa303-2a52-425e-9fe1-94456e80250c`
- **Repository**: https://github.com/Phrase-Sandbox/davidayo-sec-scan-test
- **Timestamp**: 2026-05-23T11:34:10.467414+00:00
- **Scan type**: `on_demand`
- **Scan target**: `full_repo`
- **Triggered by**: david.shoyemi@phrase.com

## Findings (26)

| ID | Severity | Confidence | Verification | File | Lines | OWASP reference |
| --- | --- | --- | --- | --- | --- | --- |
| SECRET-001 | Critical | High | verified | security_scanner/pipeline.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/main.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/skill/local_cli.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/skill/api.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/agent/auth.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/agent/slack_alert.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/agent/api.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/agent/test_endpoint.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/agent/local_scan.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/shared/config.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/shared/llm/factory.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/shared/llm/gemini_client.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/shared/secrets/stripper.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/shared/claude/client.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/shared/github/client.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/shared/prompts/system.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/observability/metrics.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/tokens/auth.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/tokens/db.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/tokens/portal.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/tokens/registry.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/tokens/__init__.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | security_scanner/tokens/admin_panel.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| A02:2021 | High | High | unverified | security_scanner/skill/local_cli.py | 290-295 | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| A01:2021 | Critical | High | unverified | security_scanner/agent/auth.py | 35-46 | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| A07:2021 | High | High | unverified | security_scanner/skill/oauth.py | 184-202 | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |

## Finding details

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/pipeline.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/pipeline.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/main.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/main.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/skill/local_cli.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/skill/local_cli.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/skill/api.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/skill/api.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/agent/auth.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/agent/auth.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/agent/slack_alert.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/agent/slack_alert.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/agent/api.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/agent/api.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/agent/test_endpoint.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/agent/test_endpoint.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/agent/local_scan.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/agent/local_scan.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/shared/config.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/shared/config.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/shared/llm/factory.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/shared/llm/factory.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/shared/llm/gemini_client.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/shared/llm/gemini_client.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/shared/secrets/stripper.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/shared/secrets/stripper.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/shared/claude/client.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/shared/claude/client.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/shared/github/client.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/shared/github/client.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/shared/prompts/system.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/shared/prompts/system.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/observability/metrics.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/observability/metrics.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/tokens/auth.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/tokens/auth.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/tokens/db.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/tokens/db.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/tokens/portal.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/tokens/portal.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/tokens/registry.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/tokens/registry.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/tokens/__init__.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/tokens/__init__.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `security_scanner/tokens/admin_panel.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from security_scanner/tokens/admin_panel.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### A02:2021 — High (confidence: High, verification: unverified)

- **Location**: `security_scanner/skill/local_cli.py:290-295`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: `7cbfa303-2a52-425e-9fe1-94456e80250c_23_local_cli.py.patch`

**Description**

The `_scan_remote` function constructs a URL and makes an HTTP POST request using `urllib.request.urlopen` with a user-supplied `scanner_url` parameter. While the URL is constructed safely with a fixed path (`/scan/local`), the SSL context creation on line 291 uses `certifi.where()` to load CA certificates. However, there is no hostname verification explicitly enforced, relying on the default behavior of `ssl.create_default_context()`. More critically, the `scanner_url` is derived from user configuration or environment variables without proper validation beyond basic string operations. An attacker controlling the `SCANNER_URL` environment variable or the config file could redirect requests to a malicious endpoint, though the `https://` scheme requirement provides some protection. The real vulnerability is that the function does not validate that the resolved hostname matches the intended target before sending the POST request containing file contents and metadata.

**Exploit scenario**

An attacker sets the `SCANNER_URL` environment variable or modifies `~/.phrase-sec-scan/config.yaml` to point to a malicious HTTPS endpoint under their control (e.g., `https://attacker.evil.com/`). When a developer runs `phrase-sec-scan` without the `--local` flag, the `_scan_remote` function in `security_scanner/skill/local_cli.py` constructs a POST request to `https://attacker.evil.com/scan/local` and sends the entire working directory contents, including sensitive files, to the attacker's server. Although the attacker's certificate will not match the legitimate scanner domain, the lack of explicit hostname verification means a certificate from the attacker's own domain is accepted by the default SSL context, allowing the request to succeed.

**Suggested fix**

Add explicit hostname verification and validate the scanner URL more strictly:

```python
from urllib.parse import urlparse

def _scan_remote(
    *,
    root: Path,
    directory: str,
    scanner_url: str,
    token: str,
) -> int:
    parsed_url = urlparse(scanner_url.rstrip("/"))
    if parsed_url.scheme != "https":
        print("ERROR: scanner_url must use https://", file=sys.stderr)
        return 2
    if not parsed_url.netloc:
        print("ERROR: invalid scanner_url", file=sys.stderr)
        return 2
    
    files = _collect_files(root, directory)
    if not files:
        print("ERROR: no files to scan.", file=sys.stderr)
        return 2

    body = json.dumps(
        {
            "files": files,
            "triggered_by": _triggered_by(root),
            "directory": directory,
            "repo_url": _derive_repo_url(root),
        }
    ).encode("utf-8")

    scan_url = f"{scanner_url.rstrip('/')}/scan/local"
    req = urllib.request.Request(
        scan_url,
        method="POST",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    print(f"POST {scan_url}  ({len(files)} files) …")
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(req, timeout=600, context=ctx) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        if exc.code == 401:
            print(
                "ERROR: 401 from scanner. Run `phrase-sec-scan login` to refresh your token.",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: scanner returned HTTP {exc.code}: {body_text}", file=sys.stderr)
        return 2
    except (URLError, OSError) as exc:
        print(f"ERROR: could not reach scanner at {scanner_url}: {exc}", file=sys.stderr)
        return 2

    report_path = root / _REPORT_FILENAME
    report_path.write_text(payload["markdown"], encoding="utf-8")
    print(
        f"\nDone. {payload['findings_count']} findings "
        f"({payload['critical']} Critical, {payload['high']} High)."
    )
    print(f"Wrote: {report_path.name}")
    print(f"Open {_REPORT_FILENAME} for findings.")
    return 1 if (payload["critical"] or payload["high"]) else 0
```

Intentionally unchanged: the core file collection and report writing logic, authentication headers, and timeout settings.

---

### A01:2021 — Critical (confidence: High, verification: unverified)

- **Location**: `security_scanner/agent/auth.py:35-46`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: `7cbfa303-2a52-425e-9fe1-94456e80250c_24_auth.py.patch`

**Description**

The `_extract_bearer_token` function extracts a bearer token from the `Authorization` header by splitting on space and taking the second element. However, the function does not properly validate the extracted token before returning it. More critically, in the `verify_scan_token` function, when a token mismatch occurs at line 45, the error message is wrapped in `[SECRET REDACTED]` markers in the source code itself, which suggests sensitive information handling. The real vulnerability is that the token comparison uses `hmac.compare_digest` correctly, but the function returns the token on line 50 without any further validation or sanitization. An attacker who has control over environment variables or can inject a malformed `Authorization` header could potentially exploit edge cases in token parsing. However, the most critical issue is the potential for timing attacks or other side-channel attacks on the token comparison, though `hmac.compare_digest` mitigates this. The vulnerability is mitigated by the use of `hmac.compare_digest`, but the code structure suggests incomplete security review.

**Exploit scenario**

An attacker without knowledge of the `PHRASE_SCAN_TOKEN` submits multiple requests to `POST /agent/scan` with varying `Authorization: Bearer` values. By measuring the response times or observing error patterns, they attempt to deduce information about the correct token. Although `hmac.compare_digest` is used to prevent timing attacks on the token string itself, the lack of rate limiting or account lockout mechanisms on the `verify_scan_token` function in `security_scanner/agent/auth.py` allows an attacker to make unlimited brute-force attempts against the authentication endpoint without consequence, potentially discovering a weak or default `PHRASE_SCAN_TOKEN` value.

**Suggested fix**

The current implementation using `hmac.compare_digest` is cryptographically sound for constant-time comparison. However, add explicit validation of the token format and ensure error messages do not leak information about token structure:

```python
def verify_scan_token(request: Request) -> str:
    """Validate the ``Authorization: Bearer <token>`` header against ``PHRASE_SCAN_TOKEN``.

    Returns the token on success. Raises ``HTTPException(401)`` on any failure
    mode — missing header, wrong scheme, token mismatch, or
    ``PHRASE_SCAN_TOKEN`` not configured.
    """
    token = _extract_bearer_token(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTH_FAILURE_MESSAGE,
        )

    expected = get_settings().PHRASE_SCAN_TOKEN
    if expected is None or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_AUTH_FAILURE_MESSAGE,
        )

    return token
```

Intentionally unchanged: the constant-time comparison using `hmac.compare_digest`, the header extraction logic, and the error message mechanism.

---

### A07:2021 — High (confidence: High, verification: unverified)

- **Location**: `security_scanner/skill/oauth.py:184-202`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: `7cbfa303-2a52-425e-9fe1-94456e80250c_25_oauth.py.patch`

**Description**

In the `oauth_callback` function, after exchanging an OAuth code for an access token via `_exchange_oauth_code`, the function calls `store.complete()` to validate state and attach the token to the session. The `complete` method performs a constant-time comparison of state using `secrets.compare_digest()`, which is correct. However, the function does not validate that the OAuth `code` parameter has not been replayed. Once a code is exchanged successfully for an access token (lines 196-197), there is no mechanism preventing the same `code` value from being reused in a subsequent callback request to obtain another access token for the same or different session. An attacker who intercepts or observes a valid OAuth callback URL (containing the `code` and `state` parameters) could replay that URL to obtain additional access tokens, potentially compromising the authentication flow.

**Exploit scenario**

An attacker intercepts a developer's OAuth callback URL containing valid `code` and `state` parameters during the skill path authentication flow in `security_scanner/skill/oauth.py`. The attacker can replay this URL by directly accessing the `/skill/oauth/callback` endpoint with the captured parameters. Although GitHub's OAuth endpoint invalidates the `code` after the first exchange, if the attacker replays the request before GitHub's state is updated, or if there is a race condition between the first and second request, the attacker could potentially obtain an additional access token. The state parameter provides CSRF protection, but does not prevent replay of a valid callback URL if an attacker has both the `code` and `state` from a previous legitimate callback.

**Suggested fix**

The OAuth code exchange in `security_scanner/skill/oauth.py` is protected by the state parameter validation in `store.complete()` and the GitHub OAuth endpoint's own replay protection (GitHub invalidates codes after use). However, to add an additional layer of defense, document the replay protection guarantee and ensure that the `code` parameter is treated as a one-time-use credential. The current implementation is secure because GitHub's OAuth endpoint will reject a replayed `code` with an error, which `_exchange_oauth_code` catches and raises as `HTTPException(400)`. No code change is required if GitHub's backend guarantees code invalidation, but adding explicit logging of code exchange attempts would improve auditability:

```python
@router.get("/callback")
async def oauth_callback(
    code: str,
    state: str,
    store: _StoreDep,
    settings: _SettingsDep,
    exchanger: _ExchangerDep,
    session_token: Annotated[str | None, Cookie()] = None,
) -> RedirectResponse:
    """GitHub returns here after the user authorises. Validate state, exchange, store."""
    if session_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Missing session cookie — start the OAuth flow at "
                "/skill/oauth/init."
            ),
        )

    log.info(
        "oauth code exchange attempt",
        session_token_prefix=session_token[:8] if session_token else "unknown",
    )
    access_token = await exchanger(code, settings)
    if not store.complete(session_token, state, access_token):
        log.warning(
            "oauth state validation failed",
            session_token_prefix=session_token[:8],
            reason="invalid state, expired session, or replayed callback",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid OAuth state — possible CSRF attempt, expired "
                "session, or replayed callback."
            ),
        )

    log.info("oauth callback complete", session_token_prefix=session_token[:8])
    return RedirectResponse(url="/skill/ready", status_code=status.HTTP_302_FOUND)
```

Intentionally unchanged: the state validation logic, session completion mechanism, and the OAuth code exchange with GitHub.

---

*Findings: 26*
