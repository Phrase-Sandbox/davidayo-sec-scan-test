# Security Scan Report

## Scan metadata
- **Scan ID**: `34a14a50-d61a-438a-847f-da4ad08dabc6`
- **Repository**: https://github.com/davidayomide/VAmPI
- **Timestamp**: 2026-05-18T05:22:36.152068+00:00
- **Scan type**: `deployment_gate`
- **Scan target**: `full_repo`
- **Triggered by**: standup-demo

## Gate decision: `BLOCKED`

## Findings (12)

| ID | Severity | Confidence | Verification | File | Lines | OWASP reference |
| --- | --- | --- | --- | --- | --- | --- |
| SECRET-001 | Critical | High | verified | api_views/users.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | config.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | models/user_model.py | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| SECRET-001 | Critical | High | verified | openapi_specs/openapi3.yml | — | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/ |
| A03:2021 | Critical | High | verified | models/user_model.py | 57-63 | https://owasp.org/Top10/A03_2021-Injection/ |
| A01:2021 | High | High | unverified | api_views/books.py | 44-56 | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |
| A01:2021 | High | High | unverified | api_views/users.py | 118-127 | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |
| A01:2021 | High | High | unverified | api_views/users.py | 37-55 | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |
| A02:2021 | High | High | unverified | config.py | 10 | https://owasp.org/Top10/A02_2021-Cryptographic_Failures/ |
| A02:2021 | High | High | unverified | models/user_model.py | 14 | https://owasp.org/Top10/A02_2021-Cryptographic_Failures/ |
| A05:2021 | Medium | High | unverified | api_views/users.py | 138-158 | https://owasp.org/Top10/A05_2021-Security_Misconfiguration/ |
| A05:2021 | Medium | High | unverified | app.py | 14 | https://owasp.org/Top10/A05_2021-Security_Misconfiguration/ |

## Finding details

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `api_views/users.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from api_views/users.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `config.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from config.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `models/user_model.py`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from models/user_model.py and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### SECRET-001 — Critical (confidence: High, verification: verified)

- **Location**: `openapi_specs/openapi3.yml`
- **OWASP reference**: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
- **Patch file**: ``

**Description**

Hardcoded credentials were detected in the source file and redacted before analysis. Remove the credentials from the codebase and rotate the exposed key/token/password.

**Exploit scenario**

An attacker who clones the repository extracts the hardcoded credential from openapi_specs/openapi3.yml and forges authenticated requests using it.

**Suggested fix**

Move the credential out of the repository (use environment variables or the Launchpad secrets pipeline via /add-secret) and rotate the exposed value.

---

### A03:2021 — Critical (confidence: High, verification: verified)

- **Location**: `models/user_model.py:57-63`
- **OWASP reference**: https://owasp.org/Top10/A03_2021-Injection/
- **Patch file**: ``

**Description**

The get_user() method constructs a raw SQL query by directly interpolating the unsanitised 'username' path parameter into an f-string, then executes it via SQLAlchemy's text(). This is a classic SQL injection when vuln==1 (the default in the Docker image).

**Exploit scenario**

An attacker sends a GET request to /users/v1/anythingRandom' OR '1'='1 against models/user_model.py. The f-string produces SELECT * FROM users WHERE username = 'anythingRandom' OR '1'='1', which always returns the first row. By crafting payloads such as ' UNION SELECT id,username,password,email,admin FROM users-- the attacker can dump all usernames, plain-text passwords, and admin flags from the database without authentication.

**Suggested fix**

Replace the raw string interpolation with a parameterised query: db.session.execute(text('SELECT * FROM users WHERE username = :u'), {'u': username}). Alternatively, use the ORM: User.query.filter_by(username=username).first() unconditionally.

---

### A01:2021 — High (confidence: High, verification: unverified)

- **Location**: `api_views/books.py:44-56`
- **OWASP reference**: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- **Patch file**: ``

**Description**

When vuln==1, get_by_title() looks up a book by title only, without checking that the authenticated user is the owner. Any authenticated user can therefore retrieve the secret_content of any book belonging to any other user — a Broken Object Level Authorization (BOLA/IDOR) vulnerability.

**Exploit scenario**

Attacker registers their own account, logs in, and obtains a valid JWT. They then send a GET request to /books/v1/bookTitle77 (a book belonging to 'name1') with their own Bearer token. Because api_views/books.py line 46 queries only by book_title with no ownership check, the response contains the secret_content of the victim's book.

**Suggested fix**

Always scope the book query to the authenticated user: Book.query.filter_by(user=user, book_title=str(book_title)).first(), regardless of the vuln flag in production deployments.

---

### A01:2021 — High (confidence: High, verification: unverified)

- **Location**: `api_views/users.py:118-127`
- **OWASP reference**: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- **Patch file**: ``

**Description**

When vuln==1, update_password() uses the username from the URL path parameter to look up the target user rather than using the identity from the validated JWT token. Any authenticated user can therefore overwrite another user's (including the admin's) password by supplying a different username in the path.

**Exploit scenario**

Attacker registers an account 'evil', logs in, and receives a valid JWT. They send a PUT request to /users/v1/admin/password with JSON body {"password": "hacked"} and their own Bearer token. In api_views/users.py line 121, the vuln branch resolves the user by the path parameter 'admin' instead of the token subject, so the admin password is overwritten. The attacker then logs in as admin.

**Suggested fix**

Always derive the target user from the verified token subject (resp['sub']) rather than from the URL parameter, regardless of the vuln flag.

---

### A01:2021 — High (confidence: High, verification: unverified)

- **Location**: `api_views/users.py:37-55`
- **OWASP reference**: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- **Patch file**: ``

**Description**

When vuln==1, the register_user() endpoint accepts a caller-supplied 'admin' field in the JSON body and uses its value to set the admin flag on the newly created account. An unauthenticated user can register themselves as an administrator by including "admin": true in the registration request.

**Exploit scenario**

An attacker sends a POST request to /users/v1/register with the JSON body {"username": "evil", "password": "evil", "email": "evil@evil.com", "admin": true}. In api_views/users.py lines 41-44, the vuln branch reads request_data['admin'] and sets admin=True on the new User object. The attacker then logs in as 'evil' and uses the admin token to call DELETE /users/v1/name1, wiping legitimate accounts.

**Suggested fix**

Remove the ability for users to self-assign the admin role. Admin elevation should only be possible through a privileged, separately authenticated management operation. Never trust client-supplied role/privilege fields.

---

### A02:2021 — High (confidence: High, verification: unverified)

- **Location**: `config.py:10`
- **OWASP reference**: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- **Patch file**: ``

**Description**

The Flask/JWT SECRET_KEY is hardcoded as the trivially guessable string 'random'. Any attacker who knows (or guesses) this value can forge valid HS256 JWT tokens for any username, including admin, without ever authenticating.

**Exploit scenario**

An attacker reads config.py (or the public repository) and notes SECRET_KEY = 'random'. They craft a JWT payload {"sub": "admin", "iat": <now>, "exp": <now+3600>} and sign it with HS256 using the key 'random'. They include this forged token as a Bearer header in a DELETE /users/v1/name1 request. The token_validator in api_views/users.py decodes it successfully, granting full admin access.

**Suggested fix**

Generate a cryptographically random secret at deployment time (e.g., secrets.token_hex(32)) and supply it via an environment variable. Never hardcode secret keys in source code.

---

### A02:2021 — High (confidence: High, verification: unverified)

- **Location**: `models/user_model.py:14`
- **OWASP reference**: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
- **Patch file**: ``

**Description**

User passwords are stored as plain text in the database (the password column is a plain String column with no hashing). A database read (e.g., via the SQL injection vulnerability or the /users/v1/_debug endpoint) exposes all user passwords in cleartext.

**Exploit scenario**

An attacker exploits the SQL injection in models/user_model.py get_user() with a UNION-based payload to read the users table, or simply calls GET /users/v1/_debug (an unauthenticated endpoint). The response from the debug endpoint returns each user's password field in plaintext (as shown in json_debug()), e.g. {"username": "admin", "password": "pass1", ...}, giving the attacker immediate credential access to all accounts.

**Suggested fix**

Hash passwords using bcrypt or argon2 before storing them. Verify passwords using the corresponding constant-time comparison function. Never store or compare plaintext passwords.

---

### A05:2021 — Medium (confidence: High, verification: unverified)

- **Location**: `api_views/users.py:138-158`
- **OWASP reference**: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- **Patch file**: ``

**Description**

When vuln==1, the update_email() endpoint uses a ReDoS-vulnerable regular expression to validate the email address. A specially crafted input can cause catastrophic backtracking, leading to denial-of-service by exhausting CPU on the server-side regex engine.

**Exploit scenario**

An authenticated attacker sends a PUT request to /users/v1/anyuser/email with the JSON body {"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@"} — a string crafted to trigger catastrophic backtracking in the regex on line 141 of api_views/users.py. The call to re.search() enters a near-infinite loop, pegging one CPU core and making the API unresponsive for all concurrent users until the process is restarted.

**Suggested fix**

Replace the vulnerable regex with a simple, non-backtracking email validation (e.g., a single anchored pattern without nested quantifiers) or use a well-tested library such as 'email-validator'. Alternatively, remove the vuln branch entirely for production deployments.

---

### A05:2021 — Medium (confidence: High, verification: unverified)

- **Location**: `app.py:14`
- **OWASP reference**: https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
- **Patch file**: ``

**Description**

The Flask application is started with debug=True, which enables the Werkzeug interactive debugger. If an unhandled exception occurs, any client that can reach port 5000 can execute arbitrary Python code via the debugger's REPL.

**Exploit scenario**

The Docker container exposes port 5000 with app.py running vuln_app.run(host='0.0.0.0', port=5000, debug=True). An attacker triggers an unhandled exception (e.g., by sending a malformed request that bypasses the jsonschema catch-all). The Werkzeug debugger page is returned, including an interactive Python console. The attacker uses this console to execute os.system('id') or read /etc/passwd, achieving unauthenticated remote code execution on the container.

**Suggested fix**

Set debug=False in production. Control the debug flag via an environment variable and default it to False. Use a production WSGI server (gunicorn, uWSGI) rather than the Flask development server.

---

*Findings: 12*

