"""Normalisation tables: ``(tool, raw_rule_id) -> vuln_class``.

The vuln_class taxonomy is fixed — new tool mappings extend these tables;
the taxonomy itself does not change.  If a rule_id is unknown the tool name
is used as a best-effort class so the candidate still flows through the
pipeline rather than being silently dropped.

Taxonomy members
----------------
sqli, xss, command_injection, path_traversal, ssrf, deserialization,
weak_crypto, xxe, csrf, open_redirect, auth_bypass, code_injection,
insecure_random, unsafe_yaml, unsafe_file_upload, injection_generic,
redos, runtime_panic, subprocess_usage, insecure_network_config, poor_error_handling,
info_disclosure, insecure_design, security_misconfiguration, vulnerable_components,
logging_monitoring_failure, memory_safety, ldap_injection, nosqli

``injection_generic`` is the fallback for OWASP A03:2021 ("Injection") when
description-based inference in merge.py cannot identify the specific subtype.
It is purely internal — the OWASP ID (A03:2021) is preserved in the report.

``redos`` covers regex denial-of-service (catastrophic backtracking) — a DoS
risk distinct from code injection. No special verifier rubric; generic prompt applies.

``runtime_panic`` covers Go runtime panic / DoS issues (e.g. out-of-bounds slice
access, memory aliasing) that are distinct from injection or traversal vulnerabilities.

``subprocess_usage`` covers subprocess module imports — potential for shell execution
but not confirmed command injection until actual usage is observed (B404).

``insecure_network_config`` covers dangerous network binding (e.g. listen on all
interfaces) — exposure risk, not server-side request forgery.

``poor_error_handling`` covers unhandled or suppressed errors that may mask security
failures — broad Go/Python rule, evaluated generically by the verifier.

``info_disclosure`` covers endpoints or code paths that expose sensitive runtime or
internal data (e.g. pprof profiling endpoints, stack traces in responses).

``insecure_design`` maps OWASP A04:2021 — broad insecure design patterns that do not
fit a more specific injection or crypto class.

``security_misconfiguration`` maps OWASP A05:2021 — misconfigured security settings,
default credentials, or unnecessary features enabled.

``vulnerable_components`` maps OWASP A06:2021 — use of components with known
vulnerabilities; verifier evaluates exploitability in context.

``logging_monitoring_failure`` maps OWASP A09:2021 — insufficient logging or monitoring
that could allow attacks to go undetected.

``memory_safety`` covers Node.js buffer misuse and similar memory-padding / uninitialized
memory issues that are distinct from code injection.

``ldap_injection`` covers injection into LDAP directory queries (e.g. LDAP filter injection,
CWE-90) — distinct from SQL injection; targets directory services, not relational databases.

``nosqli`` covers injection into NoSQL document store queries (e.g. MongoDB operator
injection via $where/$ne, CWE-943) — targets document stores, not SQL databases.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Bandit (Python)
# ---------------------------------------------------------------------------
_BANDIT_MAP: dict[str, str] = {
    "B101": "code_injection",       # assert_used (not really a vuln_class but closest)
    "B102": "code_injection",       # exec_used
    "B103": "path_traversal",       # setting_nodev
    "B104": "insecure_network_config",  # hardcoded_bind_all_interfaces — 0.0.0.0 exposure, not SSRF
    "B105": "auth_bypass",          # hardcoded_password_string
    "B106": "auth_bypass",          # hardcoded_password_funcarg
    "B107": "auth_bypass",          # hardcoded_password_default
    "B108": "path_traversal",       # hardcoded_tmp_directory
    "B110": "auth_bypass",          # try_except_pass
    "B112": "auth_bypass",          # try_except_continue
    "B201": "security_misconfiguration",  # flask_debug_true — Werkzeug debugger, not injection
    "B301": "deserialization",      # pickle
    "B302": "deserialization",      # marshal
    "B303": "weak_crypto",          # md5
    "B304": "weak_crypto",          # des
    "B305": "weak_crypto",          # cipher
    "B306": "path_traversal",       # mktemp_q
    "B307": "code_injection",       # eval
    "B308": "xss",                  # mark_safe
    "B310": "ssrf",                 # urllib_urlopen
    "B311": "insecure_random",      # random
    "B312": "ssrf",                 # telnetlib
    "B313": "xxe",                  # xml_bad_cElementTree
    "B314": "xxe",                  # xml_bad_ElementTree
    "B315": "xxe",                  # xml_bad_expatreader
    "B316": "xxe",                  # xml_bad_expatbuilder
    "B317": "xxe",                  # xml_bad_sax
    "B318": "xxe",                  # xml_bad_minidom
    "B319": "xxe",                  # xml_bad_pulldom
    "B320": "xxe",                  # xml_bad_etree
    "B321": "ssrf",                 # ftp_lib
    "B322": "code_injection",       # input  (Python 2)
    "B323": "weak_crypto",          # unverified_context
    "B324": "weak_crypto",          # hashlib
    "B325": "insecure_random",      # tempnam
    "B401": "ssrf",                 # import_telnetlib
    "B402": "ssrf",                 # import_ftplib
    "B403": "deserialization",      # import_pickle
    "B404": "subprocess_usage",      # import_subprocess — import alone is not injection
    "B405": "xxe",                  # import_xml_etree
    "B406": "xxe",                  # import_xml_sax
    "B407": "xxe",                  # import_xml_expat
    "B408": "xxe",                  # import_xml_minidom
    "B409": "xxe",                  # import_xml_pulldom
    "B411": "ssrf",                 # import_xmlrpclib
    "B412": "ssrf",                 # import_httpoxy
    "B413": "weak_crypto",          # pycrypto
    "B501": "weak_crypto",          # request_with_no_cert_validation
    "B502": "weak_crypto",          # ssl_with_bad_version
    "B503": "weak_crypto",          # ssl_with_bad_defaults
    "B504": "weak_crypto",          # ssl_with_no_version
    "B505": "weak_crypto",          # weak_cryptographic_key
    "B202": "unsafe_file_upload",   # tarfile_unsafe_extract
    "B506": "unsafe_yaml",          # yaml_load
    "B507": "weak_crypto",           # ssh_no_host_key_verification — MITM/crypto risk, not SSRF
    "B601": "command_injection",    # paramiko_calls
    "B602": "command_injection",    # subprocess_popen_with_shell_equals_true
    "B603": "command_injection",    # subprocess_without_shell_equals_true
    "B604": "command_injection",    # any_other_function_with_shell_equals_true
    "B605": "command_injection",    # start_process_with_a_shell
    "B606": "command_injection",    # start_process_with_no_shell
    "B607": "command_injection",    # start_process_with_partial_path
    "B608": "sqli",                 # hardcoded_sql_expressions
    "B609": "command_injection",    # linux_commands_wildcard_injection
    "B610": "sqli",                 # django_extra_used
    "B611": "sqli",                 # django_rawsql_used
    "B701": "xss",                  # jinja2_autoescape_false
    "B702": "xss",                  # use_of_mako_templates
    "B703": "xss",                  # django_mark_safe
}

# ---------------------------------------------------------------------------
# gosec (Go)
# ---------------------------------------------------------------------------
_GOSEC_MAP: dict[str, str] = {
    "G101": "auth_bypass",          # hardcoded credentials
    "G102": "insecure_network_config",  # bind to all interfaces — exposure, not SSRF
    "G103": "code_injection",          # unsafe block
    "G104": "poor_error_handling",     # errors unhandled — broad; verifier checks impact
    "G106": "weak_crypto",          # ssh InsecureIgnoreHostKey
    "G107": "ssrf",                 # url provided to HTTP request as taint
    "G108": "info_disclosure",         # profiling endpoint — exposes runtime data, not traversal
    "G109": "code_injection",       # Potential Integer overflow
    "G110": "path_traversal",       # potential DoS (zip slip)
    "G111": "path_traversal",       # file path provided as taint
    "G112": "security_misconfiguration",  # ReadHeaderTimeout not configured — slowloris DoS
    "G113": "weak_crypto",          # Rat math/big
    "G114": "weak_crypto",          # deprecated ioutil
    "G201": "sqli",                 # SQL query construction using format string
    "G202": "sqli",                 # SQL query construction using string concatenation
    "G203": "xss",                  # Use of unescaped data in HTML templates
    "G204": "command_injection",    # Subprocess launched with variable
    "G301": "path_traversal",       # Poor file permissions used when creating a directory
    "G302": "path_traversal",       # Poor file permissions used with chmod
    "G303": "path_traversal",       # Creating tempfile using a predictable path
    "G304": "path_traversal",       # File path provided as taint input
    "G305": "path_traversal",       # File traversal when extracting zip/tar archive
    "G306": "path_traversal",       # Poor file permissions used when writing to a new file
    "G307": "path_traversal",       # Deferring a method which returns an error
    "G401": "weak_crypto",          # Use of weak cryptographic primitive (MD5/SHA1)
    "G402": "weak_crypto",          # TLS InsecureSkipVerify
    "G403": "weak_crypto",          # RSA key size < 2048
    "G404": "insecure_random",      # Use of weak random number generator (math/rand)
    "G405": "weak_crypto",          # Use of DES/3DES/RC4
    "G406": "weak_crypto",          # Use of MD4 or RIPEMD160
    "G407": "weak_crypto",          # Use of hardcoded IV/nonce
    "G501": "weak_crypto",          # Import blocklist: crypto/md5
    "G502": "weak_crypto",          # Import blocklist: crypto/des
    "G503": "weak_crypto",          # Import blocklist: crypto/rc4
    "G504": "deserialization",      # Import blocklist: net/http/cgi
    "G505": "weak_crypto",          # Import blocklist: crypto/sha1
    "G601": "runtime_panic",         # Implicit memory aliasing in for loop
    "G602": "runtime_panic",         # Slice access can cause a panic
}

# ---------------------------------------------------------------------------
# Semgrep (language-agnostic, using vendored rule IDs)
# ---------------------------------------------------------------------------
_SEMGREP_MAP: dict[str, str] = {
    # OWASP top-ten vendored rules — Python
    "python-sqli-fstring": "sqli",
    "python-sqli-string-format": "sqli",
    "python-sqli-concat": "sqli",
    "python-sqli-percent-format-assign": "sqli",
    "python-sqli-format-method": "sqli",
    "python-jinja2-autoescape-false": "xss",
    "jinja2-safe-filter": "xss",
    "python-eval-input": "code_injection",
    "python-exec-input": "code_injection",       # exec() arbitrary code execution (CWE-94)
    "python-os-system-input": "command_injection",
    "python-pickle-loads": "deserialization",
    "python-marshal-loads": "deserialization",    # marshal.loads() untrusted data (CWE-502)
    "python-xml-parse-no-defusedxml": "xxe",
    # OWASP top-ten vendored rules — JavaScript/TypeScript
    "js-innerhtml-assignment": "xss",            # innerHTML/outerHTML DOM XSS sink (CWE-79)
    "js-document-write": "xss",                  # document.write DOM XSS sink (CWE-79)
    "js-eval-input": "code_injection",           # eval() code injection (CWE-94)
    "js-dangerously-set-innerhtml": "xss",       # React dangerouslySetInnerHTML (CWE-79)
    "js-child-process-exec-concat": "command_injection",  # child_process.exec concat (CWE-78)
    # Security-audit vendored rules — Python
    "python-subprocess-shell-true": "command_injection",
    "python-hashlib-md5": "weak_crypto",
    "python-hashlib-sha1": "weak_crypto",
    "python-random-security": "insecure_random",
    "python-ssl-no-verify": "weak_crypto",        # TLS cert validation disabled (CWE-295)
    "python-requests-no-verify": "weak_crypto",   # requests verify=False (CWE-295, OWASP A02)
    "python-assert-auth": "auth_bypass",          # assert for auth stripped by -O (OWASP A01)
    "python-yaml-load-unsafe": "unsafe_yaml",     # yaml.load() unsafe Loader (CWE-502)
    "python-tempfile-insecure": "path_traversal", # TOCTOU tempfile race (CWE-377)
    # Security-audit vendored rules — JavaScript/TypeScript
    "js-localstorage-sensitive": "auth_bypass",    # sensitive tokens in localStorage (CWE-922)
    # Generic semgrep community IDs (r2c / p/owasp-top-ten etc.)
    "sql-injection": "sqli",
    "xss": "xss",
    "ssrf": "ssrf",
    "path-traversal": "path_traversal",
    "command-injection": "command_injection",
    "deserialization": "deserialization",
    "weak-crypto": "weak_crypto",
    "xxe": "xxe",
    "csrf": "csrf",
    "open-redirect": "open_redirect",
    "auth-bypass": "auth_bypass",
    "code-injection": "code_injection",
    "insecure-random": "insecure_random",
    "unsafe-yaml": "unsafe_yaml",
    # ssrf.yaml — Python SSRF
    "python-requests-ssrf": "ssrf",
    "python-urllib-ssrf": "ssrf",
    "python-urllib2-urlopen-ssrf": "ssrf",
    "python-httpx-ssrf": "ssrf",
    "python-aiohttp-ssrf": "ssrf",
    "python-requests-url-format": "ssrf",
    "python-requests-url-fstring": "ssrf",
    # ssrf.yaml — JS/TS SSRF
    "js-fetch-ssrf": "ssrf",
    "js-axios-ssrf": "ssrf",
    "js-node-http-ssrf": "ssrf",
    "js-node-https-ssrf": "ssrf",
    "js-got-ssrf": "ssrf",
    # ssrf.yaml — Ruby SSRF
    "ruby-net-http-ssrf": "ssrf",
    "ruby-open-uri-ssrf": "ssrf",
    # path-traversal.yaml — Python
    "python-open-path-traversal": "path_traversal",
    "python-open-concat-traversal": "path_traversal",
    "python-open-fstring-traversal": "path_traversal",
    "python-pathlib-traversal": "path_traversal",
    "python-send-file-traversal": "path_traversal",
    "python-send-from-directory-traversal": "path_traversal",
    "python-os-listdir-traversal": "path_traversal",
    "python-shutil-copy-traversal": "path_traversal",
    "python-os-path-join-user-input": "path_traversal",
    # path-traversal.yaml — JS/TS
    "js-fs-readfile-traversal": "path_traversal",
    "js-fs-readfilesync-traversal": "path_traversal",
    "js-fs-writefile-traversal": "path_traversal",
    "js-fs-createreadstream-traversal": "path_traversal",
    "js-path-join-traversal": "path_traversal",
    "js-express-res-download-traversal": "path_traversal",
    "js-express-res-sendfile-traversal": "path_traversal",
    # path-traversal.yaml — Ruby
    "ruby-file-read-traversal": "path_traversal",
    "ruby-file-open-traversal": "path_traversal",
    # injection.yaml — SSTI (Python)
    "python-render-template-string-ssti": "code_injection",
    "python-render-template-string-import-ssti": "code_injection",
    "python-jinja2-from-string-ssti": "code_injection",
    "python-jinja2-template-ssti": "code_injection",
    "python-mako-template-ssti": "code_injection",
    # injection.yaml — SSTI (JS)
    "js-handlebars-compile-ssti": "code_injection",
    "js-pug-compile-ssti": "code_injection",
    "js-ejs-render-ssti": "code_injection",
    "js-vm-runinthiscontext-ssti": "code_injection",
    "js-new-function-injection": "code_injection",
    # injection.yaml — header injection
    "python-flask-header-injection": "xss",
    "js-express-header-injection": "xss",
    "js-express-setHeader-injection": "xss",
    # injection.yaml — NoSQL injection (MongoDB document store — not SQL)
    "python-pymongo-nosql-injection": "nosqli",
    "js-mongoose-nosql-injection": "nosqli",
    # injection.yaml — LDAP injection (directory queries — not SQL)
    "python-ldap-injection": "ldap_injection",
    # injection.yaml — format_map injection
    "python-format-map-injection": "code_injection",
    # auth.yaml — JWT weaknesses
    "python-jwt-decode-no-verify": "auth_bypass",
    "python-jwt-decode-algorithms-none": "auth_bypass",
    "python-jwt-decode-complete-unverified": "auth_bypass",
    "python-python-jose-no-verify": "auth_bypass",
    "js-jwt-no-verify": "auth_bypass",
    "js-jwt-verify-algorithms-none": "auth_bypass",
    # auth.yaml — hardcoded secrets
    "python-flask-hardcoded-secret": "auth_bypass",
    "python-django-hardcoded-secret": "auth_bypass",
    "js-hardcoded-jwt-secret": "auth_bypass",
    "python-hardcoded-password-in-db-url": "auth_bypass",
    # auth.yaml — CORS
    "python-cors-wildcard-credentials": "auth_bypass",
    "python-cors-echo-origin": "auth_bypass",
    "js-cors-wildcard-credentials": "auth_bypass",
    "js-cors-echo-origin": "auth_bypass",
    # auth.yaml — timing attack, debug mode, cookies
    "python-timing-attack-password-compare": "auth_bypass",
    "python-flask-debug-mode": "security_misconfiguration",
    "python-django-debug-true": "security_misconfiguration",
    "python-flask-cookie-no-httponly": "auth_bypass",
    "python-flask-cookie-no-secure": "auth_bypass",
    # php.yaml — SQL injection
    "php-sqli-mysql-concat": "sqli",
    "php-sqli-mysqli-concat": "sqli",
    "php-sqli-pdo-exec-concat": "sqli",
    "php-sqli-variable-query": "sqli",
    # php.yaml — XSS
    "php-echo-xss-get": "xss",
    "php-echo-xss-post": "xss",
    "php-echo-xss-request": "xss",
    "php-print-xss": "xss",
    # php.yaml — LFI
    "php-lfi-include": "path_traversal",
    "php-lfi-require": "path_traversal",
    "php-lfi-include-once": "path_traversal",
    # php.yaml — command injection
    "php-cmd-injection-system": "command_injection",
    "php-cmd-injection-exec": "command_injection",
    "php-cmd-injection-shell-exec": "command_injection",
    "php-cmd-injection-passthru": "command_injection",
    "php-cmd-injection-popen": "command_injection",
    # php.yaml — code injection / deserialization / file upload
    "php-code-injection-eval": "code_injection",
    "php-create-function-injection": "code_injection",
    "php-deserialization-get": "deserialization",
    "php-file-upload-unsafe": "unsafe_file_upload",
    # php.yaml — misc
    "php-open-redirect": "open_redirect",
    "php-header-injection": "xss",
    "php-file-get-contents-traversal": "path_traversal",
    # java.yaml — SQL injection
    "java-sqli-statement-concat": "sqli",
    "java-sqli-string-format": "sqli",
    "java-sqli-jpa-concat": "sqli",
    # java.yaml — command injection
    "java-cmd-injection-runtime-exec": "command_injection",
    "java-cmd-injection-processbuilder": "command_injection",
    # java.yaml — path traversal
    "java-path-traversal-new-file": "path_traversal",
    "java-path-traversal-fileinputstream": "path_traversal",
    "java-path-traversal-paths-get": "path_traversal",
    # java.yaml — XXE
    "java-xxe-documentbuilder": "xxe",
    "java-xxe-saxparser": "xxe",
    "java-xxe-xmlinputfactory": "xxe",
    # java.yaml — deserialization / SSRF / redirect / XSS / LDAP / EL
    "java-deserialization-objectinputstream": "deserialization",
    "java-ssrf-url": "ssrf",
    "java-ssrf-url-read": "ssrf",
    "java-open-redirect": "open_redirect",
    "java-xss-printwriter": "xss",
    "java-ldap-injection": "ldap_injection",
    "java-el-injection": "code_injection",
    # java.yaml — weak crypto
    "java-weak-crypto-md5": "weak_crypto",
    "java-weak-crypto-sha1": "weak_crypto",
    "java-weak-cipher-des": "weak_crypto",
    "java-tls-insecure-skip-verify": "weak_crypto",
    # Prefix-based catch-all for registry rule IDs (p/owasp-top-ten etc.)
    # These use patterns like "python.lang.security.audit.sqli.*"
    # The normalize() prefix/substring logic handles the rest.
    "php-sqli": "sqli",           # prefix for any php-sqli-* variant
    "php-xss": "xss",
    "php-echo-xss": "xss",
    "php-lfi": "path_traversal",
    "php-cmd": "command_injection",
    "php-code-injection": "code_injection",
    "php-deserialization": "deserialization",
    "php-file-upload": "unsafe_file_upload",
    "php-header": "xss",
    "java-sqli": "sqli",
    "java-xxe": "xxe",
    "java-cmd": "command_injection",
    "java-path-traversal": "path_traversal",
    "java-deserialization": "deserialization",
    "java-ssrf": "ssrf",
    "java-xss": "xss",
    "java-ldap": "ldap_injection",
    "java-el": "code_injection",
    "java-weak": "weak_crypto",
    # upload-security.yaml rule IDs
    "upload-attacker-filename": "unsafe_file_upload",
    "upload-extension-only": "unsafe_file_upload",
    "upload-mime-only": "unsafe_file_upload",
    "upload-blocklist-ext": "unsafe_file_upload",
    "upload-webroot-storage": "unsafe_file_upload",
    "upload-no-size-limit": "unsafe_file_upload",
    "upload-zip-slip": "unsafe_file_upload",
    "upload-tar-slip": "unsafe_file_upload",
    "upload-risky-parser": "unsafe_file_upload",
    "unsafe-file-upload": "unsafe_file_upload",
    # Bandit rule IDs sometimes leak through as Semgrep raw IDs in test
    # fixtures and via consolidated reports.
    "B202": "unsafe_file_upload",
    # Catch-all upload- prefix so vendor-specific rule variants
    # (e.g. upload-attacker-filename-django, upload-webroot-storage-flask)
    # also map even when not enumerated explicitly. The prefix-iteration
    # in normalize() will pick this up via raw_rule_id.startswith("upload-").
    "upload-": "unsafe_file_upload",
}

# ---------------------------------------------------------------------------
# ESLint-security (JS/TS)
# ---------------------------------------------------------------------------
_ESLINT_MAP: dict[str, str] = {
    "security/detect-sql-literal-injection": "sqli",
    "security/detect-non-literal-regexp": "redos",
    "security/detect-non-literal-fs-filename": "path_traversal",
    "security/detect-non-literal-require": "code_injection",
    "security/detect-eval-with-expression": "code_injection",
    "security/detect-new-buffer": "memory_safety",
    "security/detect-no-csrf-before-method-override": "csrf",
    "security/detect-possible-timing-attacks": "auth_bypass",
    "security/detect-pseudoRandomBytes": "insecure_random",
    "security/detect-unsafe-regex": "redos",
    "security/detect-buffer-noassert": "memory_safety",
    "security/detect-child-process": "command_injection",
    "security/detect-disable-mustache-escape": "xss",
    "security/detect-object-injection": "auth_bypass",
    "no-unsanitized/method": "xss",
    "no-unsanitized/property": "xss",
}

# ---------------------------------------------------------------------------
# Master lookup: (tool, raw_rule_id) → vuln_class
# ---------------------------------------------------------------------------
_TOOL_MAPS: dict[str, dict[str, str]] = {
    "bandit": _BANDIT_MAP,
    "gosec": _GOSEC_MAP,
    "semgrep": _SEMGREP_MAP,
    "eslint": _ESLINT_MAP,
}


# ---------------------------------------------------------------------------
# OWASP ID → vuln_class mapping (for Claude finding normalization in merge.py)
# ---------------------------------------------------------------------------
_OWASP_MAP: dict[str, str] = {
    "a01:2021": "auth_bypass",       # Broken Access Control
    "a02:2021": "weak_crypto",       # Cryptographic Failures
    "a03:2021": "injection_generic",  # Injection — specific class inferred in merge.py
    "a04:2021": "insecure_design",              # Insecure Design
    "a05:2021": "security_misconfiguration",    # Security Misconfiguration
    "a06:2021": "vulnerable_components",        # Vulnerable and Outdated Components
    "a07:2021": "auth_bypass",                  # Identification and Authentication Failures
    "a08:2021": "deserialization",              # Software and Data Integrity Failures
    "a09:2021": "logging_monitoring_failure",   # Security Logging and Monitoring Failures
    "a10:2021": "ssrf",              # SSRF
    "secret-001": "weak_crypto",     # hardcoded credential
}

# Add OWASP map to the tool maps so normalize() can handle it.
_TOOL_MAPS["owasp"] = _OWASP_MAP


def normalize(tool: str, raw_rule_id: str) -> str:
    """Return the canonical vuln_class for the given tool/rule combination.

    Falls back to the raw_rule_id (lowercased, spaces→underscores) when no
    mapping is found, so unknown rules still flow through rather than being
    silently dropped.
    """
    tool_map = _TOOL_MAPS.get(tool.lower(), {})
    # Exact match first.
    if raw_rule_id in tool_map:
        return tool_map[raw_rule_id]
    # Prefix match — semgrep rule IDs are often ``<prefix>.<check-name>``.
    for key, vuln_class in tool_map.items():
        if raw_rule_id.startswith(key) or key in raw_rule_id:
            return vuln_class
    # Last resort: return a sanitised version of the raw id.
    return raw_rule_id.lower().replace(" ", "_").replace("-", "_")
