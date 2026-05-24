"""Normalisation tables: ``(tool, raw_rule_id) -> vuln_class``.

The vuln_class taxonomy is fixed — new tool mappings extend these tables;
the taxonomy itself does not change.  If a rule_id is unknown the tool name
is used as a best-effort class so the candidate still flows through the
pipeline rather than being silently dropped.

Taxonomy members
----------------
sqli, xss, command_injection, path_traversal, ssrf, deserialization,
weak_crypto, xxe, csrf, open_redirect, auth_bypass, code_injection,
insecure_random, unsafe_yaml, unsafe_file_upload
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Bandit (Python)
# ---------------------------------------------------------------------------
_BANDIT_MAP: dict[str, str] = {
    "B101": "code_injection",       # assert_used (not really a vuln_class but closest)
    "B102": "code_injection",       # exec_used
    "B103": "path_traversal",       # setting_nodev
    "B104": "ssrf",                 # hardcoded_bind_all_interfaces
    "B105": "auth_bypass",          # hardcoded_password_string
    "B106": "auth_bypass",          # hardcoded_password_funcarg
    "B107": "auth_bypass",          # hardcoded_password_default
    "B108": "path_traversal",       # hardcoded_tmp_directory
    "B110": "auth_bypass",          # try_except_pass
    "B112": "auth_bypass",          # try_except_continue
    "B201": "code_injection",       # flask_debug_true
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
    "B404": "command_injection",    # import_subprocess
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
    "B507": "ssrf",                 # ssh_no_host_key_verification
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
    "B701": "code_injection",       # jinja2_autoescape_false
    "B702": "xss",                  # use_of_mako_templates
    "B703": "xss",                  # django_mark_safe
}

# ---------------------------------------------------------------------------
# gosec (Go)
# ---------------------------------------------------------------------------
_GOSEC_MAP: dict[str, str] = {
    "G101": "auth_bypass",          # hardcoded credentials
    "G102": "ssrf",                 # bind to all interfaces
    "G103": "code_injection",       # unsafe block
    "G104": "auth_bypass",          # errors unhandled
    "G106": "weak_crypto",          # ssh InsecureIgnoreHostKey
    "G107": "ssrf",                 # url provided to HTTP request as taint
    "G108": "path_traversal",       # profiling endpoint
    "G109": "code_injection",       # Potential Integer overflow
    "G110": "path_traversal",       # potential DoS (zip slip)
    "G111": "path_traversal",       # file path provided as taint
    "G112": "path_traversal",       # ReadHeaderTimeout not configured
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
    "G601": "path_traversal",       # Implicit memory aliasing in for loop
    "G602": "code_injection",       # Slice access can cause a panic
}

# ---------------------------------------------------------------------------
# Semgrep (language-agnostic, using vendored rule IDs)
# ---------------------------------------------------------------------------
_SEMGREP_MAP: dict[str, str] = {
    # OWASP top-ten vendored rules
    "python-sqli-string-format": "sqli",
    "python-sqli-concat": "sqli",
    "python-eval-input": "code_injection",
    "python-os-system-input": "command_injection",
    "python-pickle-loads": "deserialization",
    "python-xml-parse-no-defusedxml": "xxe",
    # Security-audit vendored rules
    "python-subprocess-shell-true": "command_injection",
    "python-hashlib-md5": "weak_crypto",
    "python-hashlib-sha1": "weak_crypto",
    "python-random-security": "insecure_random",
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
    "security/detect-non-literal-regexp": "code_injection",
    "security/detect-non-literal-fs-filename": "path_traversal",
    "security/detect-non-literal-require": "code_injection",
    "security/detect-eval-with-expression": "code_injection",
    "security/detect-new-buffer": "code_injection",
    "security/detect-no-csrf-before-method-override": "csrf",
    "security/detect-possible-timing-attacks": "auth_bypass",
    "security/detect-pseudoRandomBytes": "insecure_random",
    "security/detect-unsafe-regex": "code_injection",
    "security/detect-buffer-noassert": "code_injection",
    "security/detect-child-process": "command_injection",
    "security/detect-disable-mustache-escape": "xss",
    "security/detect-object-injection": "code_injection",
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
    "a03:2021": "sqli",              # Injection (default to SQLi, most common)
    "a04:2021": "code_injection",    # Insecure Design
    "a05:2021": "code_injection",    # Security Misconfiguration
    "a06:2021": "code_injection",    # Vulnerable Components
    "a07:2021": "auth_bypass",       # Auth Failures
    "a08:2021": "deserialization",   # Software & Data Integrity Failures
    "a09:2021": "code_injection",    # Security Logging Failures
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
