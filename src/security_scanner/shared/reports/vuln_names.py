"""Canonical human-readable names for finding IDs used in reports.

IDs come from two sources:
- OWASP codes assigned by the LLM (A0X:2021, LLM0X:2025) via prompts/system.py
- Scanner-derived IDs: vuln_class.upper() fallback in verification/vulns.py

Names for OWASP Top 10 2021 are from owasp.org/Top10/.
Names for OWASP LLM Top 10 2025 are from genai.owasp.org.
"""

from __future__ import annotations

_VULN_ID_TO_NAME: dict[str, str] = {
    # OWASP Top 10 2021
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable & Outdated Components",
    "A07:2021": "Identification & Authentication Failures",
    "A08:2021": "Software & Data Integrity Failures",
    "A09:2021": "Security Logging & Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
    # OWASP LLM Top 10 2025
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
    # Custom / pipeline-set
    "SECRET-001": "Hardcoded Credential",
    # Scanner-derived IDs (vuln_class.upper()) — all taxonomy members from normalize.py
    "SQLI": "SQL Injection",
    "XSS": "Cross-Site Scripting",
    "COMMAND_INJECTION": "Command Injection",
    "PATH_TRAVERSAL": "Path Traversal",
    "SSRF": "Server-Side Request Forgery",
    "DESERIALIZATION": "Insecure Deserialization",
    "WEAK_CRYPTO": "Weak Cryptography",
    "XXE": "XML External Entity",
    "CSRF": "Cross-Site Request Forgery",
    "OPEN_REDIRECT": "Open Redirect",
    "AUTH_BYPASS": "Authentication Bypass",
    "CODE_INJECTION": "Code Injection",
    "INSECURE_RANDOM": "Insecure Randomness",
    "UNSAFE_YAML": "Unsafe YAML Deserialization",
    "UNSAFE_FILE_UPLOAD": "Unsafe File Upload",
    "INJECTION_GENERIC": "Injection",
    "REDOS": "Regular Expression DoS",
    "RUNTIME_PANIC": "Runtime Panic / DoS",
    "SUBPROCESS_USAGE": "Subprocess Usage",
    "INSECURE_NETWORK_CONFIG": "Insecure Network Configuration",
    "POOR_ERROR_HANDLING": "Poor Error Handling",
    "INFO_DISCLOSURE": "Information Disclosure",
    "INSECURE_DESIGN": "Insecure Design",
    "SECURITY_MISCONFIGURATION": "Security Misconfiguration",
    "VULNERABLE_COMPONENTS": "Vulnerable Components",
    "LOGGING_MONITORING_FAILURE": "Insufficient Logging & Monitoring",
    "MEMORY_SAFETY": "Memory Safety Issue",
    "LDAP_INJECTION": "LDAP Injection",
    "NOSQLI": "NoSQL Injection",
    "HARDCODED_SECRET": "Hardcoded Credential",
}


def vuln_display_name(vuln_id: str) -> str:
    """Return the canonical human-readable name for a vuln ID, or '' if unknown."""
    return _VULN_ID_TO_NAME.get(vuln_id, "")
