"""CandidateForVerification — unified view for the production-mode verifier.

After merging LLM findings with aggregated scanner candidates, the verifier
receives a list of these objects.  Every field from both sources is present;
fields absent in one source have sensible defaults.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CandidateForVerification(BaseModel):
    """Merged candidate sent to the production-mode vuln verifier."""

    # ---- Location fields (always populated) --------------------------------
    file: str
    """Relative path of the affected file."""

    line_start: int = 0
    """1-based start line (0 = unknown)."""

    line_end: int = 0
    """1-based end line (0 = unknown)."""

    vuln_class: str
    """Normalised vulnerability class (from scanner) or OWASP ID (from Claude)."""

    # ---- Claude fields (populated when Claude voted) -----------------------
    vulnerability_id: str = ""
    """OWASP vulnerability identifier from Claude's first pass."""

    severity: str = "Medium"
    """Severity label from Claude (or scanner hint if Claude absent)."""

    confidence: str = "Medium"
    """Confidence from Claude."""

    cvss_band: str = "4.0-6.9"
    """CVSS band from Claude."""

    description: str = ""
    """Human-readable description from Claude."""

    suggested_fix: str = ""
    """Suggested fix from Claude."""

    owasp_reference: str = ""
    """OWASP reference URL from Claude."""

    exploit_scenario: str = ""
    """Exploit scenario from Claude."""

    # ---- Multi-source fields -----------------------------------------------
    sources: list[str] = Field(default_factory=list)
    """Which sources (``claude``, ``semgrep``, ``bandit``, …) contributed."""

    consensus_score: int = 1
    """Number of distinct sources that flagged this location."""

    raw_rule_ids: list[str] = Field(default_factory=list)
    """Raw rule IDs from scanner tools."""

    scanner_message: str = ""
    """Message from the scanner tool (untrusted — defanged before LLM prompt)."""
