from pydantic import BaseModel, Field

from .enums import Confidence, Severity, VerificationStatus


class VulnerabilityFinding(BaseModel):
    vulnerability_id: str
    severity: Severity
    confidence: Confidence
    cvss_band: str
    affected_file: str
    affected_lines: str | None = None
    description: str
    suggested_fix: str
    owasp_reference: str
    patch_file_path: str
    exploit_scenario: str
    verification_status: VerificationStatus = VerificationStatus.unverified
    # Multi-scanner fields — default-init so existing serialization is compatible.
    sources: list[str] = Field(default_factory=list)
    consensus_score: int = 0
    # v2: optional cross-file context summary for advisory_real findings.
    # Populated by candidate_to_finding when a ContextBundle was used.
    context_summary: str = ""
