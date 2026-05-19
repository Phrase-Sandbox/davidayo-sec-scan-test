from pydantic import BaseModel

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
