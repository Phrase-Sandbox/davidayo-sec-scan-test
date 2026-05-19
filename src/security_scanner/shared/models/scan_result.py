from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .enums import GateDecision, ScanTarget, ScanType
from .finding import VulnerabilityFinding


class ScanResult(BaseModel):
    scan_id: UUID = Field(default_factory=uuid4)
    repo_url: str
    scan_target: ScanTarget
    scan_type: ScanType
    triggered_by: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    findings_count: int = 0
    gate_decision: GateDecision = GateDecision.advisory
    bypass_invoked: bool = False
    partial_scan: bool = False
    unscanned_files: list[str] = Field(default_factory=list)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    patches: dict[str, str] = Field(default_factory=dict)
