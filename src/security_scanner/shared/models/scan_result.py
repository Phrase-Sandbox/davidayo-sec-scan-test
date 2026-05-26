from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .enums import GateDecision, ScanTarget, ScanType
from .finding import VulnerabilityFinding


class ScanResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

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
    # LLM usage accumulated during this scan — populated by the pipeline and
    # persisted to scan_usage + llm_usage_monthly in the handler.
    # Not included in API responses (LocalScanResponse / gate ScanResult JSON).
    llm_usage: Any = Field(default=None, exclude=True)
