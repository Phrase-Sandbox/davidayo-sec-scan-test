from enum import StrEnum


class Severity(StrEnum):
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"


class Confidence(StrEnum):
    High = "High"
    Medium = "Medium"
    Low = "Low"


class ScanType(StrEnum):
    on_demand = "on_demand"
    deployment_gate = "deployment_gate"


class ScanTarget(StrEnum):
    full_repo = "full_repo"
    diff = "diff"
    directory = "directory"


class VerificationStatus(StrEnum):
    verified = "verified"
    unverified = "unverified"
    conflicting = "conflicting"
    advisory_real = "advisory_real"


class GateDecision(StrEnum):
    # 'pass' is a Python keyword — member is pass_, value preserves the spec wording.
    pass_ = "pass"  # noqa: S105 — enum value, not a hardcoded password
    blocked = "blocked"
    bypassed = "bypassed"
    advisory = "advisory"
    scan_failed = "scan_failed"
