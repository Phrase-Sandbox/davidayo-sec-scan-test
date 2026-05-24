"""Pydantic models for scanner candidates.

``ScannerCandidate`` is the raw, per-tool output.  After the consensus pass it
becomes an ``AggregatedCandidate`` with a ``consensus_score`` and a
``sources`` list showing which tools voted.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScannerCandidate(BaseModel):
    """Raw finding from a single scanner tool before consensus aggregation."""

    tool: str
    """Name of the tool that produced this candidate, e.g. ``semgrep``."""

    vuln_class: str
    """Normalised vulnerability class from the taxonomy in ``normalize.py``."""

    file: str
    """Relative path of the affected file inside the scan workspace."""

    line_start: int
    """1-based start line of the affected region."""

    line_end: int
    """1-based end line of the affected region (same as line_start for single-line)."""

    message: str
    """Human-readable description from the tool output."""

    raw_rule_id: str
    """Original rule/check identifier from the tool (e.g. ``B608``, ``G201``)."""

    severity_hint: str = "medium"
    """Tool's severity hint, e.g. ``high`` / ``medium`` / ``low`` (not binding)."""


class AggregatedCandidate(BaseModel):
    """Consensus-aggregated candidate after grouping overlapping tool votes."""

    vuln_class: str
    """Normalised vulnerability class."""

    file: str
    """Relative path of the affected file."""

    line_start: int
    """Consensus start line (min of all voters)."""

    line_end: int
    """Consensus end line (max of all voters)."""

    message: str
    """Message from the highest-priority (first) voter."""

    sources: list[str] = Field(default_factory=list)
    """Names of the tools that voted for this candidate."""

    consensus_score: int = 1
    """Number of distinct tools that agreed on this candidate."""

    raw_rule_ids: list[str] = Field(default_factory=list)
    """All raw rule IDs from all voters."""

    severity_hint: str = "medium"
    """Severity hint from the first voter."""
