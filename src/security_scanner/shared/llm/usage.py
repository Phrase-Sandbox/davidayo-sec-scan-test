"""LLM token usage accumulator.

Each ``ClaudeClient`` / ``GeminiClient`` instance owns one accumulator.
Because clients are built **per request** (never cached between requests),
the accumulator is automatically reset between scans — there is no risk of
cross-scan contamination.

Usage objects are propagated from the client → pipeline → ``ScanResult``
→ database persistence, giving the portal a full audit trail of every scan's
LLM cost.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LLMUsage:
    """Token usage accumulated across all LLM calls in one scan.

    Anthropic exposes separate cache-creation / cache-read counters;
    Gemini does not — those fields stay 0 for Google scans.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    n_calls: int = 0
    # Provider response IDs for user cross-reference (e.g. "msg_01ABC").
    # Anthropic: response.id; Gemini: Candidate.content.parts[0].thought_id
    # (not always present) — we keep whatever the SDK exposes.
    response_ids: list[str] = field(default_factory=list)

    def add(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_creation_input_tokens: int = 0,
        cache_read_input_tokens: int = 0,
        response_id: str | None = None,
    ) -> None:
        """Accumulate one API-call's usage into this object."""
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.cache_creation_input_tokens += cache_creation_input_tokens
        self.cache_read_input_tokens += cache_read_input_tokens
        self.n_calls += 1
        if response_id:
            self.response_ids.append(response_id)

    @property
    def response_ids_csv(self) -> str:
        """Comma-separated response IDs for DB storage."""
        return ",".join(self.response_ids)
