"""Pluggable LLM-provider seam (Appendix D-15 — DEVIATION, pending sign-off).

The scanner is spec-mandated to use Anthropic Claude (§7.2/§8.3, with a
confirmed ZDR agreement + DPA). This package adds a provider-abstraction
seam so the *local simulation* can also route to Google — selected
by env var, **defaulting to Anthropic so production behaviour is unchanged**.

DATA GOVERNANCE: the ZDR/DPA guarantees in §8.3 are confirmed for Anthropic
ONLY. Selecting a non-Anthropic provider sends filtered source code to a
provider without a confirmed zero-retention agreement — it is sim-only, off
by default, loudly warned, and pending Security/Legal sign-off (D-15).
"""

from security_scanner.shared.llm.base import LLMClient, LLMConfigError
from security_scanner.shared.llm.parsing import LLMResponseError, parse_findings

__all__ = [
    "LLMClient",
    "LLMConfigError",
    "LLMResponseError",
    "parse_findings",
]
