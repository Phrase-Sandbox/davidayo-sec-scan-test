"""The provider-agnostic client contract the pipeline already duck-types.

``ScanPipeline`` only ever calls ``.analyse(files)`` (returns the raw
findings list) and ``.ask(system_prompt, user_message)`` (the BR-009 blind
verification pass). Any provider client that satisfies this Protocol is a
drop-in. ``ClaudeClient`` already conforms unchanged; ``GeminiClient``
implements the same surface.

Transport failures from the non-Claude clients raise the *existing*
``ClaudeUnavailableError`` / ``ClaudeTimeoutError`` and (via
``parse_findings`` ``error_cls``) ``ClaudeResponseError`` so the pipeline's
proven error handling needs no change — those types are the canonical
"LLM transport/parse error" the pipeline understands (renaming them is a
separate, out-of-scope refactor). ``LLMConfigError`` is raised *before* any
client is built (bad/unknown provider, missing key) and is a startup/config
fault, distinct from a runtime transport fault.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class LLMConfigError(Exception):
    """Provider selection/config is invalid (unknown provider, missing key).

    Raised by the factory before a client exists — a fail-fast config fault,
    not a runtime transport error.
    """


@runtime_checkable
class LLMClient(Protocol):
    """Minimal contract the scan pipeline depends on."""

    def analyse(self, files: dict[str, str]) -> list[dict]:
        """Send the wrapped files to the model; return the parsed findings."""
        ...

    def ask(self, system_prompt: str, user_message: str) -> str:
        """Send a one-off prompt; return the raw text reply (BR-009)."""
        ...

    async def analyse_async(self, files: dict[str, str]) -> list[dict]:
        """Async variant of ``analyse`` — delegates to a thread-pool worker."""
        ...

    async def ask_async(self, system: str, user: str) -> str:
        """Async variant of ``ask`` — delegates to a thread-pool worker."""
        ...
