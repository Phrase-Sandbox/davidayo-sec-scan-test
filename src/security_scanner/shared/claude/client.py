"""Anthropic Claude API client (spec §7.2).

Builds the system prompt + user message via
``security_scanner.shared.prompts.system``, calls the Anthropic API with
retries / circuit-breaker / rate-limit handling, and returns the raw parsed
finding list. Downstream validation lives in
``security_scanner.shared.validation``.

Hard rules from §7.2 and §5 (EC-001..EC-004):
- Model: ``claude-sonnet-4-20250514`` (§8.3).
- 30 s per-request timeout (EC-004). Times out fail-fast — caller marks
  ``partial_scan = true`` if mid-scan.
- 3 attempts with 1 s / 2 s / 4 s exponential backoff.
- 429 honours ``Retry-After`` (EC-003).
- 5xx and connection errors trigger backoff + retry (EC-001).
- Circuit breaker — open after 5 consecutive failures, 60 s recovery, close
  after 3 consecutive successes.
- API key loaded from config only — never hardcoded.
- **Never log prompt content, source code, or response content.** Token
  counts, model name, status codes, and latency are the only allowed fields.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Callable
from typing import Any

import anthropic

from security_scanner.shared.llm.parsing import parse_findings
from security_scanner.shared.llm.usage import LLMUsage
from security_scanner.shared.logging_util import get_logger
from security_scanner.shared.prompts.system import (
    build_system_prompt,
    build_user_message,
)

log = get_logger(__name__)

# Spec §8.3 mandates claude-sonnet-4-20250514 in the Phrase Enterprise
# environment. CLAUDE_MODEL is an optional override for local simulation,
# where a personal API key does not have access to that Enterprise-only
# model. When CLAUDE_MODEL is unset (production / Phrase), the spec model is
# used unchanged — production behaviour is not affected.
DEFAULT_MODEL = os.getenv("CLAUDE_MODEL") or "claude-sonnet-4-20250514"
# Max output tokens for the findings JSON. If the model's reply exceeds this
# it is truncated mid-JSON and the scan fails to parse (scan_failed).
# 8192 is the safe default: repos with 15+ findings per chunk no longer
# truncate. CLAUDE_MAX_TOKENS overrides (set to 16384 in docker-compose
# to match GEMINI_MAX_TOKENS for large CLAUDE_CHUNK_SIZE=48 batches).
DEFAULT_MAX_TOKENS = int(os.getenv("CLAUDE_MAX_TOKENS") or 8192)
# Spec §5 EC-004 mandates a 30 s per-request timeout against Phrase's
# provisioned Enterprise Claude throughput. CLAUDE_TIMEOUT_SECONDS is an
# optional override for local simulation, where a personal API key is slower
# and a multi-file analysis exceeds 30 s. Unset (production / Phrase) keeps
# the spec's 30 s — production behaviour is not affected.
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("CLAUDE_TIMEOUT_SECONDS") or 30.0)
# Number of files to send to Claude in a single parallel chunk.  Splitting the
# file dict into N chunks and running them concurrently via asyncio.gather()
# reduces wall-clock time on large repos.  CLAUDE_CHUNK_SIZE=0 disables
# chunking (falls back to a single call).  The docker-compose default is 12.
CLAUDE_CHUNK_SIZE = int(os.environ.get("CLAUDE_CHUNK_SIZE", "12"))
MAX_ATTEMPTS = 3
BACKOFF_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)

CB_FAILURE_THRESHOLD = 5
CB_RECOVERY_TIMEOUT_SECONDS = 60.0
CB_SUCCESS_THRESHOLD = 3


class ClaudeError(Exception):
    """Base class for Claude client errors."""


class ClaudeUnavailableError(ClaudeError):
    """Service unavailable after retries or via circuit breaker.

    Gate path (BR-006): caller logs + allows deployment to proceed.
    Skill path (EC-002): caller surfaces "scan service temporarily unavailable".
    """


class ClaudeCircuitOpenError(ClaudeUnavailableError):
    """Circuit breaker open — calls short-circuited until recovery timeout."""


class ClaudeTimeoutError(ClaudeError):
    """30 s per-request timeout exceeded (EC-004).

    Caller marks ``partial_scan = true`` and reports findings collected so far.
    """


class ClaudeResponseError(ClaudeError):
    """Response was not parseable as the expected JSON structure."""


class _CircuitBreaker:
    STATE_CLOSED = "closed"
    STATE_OPEN = "open"
    STATE_HALF_OPEN = "half_open"

    def __init__(self, clock_fn: Callable[[], float]) -> None:
        self._clock = clock_fn
        self._state = self.STATE_CLOSED
        self._consecutive_failures = 0
        self._consecutive_successes_half_open = 0
        self._opened_at: float | None = None

    @property
    def state(self) -> str:
        return self._state

    def check(self) -> None:
        if self._state != self.STATE_OPEN:
            return
        elapsed = self._clock() - (self._opened_at or 0.0)
        if elapsed < CB_RECOVERY_TIMEOUT_SECONDS:
            remaining = CB_RECOVERY_TIMEOUT_SECONDS - elapsed
            raise ClaudeCircuitOpenError(
                f"Claude circuit breaker open; retry in {remaining:.0f}s"
            )
        self._state = self.STATE_HALF_OPEN
        self._consecutive_successes_half_open = 0

    def record_success(self) -> None:
        if self._state == self.STATE_HALF_OPEN:
            self._consecutive_successes_half_open += 1
            if self._consecutive_successes_half_open >= CB_SUCCESS_THRESHOLD:
                self._state = self.STATE_CLOSED
                self._consecutive_failures = 0
                self._consecutive_successes_half_open = 0
                self._opened_at = None
        else:
            self._consecutive_failures = 0

    def record_failure(self) -> None:
        if self._state == self.STATE_HALF_OPEN:
            self._state = self.STATE_OPEN
            self._opened_at = self._clock()
            self._consecutive_failures = 0
            self._consecutive_successes_half_open = 0
            return
        self._consecutive_failures += 1
        if self._consecutive_failures >= CB_FAILURE_THRESHOLD:
            self._state = self.STATE_OPEN
            self._opened_at = self._clock()


class ClaudeClient:
    """Anthropic Claude API client with retry, rate-limit, and circuit-breaker logic."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        anthropic_client: anthropic.Anthropic | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        clock_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        self._model = model
        self._max_tokens = max_tokens
        self._timeout = timeout
        # max_retries=0 because we drive retries ourselves.
        self._client = anthropic_client or anthropic.Anthropic(
            api_key=api_key,
            timeout=timeout,
            max_retries=0,
        )
        self._sleep = sleep_fn
        self._clock = clock_fn
        self._circuit_breaker = _CircuitBreaker(clock_fn)
        # Per-instance accumulator — reset per request because factory builds
        # a fresh client per scan (never cached across requests).
        self.usage = LLMUsage()

    # --- Public API ---------------------------------------------------------

    def analyse(
        self,
        files: dict[str, str],
        extra_instruction: str = "",
    ) -> list[dict]:
        """Send the wrapped files to Claude and return the parsed findings list.

        Parameters
        ----------
        extra_instruction:
            Optional instruction appended to the system prompt for this call
            only.  Used by the zero-findings retry to ask Claude to look harder.

        Raises
        ------
        ClaudeUnavailableError
            Retries exhausted or circuit breaker open.
        ClaudeTimeoutError
            Per-request 30 s timeout exceeded.
        ClaudeResponseError
            Response body was not parseable as the expected JSON shape.
        """
        system_prompt = build_system_prompt()
        if extra_instruction:
            system_prompt = system_prompt + "\n\n" + extra_instruction
        user_message = build_user_message(files)
        message = self._call_with_retry(system_prompt, user_message)
        return _parse_findings(self._extract_text(message))

    def ask(self, system_prompt: str, user_message: str) -> str:
        """Send a one-off prompt to Claude and return the raw text response.

        Used by callers that need a non-JSON protocol on top of the standard
        retry / circuit-breaker behaviour — currently the BR-009 blind
        verification pass in ``shared/verification/parallel.py``.
        """
        message = self._call_with_retry(system_prompt, user_message)
        return self._extract_text(message)

    # --- Async wrappers (thin asyncio.to_thread delegates) ------------------

    async def analyse_async(
        self,
        files: dict[str, str],
        extra_instruction: str = "",
    ) -> list[dict]:
        """Async wrapper around ``analyse`` for use in an event loop.

        Runs the blocking Anthropic SDK call in a thread-pool worker so the
        event loop is not blocked while waiting for the API response.
        """
        return await asyncio.to_thread(self.analyse, files, extra_instruction)

    async def analyse_async_chunked(
        self,
        files: dict[str, str],
        chunk_size: int = CLAUDE_CHUNK_SIZE,
        extra_instruction: str = "",
    ) -> tuple[list[dict], list[str]]:
        """Split ``files`` into chunks and run ``analyse_async`` on each in parallel.

        Returns a ``(raw_findings, partial_files)`` tuple where:
        - ``raw_findings`` is the concatenated findings from all successful chunks.
        - ``partial_files`` is the list of file names from chunks that timed out.
          The caller should add these to ``unscanned_files`` and set
          ``partial_scan=True``.

        Single-chunk fast path: if ``len(files) <= chunk_size``, delegates
        directly to ``analyse_async`` with no overhead.

        If a chunk raises ``ClaudeTimeoutError``, its files are appended to
        ``partial_files`` and processing continues.  Any other exception
        propagates as-is (e.g. ``ClaudeUnavailableError`` or
        ``ClaudeResponseError``).
        """
        effective_chunk_size = max(1, chunk_size) if chunk_size > 0 else len(files)

        # Fast path: fits in a single chunk. Route through the halve-retry
        # wrapper so a truncated-output parse error still gets one chance to
        # recover instead of dropping the whole scan.
        if len(files) <= effective_chunk_size:
            try:
                findings = await self._analyse_with_halving_retry(files, extra_instruction)
            except ClaudeResponseError as exc:
                log.warning(
                    "claude single-chunk parse error after halve-retry — files marked partial",
                    file_count=len(files),
                    reason=str(exc),
                )
                return [], list(files.keys())
            return findings, []

        # Split into chunks preserving insertion order.
        items = list(files.items())
        chunks: list[dict[str, str]] = []
        for i in range(0, len(items), effective_chunk_size):
            chunks.append(dict(items[i : i + effective_chunk_size]))

        log.info(
            "claude chunked analysis start",
            total_files=len(files),
            chunk_count=len(chunks),
            chunk_size=effective_chunk_size,
        )

        tasks = [
            asyncio.create_task(
                self._analyse_with_halving_retry(chunk, extra_instruction)
            )
            for chunk in chunks
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_findings: list[dict] = []
        partial_files: list[str] = []

        for chunk, result in zip(chunks, results, strict=False):
            if isinstance(result, ClaudeTimeoutError):
                log.warning(
                    "claude chunk timeout — files marked partial",
                    file_count=len(chunk),
                    reason=str(result),
                )
                partial_files.extend(chunk.keys())
            elif isinstance(result, ClaudeResponseError):
                # Parse error survived halve-retry. Mark this chunk's files
                # partial rather than failing the whole scan (the previous
                # behaviour was to propagate, which discarded findings from
                # ALL other chunks in the same gather).
                log.warning(
                    "claude chunk unparseable after halve-retry — files marked partial",
                    file_count=len(chunk),
                    reason=str(result),
                )
                partial_files.extend(chunk.keys())
            elif isinstance(result, Exception):
                # Propagate non-recoverable errors (unavailable, circuit-open, etc.)
                raise result
            else:
                raw_findings.extend(result)

        log.info(
            "claude chunked analysis complete",
            total_findings=len(raw_findings),
            partial_file_count=len(partial_files),
        )
        return raw_findings, partial_files

    async def ask_async(self, system: str, user: str) -> str:
        """Async wrapper around ``ask`` for use in an event loop."""
        return await asyncio.to_thread(self.ask, system, user)

    async def _analyse_with_halving_retry(
        self,
        chunk: dict[str, str],
        extra_instruction: str = "",
    ) -> list[dict]:
        """Run ``analyse_async`` on ``chunk``; on parse error, halve and retry once.

        Truncated-output JSON failures are size-driven (model hit the
        ``max_tokens`` ceiling mid-string). Halving the input reliably fits.
        If a half also fails to parse, we still return findings from the
        other half rather than dropping the whole chunk.
        """
        try:
            return await self.analyse_async(chunk, extra_instruction)
        except ClaudeResponseError as exc:
            if len(chunk) <= 1:
                # Can't halve further — propagate so the chunked loop can
                # mark this file partial.
                raise
            items = list(chunk.items())
            mid = len(items) // 2
            left = dict(items[:mid])
            right = dict(items[mid:])
            log.warning(
                "claude chunk parse error — halving and retrying",
                original_file_count=len(chunk),
                left_count=len(left),
                right_count=len(right),
                reason=str(exc),
            )
            results = await asyncio.gather(
                self.analyse_async(left, extra_instruction),
                self.analyse_async(right, extra_instruction),
                return_exceptions=True,
            )
            findings: list[dict] = []
            still_failed = 0
            for result in results:
                if isinstance(result, ClaudeResponseError):
                    still_failed += 1
                elif isinstance(result, Exception):
                    raise result from result
                else:
                    findings.extend(result)
            if still_failed == 2:
                raise ClaudeResponseError(
                    f"both halves of chunk ({len(chunk)} files) failed to parse"
                ) from exc
            return findings

    # --- Internals ----------------------------------------------------------

    def _call_with_retry(self, system_prompt: str, user_message: str) -> Any:
        self._circuit_breaker.check()

        last_error_summary = "unknown error"
        start = self._clock()

        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._client.messages.create(
                    model=self._model,
                    max_tokens=self._max_tokens,
                    system=[{
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }],
                    messages=[{"role": "user", "content": user_message}],
                )
            except anthropic.APITimeoutError as exc:
                self._circuit_breaker.record_failure()
                raise ClaudeTimeoutError(
                    f"Claude request exceeded {self._timeout}s timeout"
                ) from exc
            except anthropic.RateLimitError as exc:
                retry_after = _retry_after_seconds(exc)
                log.warning(
                    "claude rate-limited",
                    model=self._model,
                    status_code=429,
                    retry_after=retry_after,
                )
                self._sleep(retry_after)
                last_error_summary = f"rate limited (429); waited {retry_after}s"
                continue
            except anthropic.APIStatusError as exc:
                status = exc.status_code
                if 500 <= status < 600:
                    log.warning(
                        "claude server error", model=self._model, status_code=status
                    )
                    self._sleep(BACKOFF_SECONDS[attempt])
                    last_error_summary = f"server error {status}"
                    continue
                self._circuit_breaker.record_failure()
                raise ClaudeUnavailableError(f"Claude returned {status}") from exc
            except anthropic.APIConnectionError as exc:
                log.warning("claude connection error", model=self._model)
                self._sleep(BACKOFF_SECONDS[attempt])
                last_error_summary = f"connection error: {exc!r}"
                continue

            latency = self._clock() - start
            usage = getattr(response, "usage", None)
            _input = getattr(usage, "input_tokens", 0) or 0
            _output = getattr(usage, "output_tokens", 0) or 0
            _cache_create = getattr(usage, "cache_creation_input_tokens", 0) or 0
            _cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
            log.info(
                "claude call complete",
                model=self._model,
                latency_seconds=round(latency, 3),
                input_tokens=_input,
                output_tokens=_output,
            )
            self.usage.add(
                input_tokens=_input,
                output_tokens=_output,
                cache_creation_input_tokens=_cache_create,
                cache_read_input_tokens=_cache_read,
                response_id=getattr(response, "id", None),
            )
            self._circuit_breaker.record_success()
            return response

        self._circuit_breaker.record_failure()
        raise ClaudeUnavailableError(
            f"Claude unavailable after {MAX_ATTEMPTS} attempts: {last_error_summary}"
        )

    @staticmethod
    def _extract_text(message: Any) -> str:
        blocks = getattr(message, "content", []) or []
        parts: list[str] = []
        for block in blocks:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts)


def _retry_after_seconds(exc: anthropic.RateLimitError) -> float:
    response = getattr(exc, "response", None)
    if response is None:
        return 1.0
    headers = getattr(response, "headers", {}) or {}
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if raw is None:
        return 1.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 1.0


def _parse_findings(text: str) -> list[dict]:
    """Parse Claude's response into a list of finding dicts.

    Thin wrapper over the shared provider-agnostic parser (D-15). The logic
    is unchanged; ``ClaudeResponseError`` is injected so this path keeps
    raising its own exception type — the existing client tests are the
    behaviour regression guard.
    """
    return parse_findings(text, error_cls=ClaudeResponseError)
