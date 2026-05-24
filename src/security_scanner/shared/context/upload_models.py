"""Data models for upload-flow context bundles.

All types are immutable (frozen dataclass / NamedTuple) so they can be
shared safely across concurrent workers without locking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NamedTuple


class UploadHandler(NamedTuple):
    """A single upload handler detected in the codebase."""

    file: str
    """Relative file path where the upload handler was found."""

    line: int
    """1-based line number of the upload trigger."""

    function_name: str
    """Name of the enclosing function (or ``<module>`` for top-level code)."""

    framework: str
    """Detected framework: ``flask``, ``fastapi``, ``django``, ``express``,
    ``multer``, ``busboy``, ``formidable``, ``gin``, ``go_multipart``,
    or ``unknown``."""


@dataclass(frozen=True)
class UploadContext:
    """All upload-flow context gathered for a single candidate vulnerability.

    Each field is a list of short human-readable strings so the verifier can
    render them as a compact labelled block.  Empty lists mean "not detected"
    — they are omitted from the rendered block to keep the prompt lean.
    """

    route_summary: list[str] = field(default_factory=list)
    """Route definitions that lead to the upload handler."""

    middleware_summary: list[str] = field(default_factory=list)
    """Auth/authz middleware / decorators applied before the handler."""

    authz_signals: list[str] = field(default_factory=list)
    """Ownership / permission checks found near the handler."""

    filename_handling: list[str] = field(default_factory=list)
    """How the uploaded filename is handled: ``preserved``, ``server-generated``,
    ``renamed``, or ``unknown``."""

    validation_signals: list[str] = field(default_factory=list)
    """Detected validation: ``extension-allowlist``, ``MIME-only``,
    ``magic-bytes``, ``blocklist``, or ``none``."""

    size_limit_signals: list[str] = field(default_factory=list)
    """Size / count limit evidence: ``yes`` or ``none``."""

    storage_signals: list[str] = field(default_factory=list)
    """Storage destination classification: ``public-path``,
    ``outside-webroot``, or ``unknown``."""

    retrieval_signals: list[str] = field(default_factory=list)
    """Retrieval patterns: ``direct-by-filename``, ``safe-serve``,
    or ``none``."""

    post_processing_signals: list[str] = field(default_factory=list)
    """Post-upload processing: ``archive-extract``, ``risky-parser``,
    or ``none``."""

    overall_summary: str = ""
    """Compact one-liner for reports, e.g.
    ``Validation: extension-allowlist | Naming: server-generated | Storage: outside-webroot``."""
