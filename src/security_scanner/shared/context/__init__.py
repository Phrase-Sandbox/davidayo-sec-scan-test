"""Cross-file context packager for the authz/IDOR-aware verifier.

Public API:

    from security_scanner.shared.context import ContextPackager, ContextBundle
"""

from security_scanner.shared.context.models import ContextBundle
from security_scanner.shared.context.packager import ContextPackager, is_high_risk_path

__all__ = ["ContextPackager", "ContextBundle", "is_high_risk_path"]
