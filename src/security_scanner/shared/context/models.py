"""Data models for cross-file context bundles.

All dataclasses are frozen (immutable) so they can be safely shared across
concurrent workers without locking.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RouteInfo:
    """A single route definition detected in the codebase."""

    file: str
    """File path where the route is defined."""

    line: int
    """1-based line number of the route decorator / registration."""

    method: str
    """HTTP method (GET, POST, PUT, DELETE, PATCH, ANY, …)."""

    path: str
    """URL path pattern (e.g. ``/users/<id>``)."""

    handler: str
    """Name of the handler function."""


@dataclass(frozen=True)
class MiddlewareInfo:
    """A single middleware / decorator observed above a handler."""

    file: str
    """File path where the middleware is applied."""

    line: int
    """1-based line number of the decorator or ``app.use`` call."""

    name: str
    """Middleware / decorator name (e.g. ``login_required``, ``Depends(get_current_user)``)."""

    kind: str
    """Category: ``decorator``, ``app.use``, ``Depends``, ``django_middleware``."""


@dataclass(frozen=True)
class CallerInfo:
    """A call-site that invokes the function under investigation."""

    file: str
    """File containing the call."""

    line: int
    """1-based line number of the call."""

    function_name: str
    """Name of the calling function (or ``<module>`` for top-level code)."""

    snippet: str
    """Up to 5 surrounding lines of context."""


@dataclass(frozen=True)
class CalleeInfo:
    """A function/helper called from within the candidate snippet window."""

    name: str
    """Name of the callee (e.g. ``get_user``, ``find_record_by_id``)."""

    kind: str
    """Category: ``db_query``, ``ownership_helper``, ``auth_check``, ``other``."""


@dataclass(frozen=True)
class OwnershipCheckInfo:
    """A detected ownership / permission check in the repo."""

    file: str
    """File where the check was found."""

    line: int
    """1-based line number."""

    pattern: str
    """The pattern that matched (e.g. ``WHERE user_id =``, ``has_permission``)."""

    identifier: str
    """The identifier being compared (e.g. ``user_id``, ``owner_id``)."""

    current_user_derived: bool
    """True if the RHS is derived from ``current_user.*`` (safe).
    False if it comes from an attacker-controllable parameter.
    """


@dataclass(frozen=True)
class ContextBundle:
    """All cross-file context gathered for a single candidate vulnerability."""

    file: str
    """Primary file of the candidate."""

    vuln_class: str
    """Vulnerability class (e.g. ``idor``, ``sqli``)."""

    snippet: str
    """The focused code snippet around the candidate lines."""

    route_definitions: tuple[RouteInfo, ...] = field(default_factory=tuple)
    """Routes that lead to the handler in the candidate file."""

    middleware_chain: tuple[MiddlewareInfo, ...] = field(default_factory=tuple)
    """Ordered middleware / decorators applied before the handler."""

    callers: tuple[CallerInfo, ...] = field(default_factory=tuple)
    """Call sites that invoke the function under investigation."""

    callees: tuple[CalleeInfo, ...] = field(default_factory=tuple)
    """Functions called from within the candidate snippet window."""

    ownership_checks: tuple[OwnershipCheckInfo, ...] = field(default_factory=tuple)
    """Ownership / permission checks found near the candidate."""
