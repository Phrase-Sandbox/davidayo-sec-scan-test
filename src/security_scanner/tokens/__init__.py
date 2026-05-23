"""Per-user LOCAL_SCAN_TOKEN registry + audit + portal/admin UI.

Phase 1 surface (this PR):
- ``db``        — SQLAlchemy async engine + session factory.
- ``models``    — ORM models for ``local_scan_tokens`` and ``audit_events``.
- ``registry``  — Pure functions: verify, issue/rotate, revoke, force_rotate, list.
- ``audit``     — Dual-write helper (DB row + structured log line).

Phases 2–4 add the routers (``portal``, ``admin_panel``), Jinja templates,
and the ``X-Userinfo`` auth deps. The Phase 1 code carries no routes and is
inert behind ``settings.USE_TOKEN_REGISTRY=False``.
"""
