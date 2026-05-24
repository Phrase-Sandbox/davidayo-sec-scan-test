"""Tests for ownership / permission check detector."""

from __future__ import annotations

import pytest

from security_scanner.shared.context.ownership_checks import scan_ownership_checks

# ---------------------------------------------------------------------------
# Positive cases
# ---------------------------------------------------------------------------

SQL_WITH_OWNERSHIP = """\
def get_document(doc_id, current_user):
    row = db.execute(
        "SELECT * FROM documents WHERE user_id = ? AND id = ?",
        current_user.id, doc_id
    )
    return row
"""

SQL_TENANT_FILTER = """\
query = "SELECT * FROM records WHERE tenant_id = :tenant AND id = :id"
"""

REQUIRE_ADMIN = """\
@require_admin
def delete_everything():
    pass
"""

HAS_PERMISSION = """\
def update(user, resource):
    if not has_permission(current_user, 'write', resource):
        raise PermissionDenied
"""

CURRENT_USER_CMP = """\
def view_record(record_id):
    record = Record.get(record_id)
    if record.owner_id != current_user.id:
        abort(403)
    return record
"""

FASTAPI_DEPENDS_CU = """\
async def read_item(
    item_id: int,
    current_user: User = Depends(get_current_user),
):
    pass
"""

# ---------------------------------------------------------------------------
# Negative cases (no real ownership gate)
# ---------------------------------------------------------------------------

SQL_NO_OWNERSHIP = """\
def get_all():
    return db.execute("SELECT * FROM docs WHERE 1=1")
"""

SQL_PARAMETERIZED_NO_OWNER = """\
def get_doc(doc_id):
    return db.execute("SELECT * FROM docs WHERE id = ?", doc_id)
"""


# ---------------------------------------------------------------------------
# Tests — positive
# ---------------------------------------------------------------------------

def test_sql_user_id_ownership():
    matches = scan_ownership_checks("app.py", SQL_WITH_OWNERSHIP)
    patterns = [m.pattern for m in matches]
    assert any("user_id" in p for p in patterns)


def test_sql_tenant_id():
    matches = scan_ownership_checks("app.py", SQL_TENANT_FILTER)
    assert any("tenant_id" in m.pattern for m in matches)


def test_require_admin_detected():
    matches = scan_ownership_checks("views.py", REQUIRE_ADMIN)
    names = [m.identifier for m in matches]
    assert any("require_admin" in n for n in names)


def test_require_admin_current_user_derived():
    matches = scan_ownership_checks("views.py", REQUIRE_ADMIN)
    admin_matches = [m for m in matches if "require_admin" in m.identifier]
    assert admin_matches
    assert all(m.current_user_derived for m in admin_matches)


def test_has_permission_detected():
    matches = scan_ownership_checks("views.py", HAS_PERMISSION)
    assert any("has_permission" in m.pattern for m in matches)


def test_current_user_id_detected():
    matches = scan_ownership_checks("views.py", CURRENT_USER_CMP)
    assert any("current_user.id" in m.pattern for m in matches)


def test_current_user_id_is_safe():
    matches = scan_ownership_checks("views.py", CURRENT_USER_CMP)
    cu_matches = [m for m in matches if "current_user.id" in m.pattern]
    assert cu_matches
    assert all(m.current_user_derived for m in cu_matches)


def test_fastapi_depends_current_user():
    matches = scan_ownership_checks("routes.py", FASTAPI_DEPENDS_CU)
    assert any("get_current_user" in m.identifier for m in matches)


# ---------------------------------------------------------------------------
# Tests — negative
# ---------------------------------------------------------------------------

def test_where_1_1_not_ownership():
    matches = scan_ownership_checks("app.py", SQL_NO_OWNERSHIP)
    # WHERE 1=1 has no ownership column
    assert not any("user_id" in m.pattern for m in matches)


def test_parameterized_no_owner_column():
    matches = scan_ownership_checks("app.py", SQL_PARAMETERIZED_NO_OWNER)
    # WHERE id = ? — no user_id/tenant_id column
    ownership_cols = {"user_id", "tenant_id", "org_id", "owner_id", "account_id"}
    matched_ids = {m.identifier for m in matches}
    assert not matched_ids.intersection(ownership_cols)
