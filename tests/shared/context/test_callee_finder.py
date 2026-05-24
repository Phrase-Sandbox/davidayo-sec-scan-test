"""Tests for callee finder."""

from __future__ import annotations

from security_scanner.shared.context.callee_finder import find_callees

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SNIPPET_WITH_DB = """\
def get_article(article_id):
    article = db.execute("SELECT * FROM articles WHERE id = %s", article_id)
    return article
"""

SNIPPET_WITH_AUTH = """\
def update_article(article_id, data):
    article = find_article_by_id(article_id)
    if not has_permission(current_user, 'write', article):
        raise PermissionError
    article.update(data)
"""

SNIPPET_WITH_OWNERSHIP = """\
def get_record(record_id):
    user = get_current_user()
    record = get_record_by_id(record_id)
    return record
"""

SNIPPET_MIXED = """\
def handler(user_id):
    can_access(user_id)
    data = query(user_id)
    helper = some_helper(data)
    return data
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_finds_db_callees():
    callees = find_callees(SNIPPET_WITH_DB)
    kinds = {c.kind for c in callees}
    assert "db_query" in kinds


def test_finds_auth_callees():
    callees = find_callees(SNIPPET_WITH_AUTH)
    names = {c.name for c in callees}
    assert "has_permission" in names


def test_auth_check_kind():
    callees = find_callees(SNIPPET_WITH_AUTH)
    auth_callees = [c for c in callees if c.kind == "auth_check"]
    assert any(c.name == "has_permission" for c in auth_callees)


def test_finds_ownership_helpers():
    callees = find_callees(SNIPPET_WITH_OWNERSHIP)
    names = {c.name for c in callees}
    assert "get_current_user" in names or "get_record_by_id" in names


def test_ownership_helper_kind():
    callees = find_callees(SNIPPET_WITH_OWNERSHIP)
    ownership = [c for c in callees if c.kind == "ownership_helper"]
    assert len(ownership) >= 1


def test_mixed_snippet_priorities():
    callees = find_callees(SNIPPET_MIXED)
    # auth_check should come before db_query
    if len(callees) > 1:
        kinds_in_order = [c.kind for c in callees]
        auth_idx = next((i for i, k in enumerate(kinds_in_order) if k == "auth_check"), None)
        db_idx = next((i for i, k in enumerate(kinds_in_order) if k == "db_query"), None)
        if auth_idx is not None and db_idx is not None:
            assert auth_idx < db_idx


def test_no_duplicates():
    callees = find_callees(SNIPPET_MIXED)
    names = [c.name for c in callees]
    assert len(names) == len(set(names))


def test_empty_snippet():
    callees = find_callees("")
    assert callees == []


def test_python_keywords_excluded():
    snippet = "if True:\n    for x in items:\n        return x\n"
    callees = find_callees(snippet)
    names = {c.name for c in callees}
    # Python keywords should not appear
    assert "if" not in names
    assert "for" not in names
    assert "return" not in names
    assert "True" not in names
