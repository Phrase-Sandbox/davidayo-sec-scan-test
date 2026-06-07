"""Tests for repo-wide caller finder."""

from __future__ import annotations

from security_scanner.shared.context.caller_finder import find_callers

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_MAIN_PY = """\
from app.views import get_user_data

def process_request(user_id):
    data = get_user_data(user_id)
    return data

def another_func():
    result = get_user_data(42)
    return result
"""

_HELPER_PY = """\
def get_user_data(user_id):
    # Implementation
    return db.query(user_id)
"""

_TEST_PY = """\
def test_get_user_data():
    get_user_data(1)
"""

_TEST_SPEC_JS = """\
it('calls get_user_data', () => {
    get_user_data(1);
});
"""


def _make_files(**kwargs: str) -> dict[str, str]:
    return dict(kwargs)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_finds_direct_callers():
    files = _make_files(**{
        "app/main.py": _MAIN_PY,
        "app/helper.py": _HELPER_PY,
    })
    callers = find_callers("get_user_data", files)
    # Both calls in main.py should be found (helper.py defines, not calls).
    call_files = [c.file for c in callers]
    assert "app/main.py" in call_files


def test_finds_correct_enclosing_function():
    files = _make_files(**{"app/main.py": _MAIN_PY})
    callers = find_callers("get_user_data", files)
    func_names = {c.function_name for c in callers}
    assert "process_request" in func_names
    assert "another_func" in func_names


def test_skips_test_paths():
    files = _make_files(**{
        "app/main.py": _MAIN_PY,
        "tests/test_views.py": _TEST_PY,
        "app/__tests__/test_helper.js": _TEST_SPEC_JS,
    })
    callers = find_callers("get_user_data", files)
    caller_files = [c.file for c in callers]
    # Test files must be excluded.
    assert "tests/test_views.py" not in caller_files
    assert "app/__tests__/test_helper.js" not in caller_files
    # Main file must be included.
    assert "app/main.py" in caller_files


def test_skips_spec_files():
    files = _make_files(**{
        "src/handler.py": "result = get_user_data(id)\n",
        "src/handler.spec.py": "get_user_data(id)\n",
        "src/handler.test.py": "get_user_data(id)\n",
    })
    callers = find_callers("get_user_data", files)
    caller_files = [c.file for c in callers]
    assert "src/handler.py" in caller_files
    assert "src/handler.spec.py" not in caller_files
    assert "src/handler.test.py" not in caller_files


def test_returns_at_most_max_callers():
    # Generate 30 files each calling the function once.
    files = {f"module_{i}.py": f"def f{i}():\n    target_func()\n"
             for i in range(30)}
    callers = find_callers("target_func", files, max_callers=5)
    assert len(callers) <= 5


def test_snippet_included():
    files = _make_files(**{"app/main.py": _MAIN_PY})
    callers = find_callers("get_user_data", files)
    # Each caller should have a non-empty snippet.
    assert all(c.snippet for c in callers)


def test_empty_function_name_returns_empty():
    files = _make_files(**{"app/main.py": _MAIN_PY})
    assert find_callers("", files) == []


def test_unknown_function_returns_empty():
    files = _make_files(**{"app/main.py": _MAIN_PY})
    assert find_callers("<unknown>", files) == []


def test_no_callers_found():
    files = _make_files(**{"app/main.py": _MAIN_PY})
    callers = find_callers("nonexistent_function_xyz", files)
    assert callers == []
