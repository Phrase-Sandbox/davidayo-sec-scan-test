"""Tests for the token-count estimator (spec §4.2, BR-005)."""

from security_scanner.shared.tokens.counter import THRESHOLD, count, exceeds_limit, trim_to_budget


def test_threshold_value_matches_br005():
    assert THRESHOLD == 150_000


# --- count() -----------------------------------------------------------------


def test_count_of_empty_input_is_zero():
    assert count({}) == 0


def test_count_formula_at_threshold():
    """Spec §4.2 worked example: 600 000 chars → 150 000 tokens."""
    files = {"file.py": "x" * 600_000}
    assert count(files) == 150_000


def test_count_sums_across_files():
    files = {"a.py": "x" * 1000, "b.py": "y" * 2000, "c.py": "z" * 500}
    assert count(files) == 3500 // 4  # = 875


def test_count_ignores_filenames_only_content_matters():
    """Filenames contribute zero tokens — only file contents are counted."""
    a = {"a.py": "x" * 400}
    b = {"a_very_long_filename_does_not_matter.py": "x" * 400}
    assert count(a) == count(b)


# --- exceeds_limit() boundary -----------------------------------------------


def test_exceeds_limit_at_threshold_boundary_is_false():
    """600 000 chars = at threshold, not strictly over it."""
    assert exceeds_limit({"f.py": "x" * 600_000}) is False


def test_exceeds_limit_just_under_threshold_is_false():
    """599 999 chars → 149 999.75 tokens — below threshold."""
    assert exceeds_limit({"f.py": "x" * 599_999}) is False


def test_exceeds_limit_just_over_threshold_is_true():
    """600 001 chars → 150 000.25 tokens — strictly exceeds threshold."""
    assert exceeds_limit({"f.py": "x" * 600_001}) is True


def test_exceeds_limit_of_empty_input_is_false():
    assert exceeds_limit({}) is False


def test_exceeds_limit_sums_across_files():
    """Limit applies to the SUM, not per-file."""
    files = {f"f_{i}.py": "x" * 100_000 for i in range(7)}  # 700 000 chars total
    assert exceeds_limit(files) is True


# ---------------------------------------------------------------------------
# V7: trim_to_budget()
# ---------------------------------------------------------------------------


def test_trim_to_budget_all_fit():
    """When total tokens ≤ budget, all files are kept and skipped is empty."""
    files = {"a.py": "x" * 100, "b.py": "y" * 200}
    kept, skipped = trim_to_budget(files, budget=THRESHOLD)
    assert kept == files
    assert skipped == []


def test_trim_to_budget_splits_at_budget():
    """Files that push the total over budget end up in skipped."""
    # Each file is 200 001 chars = 50 000.25 tokens.
    # Budget = 150 000 tokens = 600 000 chars.
    # 3 files = 600 003 chars → exceeds.  Only 2 should fit.
    chunk = "x" * 200_001
    files = {"a.py": chunk, "b.py": chunk, "c.py": chunk}
    kept, skipped = trim_to_budget(files, budget=150_000)
    assert len(kept) == 2
    assert len(skipped) == 1


def test_trim_to_budget_high_risk_files_prioritised():
    """Files under high-risk paths are kept over normal files when budget is tight."""
    # Each file is 200 001 chars.  Budget fits 2 files.
    chunk = "x" * 200_001
    files = {
        "utils/helpers.py": chunk,       # normal
        "auth/login.py": chunk,          # high-risk
        "payments/checkout.py": chunk,   # high-risk
    }
    kept, skipped = trim_to_budget(files, budget=150_000)
    assert "auth/login.py" in kept
    assert "payments/checkout.py" in kept
    assert "utils/helpers.py" in skipped


def test_trim_to_budget_returned_kept_is_within_budget():
    """kept always fits within the budget."""
    chunk = "x" * 50_001  # ~12 500 tokens each
    files = {f"f_{i}.py": chunk for i in range(20)}  # ~250 000 tokens total
    kept, skipped = trim_to_budget(files, budget=150_000)
    assert count(kept) <= 150_000
    assert len(kept) + len(skipped) == len(files)


def test_trim_to_budget_skipped_plus_kept_equals_all_files():
    """Every file ends up in exactly one of kept or skipped."""
    chunk = "x" * 100_001
    files = {f"f_{i}.py": chunk for i in range(10)}
    kept, skipped = trim_to_budget(files, budget=150_000)
    assert set(kept) | set(skipped) == set(files)
    assert set(kept) & set(skipped) == set()
