"""Tests for the token-count estimator (spec §4.2, BR-005)."""

from security_scanner.shared.tokens.counter import THRESHOLD, count, exceeds_limit


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
