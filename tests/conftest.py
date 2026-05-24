"""Shared test fixtures."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_run_layer1():
    """Auto-mock run_layer1 in pipeline tests to avoid spawning real scanner processes.

    In tests that need real scanner behavior, override this fixture or use
    `monkeypatch` to remove the mock.
    """
    with patch(
        "security_scanner.pipeline.run_layer1",
        new_callable=AsyncMock,
        return_value=[],
    ) as mock:
        yield mock
