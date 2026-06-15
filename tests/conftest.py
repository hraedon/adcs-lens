"""Shared test fixtures: synthetic exports built fresh into tmp dirs."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

# Make the declarative fixture generator importable.
sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
from build_fixture import build_export  # noqa: E402

# A fixed "now" so expiry/CRL assertions are deterministic regardless of
# wall-clock at test time. The synthetic export's validity windows are anchored
# to this instant.
NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def now() -> datetime:
    return NOW


@pytest.fixture
def json_export(tmp_path: Path) -> Path:
    """A stdlib-readable export (no DER certs)."""
    return build_export(tmp_path / "export", with_certs=False, now=NOW)


@pytest.fixture
def full_export(tmp_path: Path) -> Path:
    """A full export including DER certs/CRLs (needs the [certs] extra)."""
    pytest.importorskip("cryptography")
    return build_export(tmp_path / "export", with_certs=True, now=NOW)
