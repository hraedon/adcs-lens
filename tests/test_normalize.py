"""SID normalization and low-privilege trustee classification."""

from __future__ import annotations

import pytest

from adcs_lens.normalize import is_low_priv_trustee, normalize_sid

DOMAIN = "S-1-5-21-1111111111-2222222222-3333333333"


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-1-0",  # Everyone
        "S-1-5-2",  # Network
        "S-1-5-4",  # Interactive
        "S-1-5-7",  # Anonymous Logon
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # BUILTIN\\Users
        "S-1-5-32-546",  # BUILTIN\\Guests
        f"{DOMAIN}-513",  # Domain Users
        f"{DOMAIN}-514",  # Domain Guests
        f"{DOMAIN}-515",  # Domain Computers
    ],
)
def test_low_priv_sids(sid: str) -> None:
    assert is_low_priv_trustee(sid)


@pytest.mark.parametrize(
    "sid",
    [
        f"{DOMAIN}-512",  # Domain Admins
        f"{DOMAIN}-519",  # Enterprise Admins
        f"{DOMAIN}-1107",  # an ordinary user/group RID
        "S-1-5-32-544",  # BUILTIN\\Administrators
        "S-1-5-18",  # Local System
    ],
)
def test_not_low_priv_sids(sid: str) -> None:
    assert not is_low_priv_trustee(sid)


def test_bare_rid_does_not_false_match() -> None:
    # A -513 suffix outside the S-1-5-21 domain prefix must NOT count as Domain
    # Users (the MS16-072 false-match class gpo-lens had to fix).
    assert not is_low_priv_trustee("S-1-5-32-513")


def test_normalize_sid_uppercases_and_trims() -> None:
    assert normalize_sid("  s-1-5-21-10-20-30-513 ") == "S-1-5-21-10-20-30-513"


def test_low_priv_matching_is_case_insensitive() -> None:
    assert is_low_priv_trustee("s-1-5-11")
