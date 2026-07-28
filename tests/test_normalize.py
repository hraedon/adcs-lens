"""SID normalization and low-privilege trustee classification.

The classifier is an allowlist: only the curated high-privilege SID set is
treated as privileged; every other trustee — broad sets, custom groups, named
accounts — is treated as low-privilege so no enabling right is silently
missed (the pre-inversion blocklist missed custom groups entirely, a
domain-compromise-class false negative).
"""

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
        f"{DOMAIN}-1601",  # a custom group RID (e.g. "Help Desk")
        f"{DOMAIN}-1107",  # an ordinary user RID
        f"{DOMAIN}-1108",  # an ordinary computer account RID
        "S-1-5-80-1234567890-123456789-123456789-123456789-123456789",  # service SID
        "S-1-5-32-554",  # Pre-Windows 2000 Compatible Access (not tier-0)
        "S-1-5-32-555",  # Remote Desktop Users (not tier-0)
    ],
)
def test_unknown_trustees_are_low_priv(sid: str) -> None:
    """The false-negative fix: anything outside the high-priv set is low-priv.

    Under the old blocklist these returned False and their enabling rights were
    silently invisible to every ACL-gated detector.
    """
    assert is_low_priv_trustee(sid)


@pytest.mark.parametrize(
    "sid",
    [
        f"{DOMAIN}-500",  # Administrator
        f"{DOMAIN}-502",  # krbtgt
        f"{DOMAIN}-512",  # Domain Admins
        f"{DOMAIN}-516",  # Domain Controllers
        f"{DOMAIN}-517",  # Cert Publishers
        f"{DOMAIN}-518",  # Schema Admins
        f"{DOMAIN}-519",  # Enterprise Admins
        f"{DOMAIN}-526",  # Key Admins
        f"{DOMAIN}-527",  # Enterprise Key Admins
        "S-1-5-18",  # Local System
        "S-1-5-19",  # Local Service
        "S-1-5-20",  # Network Service
        "S-1-5-9",  # Enterprise Domain Controllers
        "S-1-5-32-544",  # BUILTIN\\Administrators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-551",  # Backup Operators
    ],
)
def test_high_priv_sids(sid: str) -> None:
    assert not is_low_priv_trustee(sid)


def test_bare_rid_does_not_false_match() -> None:
    # A -512 suffix outside the S-1-5-21 domain prefix must NOT inherit Domain
    # Admins' high-privilege standing (the MS16-072 false-match class gpo-lens
    # had to fix, mirrored for the inverted allowlist).
    assert is_low_priv_trustee("S-1-5-32-512")
    assert is_low_priv_trustee("S-1-5-32-519")


def test_normalize_sid_uppercases_and_trims() -> None:
    assert normalize_sid("  s-1-5-21-10-20-30-513 ") == "S-1-5-21-10-20-30-513"


def test_low_priv_matching_is_case_insensitive() -> None:
    assert is_low_priv_trustee("s-1-5-11")
    assert not is_low_priv_trustee(f"{DOMAIN}-512".lower())
