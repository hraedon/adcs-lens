"""Normalization helpers — SIDs and join keys.

Pure, stdlib-only. Kept separate from ingest so detectors that reason about
*who* a right is granted to (ESC4/5/7, later) share one definition of
"low-privilege trustee" rather than re-deriving it.
"""

from __future__ import annotations

# Well-known SIDs that represent a broad/low-privilege set of principals. A
# privileged right (enroll, write, ManageCA) granted to any of these is the
# enabling condition behind several ESC classes.
#
# Domain-relative RIDs (Domain Users -513, Domain Computers -515) must be matched
# only under the domain SID prefix S-1-5-21-* — a bare "-515" suffix can belong
# to an unrelated group (the exact false-match gpo-lens had to fix for MS16-072).
_ABSOLUTE_LOW_PRIV: frozenset[str] = frozenset(
    {
        "S-1-1-0",  # Everyone
        "S-1-5-7",  # Anonymous Logon
        "S-1-5-11",  # Authenticated Users
        "S-1-5-32-545",  # BUILTIN\Users
    }
)
_DOMAIN_LOW_PRIV_RIDS: frozenset[str] = frozenset(
    {
        "513",  # Domain Users
        "514",  # Domain Guests
        "515",  # Domain Computers
    }
)


def normalize_sid(sid: str) -> str:
    """Canonicalize a SID string: trim and upper-case the ``S-`` form."""
    s = sid.strip()
    if s[:2].upper() == "S-":
        return "S-" + s[2:].upper()
    return s


def is_low_priv_trustee(sid: str) -> bool:
    """True if *sid* names a broad/low-privilege principal set.

    Domain-relative RIDs only match under the ``S-1-5-21-`` domain prefix, so a
    coincidental ``*-515`` on an unrelated group does not false-positive.
    """
    s = normalize_sid(sid)
    if s in _ABSOLUTE_LOW_PRIV:
        return True
    if s.startswith("S-1-5-21-"):
        rid = s.rsplit("-", 1)[-1]
        return rid in _DOMAIN_LOW_PRIV_RIDS
    return False
