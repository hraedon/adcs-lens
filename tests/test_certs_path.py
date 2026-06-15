"""End-to-end lifecycle path: DER certs/CRLs parsed via the [certs] extra.

Skips when cryptography is absent (the core's degrade path is covered in
test_detection.py without the dependency).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from adcs_lens.detection import run_all
from adcs_lens.ingest import ingest

pytestmark = __import__("pytest").mark.certs


def test_full_export_populates_lifecycle(full_export: Path, now: datetime) -> None:
    estate = ingest(full_export)
    assert estate.manifest.certs_parsed is True
    assert len(estate.crls) == 2
    # Every CA cert carried a real not_after parsed from DER.
    parsed = [c for ca in estate.cas for c in ca.certs if c.not_after is not None]
    assert len(parsed) == 2


def test_full_export_flags_root_crl_and_expiry(full_export: Path, now: datetime) -> None:
    findings = run_all(ingest(full_export), now=now)
    by_check = {f.check: f for f in findings}

    # Root CRL is past nextUpdate -> critical, root-tier, no degrade note.
    assert "CRL_EXPIRY" in by_check
    crl = by_check["CRL_EXPIRY"]
    assert crl.severity == "critical" and crl.tier == "root"
    assert "LIFECYCLE_NOT_EVALUATED" not in by_check

    # Issuing cert expiring within the default window -> flagged.
    assert "CA_CERT_EXPIRY" in by_check

    # ESC6 still independently detected on the config path.
    assert "ESC6" in by_check
