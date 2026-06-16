"""Detector logic, exercised on directly-constructed model objects (no I/O)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from adcs_lens.detection import detect_esc6, detect_infra_cert_expiry, run_all
from adcs_lens.model import (
    CaKind,
    CertAuthority,
    CertKind,
    CertLifecycle,
    Crl,
    CrlTier,
    Estate,
    Manifest,
    Severity,
)

NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


def _ca(
    name: str,
    *,
    kind: CaKind = CaKind.ISSUING,
    edit_flags: tuple[str, ...] = (),
    certs: tuple[CertLifecycle, ...] = (),
) -> CertAuthority:
    return CertAuthority(
        name=name,
        dns="",
        config_string=f"host\\{name}",
        kind=kind,
        edit_flags=frozenset(edit_flags),
        interface_flags=frozenset(),
        audit_filter=None,
        validity="",
        roles=frozenset(),
        security=(),
        certs=certs,
    )


def _estate(
    *,
    cas: tuple[CertAuthority, ...] = (),
    crls: tuple[Crl, ...] = (),
    certs_parsed: bool = True,
) -> Estate:
    manifest = Manifest(
        collector_version="t",
        collected_at="",
        host="",
        domain="",
        skipped_passes=(),
        certs_parsed=certs_parsed,
    )
    return Estate(cas=cas, templates=(), acls=(), oids=(), crls=crls, manifest=manifest)


# --- ESC6 -----------------------------------------------------------------


def test_esc6_flagged() -> None:
    estate = _estate(cas=(_ca("BadCA", edit_flags=("EDITF_ATTRIBUTESUBJECTALTNAME2",)),))
    findings = detect_esc6(estate)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].subject == "BadCA"
    assert "policy\\EditFlags" in findings[0].source


def test_esc6_clean_ca_no_finding() -> None:
    assert detect_esc6(_estate(cas=(_ca("GoodCA"),))) == []


# --- lifecycle: degrade path ----------------------------------------------


def test_lifecycle_degrades_without_certs() -> None:
    findings = detect_infra_cert_expiry(_estate(certs_parsed=False), now=NOW)
    assert len(findings) == 1
    assert findings[0].check == "LIFECYCLE_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_lifecycle_rejects_naive_now() -> None:
    estate = _estate(
        cas=(
            _ca(
                "CA",
                certs=(
                    CertLifecycle(
                        "CN=Soon",
                        CertKind.ISSUING_CA,
                        NOW,
                        NOW + timedelta(days=30),
                        "sha256",
                        2048,
                    ),
                ),
            ),
        )
    )
    try:
        detect_infra_cert_expiry(estate, now=datetime(2026, 6, 15, 12, 0, 0))
    except ValueError:
        pass
    else:
        raise AssertionError("naive datetime should be rejected")


# --- lifecycle: cert expiry -----------------------------------------------


def test_expired_ca_cert_critical() -> None:
    cert = CertLifecycle(
        "CN=Old",
        CertKind.ISSUING_CA,
        NOW - timedelta(days=800),
        NOW - timedelta(days=1),
        "sha256",
        2048,
    )
    findings = detect_infra_cert_expiry(_estate(cas=(_ca("CA", certs=(cert,)),)), now=NOW)
    assert findings[0].check == "CA_CERT_EXPIRY"
    assert findings[0].severity == Severity.CRITICAL


def test_issuing_cert_near_expiry_high() -> None:
    cert = CertLifecycle(
        "CN=Soon", CertKind.ISSUING_CA, NOW, NOW + timedelta(days=30), "sha256", 2048
    )
    findings = detect_infra_cert_expiry(
        _estate(cas=(_ca("CA", certs=(cert,)),)), now=NOW, warn_days=90
    )
    assert findings[0].severity == Severity.HIGH


def test_root_cert_near_expiry_escalated_to_critical() -> None:
    cert = CertLifecycle(
        "CN=Root", CertKind.ROOT_CA, NOW, NOW + timedelta(days=30), "sha256", 4096
    )
    findings = detect_infra_cert_expiry(
        _estate(cas=(_ca("Root", kind=CaKind.ROOT, certs=(cert,)),)), now=NOW
    )
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].tier == CrlTier.ROOT


def test_healthy_cert_no_finding() -> None:
    cert = CertLifecycle(
        "CN=Fine", CertKind.ISSUING_CA, NOW, NOW + timedelta(days=1000), "sha256", 2048
    )
    assert detect_infra_cert_expiry(_estate(cas=(_ca("CA", certs=(cert,)),)), now=NOW) == []


# --- lifecycle: CRL freshness ---------------------------------------------


def test_expired_root_crl_critical_and_root_tier() -> None:
    crl = Crl(
        "CN=Root",
        NOW - timedelta(days=400),
        NOW - timedelta(days=35),
        CrlTier.ROOT,
        "published",
    )
    findings = detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW)
    assert findings[0].check == "CRL_EXPIRY"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].tier == CrlTier.ROOT
    assert "offline" in findings[0].detail


def test_fresh_crl_no_finding() -> None:
    crl = Crl(
        "CN=Iss",
        NOW - timedelta(days=2),
        NOW + timedelta(days=5),
        CrlTier.ISSUING,
        "host",
    )
    assert detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW) == []


# --- composition ----------------------------------------------------------


def test_run_all_sorted_worst_first() -> None:
    cert = CertLifecycle(
        "CN=Soon", CertKind.ISSUING_CA, NOW, NOW + timedelta(days=30), "sha256", 2048
    )
    estate = _estate(
        cas=(_ca("BadCA", edit_flags=("EDITF_ATTRIBUTESUBJECTALTNAME2",), certs=(cert,)),),
    )
    findings = run_all(estate, now=NOW)
    severities = [f.severity for f in findings]
    assert severities == sorted(severities)
    assert findings[0].severity == Severity.CRITICAL
