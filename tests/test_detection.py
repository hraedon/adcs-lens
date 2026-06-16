"""Detector logic, exercised on directly-constructed model objects (no I/O)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from adcs_lens.detection import (
    detect_esc1,
    detect_esc2,
    detect_esc3,
    detect_esc4,
    detect_esc6,
    detect_esc7,
    detect_esc9,
    detect_infra_cert_expiry,
    run_all,
)
from adcs_lens.model import (
    AceEntry,
    AceType,
    CaKind,
    CertAuthority,
    CertKind,
    CertLifecycle,
    CertTemplate,
    Crl,
    CrlTier,
    Estate,
    Manifest,
    Severity,
)

NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
ANY_PURPOSE = "2.5.29.37.0"
ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
LOW_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-513"  # Domain Users
HIGH_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-512"  # Domain Admins


def _enroll_ace(sid: str = LOW_PRIV_SID, *, right: str = "Enroll") -> AceEntry:
    return AceEntry(
        trustee_sid=sid, trustee_name="trustee", rights=(right,), ace_type=AceType.ALLOW
    )


def _template(
    name: str = "T",
    *,
    ekus: tuple[str, ...] = (CLIENT_AUTH,),
    name_flags: tuple[str, ...] = ("ENROLLEE_SUPPLIES_SUBJECT",),
    enrollment_flags: tuple[str, ...] = (),
    security: tuple[AceEntry, ...] = (),
) -> CertTemplate:
    return CertTemplate(
        name=name,
        display_name=name,
        schema_version=2,
        oid=f"1.3.6.1.4.1.311.21.8.{name}",
        ekus=ekus,
        name_flags=frozenset(name_flags),
        enrollment_flags=frozenset(enrollment_flags),
        min_key_size=2048,
        issuance_policy_oids=(),
        security=security,
        published_by=(),
    )


def _ca(
    name: str,
    *,
    kind: CaKind = CaKind.ISSUING,
    edit_flags: tuple[str, ...] = (),
    certs: tuple[CertLifecycle, ...] = (),
    security: tuple[AceEntry, ...] = (),
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
        security=security,
        certs=certs,
    )


def _estate(
    *,
    cas: tuple[CertAuthority, ...] = (),
    templates: tuple[CertTemplate, ...] = (),
    crls: tuple[Crl, ...] = (),
    certs_parsed: bool = True,
    skipped_passes: tuple[str, ...] = (),
) -> Estate:
    manifest = Manifest(
        collector_version="t",
        collected_at="",
        host="",
        domain="",
        skipped_passes=skipped_passes,
        certs_parsed=certs_parsed,
    )
    return Estate(
        cas=cas, templates=templates, acls=(), oids=(), crls=crls, manifest=manifest
    )


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


# --- ESC1 -----------------------------------------------------------------


def test_esc1_flagged_when_all_conditions_hold() -> None:
    tmpl = _template("VulnUserAuth", security=(_enroll_ace(),))
    findings = detect_esc1(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].subject == "VulnUserAuth"


def test_esc1_no_eku_is_dangerous() -> None:
    # A template with no EKU at all is valid for any purpose -> still ESC1.
    tmpl = _template("NoEku", ekus=(), security=(_enroll_ace(),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


def test_esc1_not_flagged_without_auth_eku() -> None:
    # Server-auth-only template cannot authenticate as a user.
    tmpl = _template("WebOnly", ekus=(SERVER_AUTH,), security=(_enroll_ace(),))
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_not_flagged_without_supplies_subject() -> None:
    tmpl = _template("Fixed", name_flags=(), security=(_enroll_ace(),))
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_mitigated_by_manager_approval() -> None:
    tmpl = _template(
        "Approved", enrollment_flags=("PEND_ALL_REQUESTS",), security=(_enroll_ace(),)
    )
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_not_flagged_when_only_high_priv_can_enroll() -> None:
    tmpl = _template("AdminOnly", security=(_enroll_ace(HIGH_PRIV_SID),))
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_deny_ace_does_not_count_as_enroll() -> None:
    deny = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=("Enroll",),
        ace_type=AceType.DENY,
    )
    assert detect_esc1(_estate(templates=(_template("D", security=(deny,)),))) == []


def test_esc1_broad_right_implies_enroll() -> None:
    # GenericAll on the template implies the ability to enroll.
    tmpl = _template("Owned", security=(_enroll_ace(right="GenericAll"),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


def test_esc1_degrades_when_template_security_not_collected() -> None:
    tmpl = _template("Vuln", security=(_enroll_ace(),))
    findings = detect_esc1(
        _estate(templates=(tmpl,), skipped_passes=("template-security",))
    )
    assert len(findings) == 1
    assert findings[0].check == "TEMPLATE_ACL_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


# --- ESC2 -----------------------------------------------------------------


def test_esc2_any_purpose_eku_flagged() -> None:
    tmpl = _template("AnyPurpose", ekus=(ANY_PURPOSE,), security=(_enroll_ace(),))
    findings = detect_esc2(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC2"
    assert findings[0].severity == Severity.HIGH


def test_esc2_no_eku_flagged() -> None:
    tmpl = _template("NoEku", ekus=(), security=(_enroll_ace(),))
    assert len(detect_esc2(_estate(templates=(tmpl,)))) == 1


def test_esc2_constrained_eku_not_flagged() -> None:
    tmpl = _template("Web", ekus=(SERVER_AUTH,), security=(_enroll_ace(),))
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc2_requires_low_priv_enroll() -> None:
    tmpl = _template("AnyPurpose", ekus=(ANY_PURPOSE,), security=(_enroll_ace(HIGH_PRIV_SID),))
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc2_mitigated_by_manager_approval() -> None:
    tmpl = _template(
        "AnyPurpose",
        ekus=(ANY_PURPOSE,),
        enrollment_flags=("PEND_ALL_REQUESTS",),
        security=(_enroll_ace(),),
    )
    assert detect_esc2(_estate(templates=(tmpl,))) == []


# --- ESC3 -----------------------------------------------------------------


def test_esc3_enrollment_agent_eku_flagged() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT,), security=(_enroll_ace(),))
    findings = detect_esc3(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC3"
    assert findings[0].severity == Severity.HIGH


def test_esc3_not_flagged_without_agent_eku() -> None:
    tmpl = _template("Plain", ekus=(CLIENT_AUTH,), security=(_enroll_ace(),))
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc3_requires_low_priv_enroll() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT,), security=(_enroll_ace(HIGH_PRIV_SID),))
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc2_esc3_silent_when_template_security_not_collected() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT, ANY_PURPOSE), security=(_enroll_ace(),))
    skipped = _estate(templates=(tmpl,), skipped_passes=("template-security",))
    assert detect_esc2(skipped) == []
    assert detect_esc3(skipped) == []


# --- ESC4 -----------------------------------------------------------------


def test_esc4_flagged_when_low_priv_can_write_template() -> None:
    tmpl = _template("Delegated", security=(_enroll_ace(right="WriteDacl"),))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC4"
    assert findings[0].severity == Severity.HIGH
    assert "WriteDacl" in findings[0].detail


def test_esc4_genericall_flagged() -> None:
    tmpl = _template("Owned", security=(_enroll_ace(right="GenericAll"),))
    assert len(detect_esc4(_estate(templates=(tmpl,)))) == 1


def test_esc4_blanket_writeproperty_flagged() -> None:
    # Blanket WriteProperty (collector token 'WritePropertyAll', from an all-zero
    # ObjectType) can rewrite msPKI-Certificate-Name-Flag → ESC1, so it is control.
    tmpl = _template("BlanketWrite", security=(_enroll_ace(right="WritePropertyAll"),))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC4"
    assert "WritePropertyAll" in findings[0].detail


def test_esc4_scoped_writeproperty_not_flagged() -> None:
    # Property-scoped WriteProperty (token 'WriteProperty') may not reach the name
    # flags; we do not flag it without a property-set GUID map.
    tmpl = _template("ScopedWrite", security=(_enroll_ace(right="WriteProperty"),))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_enroll_only_is_not_esc4() -> None:
    # Plain Enroll is not a control right — that is ESC1 territory, not ESC4.
    tmpl = _template("EnrollOnly", security=(_enroll_ace(right="Enroll"),))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_high_priv_writer_not_flagged() -> None:
    tmpl = _template("AdminWrite", security=(_enroll_ace(HIGH_PRIV_SID, right="WriteOwner"),))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_silent_when_template_security_not_collected() -> None:
    # ESC1 emits the degradation note; ESC4 stays silent to avoid duplicating it.
    tmpl = _template("Delegated", security=(_enroll_ace(right="WriteDacl"),))
    assert detect_esc4(
        _estate(templates=(tmpl,), skipped_passes=("template-security",))
    ) == []


# --- ESC7 -----------------------------------------------------------------


def test_esc7_manage_ca_by_low_priv_is_critical() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(right="ManageCA"),))
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC7"
    assert findings[0].severity == Severity.CRITICAL


def test_esc7_manage_certs_by_low_priv_is_high() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(right="ManageCertificates"),))
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_esc7_low_priv_enroll_only_no_finding() -> None:
    # Authenticated Users with Enroll on the CA is normal, not ESC7.
    ca = _ca("IssuingCA", security=(_enroll_ace(right="Enroll"),))
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_esc7_high_priv_manage_not_flagged() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(HIGH_PRIV_SID, right="ManageCA"),))
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_esc7_aggregates_both_roles_per_trustee_to_one_critical() -> None:
    # Same low-priv trustee with two ACEs (ManageCA + ManageCertificates) -> one
    # finding, escalated to critical by the Manage CA right.
    ca = _ca(
        "IssuingCA",
        security=(
            _enroll_ace(right="ManageCA"),
            _enroll_ace(right="ManageCertificates"),
        ),
    )
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_esc7_degrades_when_ca_security_not_collected() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(right="ManageCA"),))
    findings = detect_esc7(_estate(cas=(ca,), skipped_passes=("ca-security",)))
    assert len(findings) == 1
    assert findings[0].check == "CA_SECURITY_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


# --- ESC9 -----------------------------------------------------------------


def test_esc9_flagged_on_no_security_extension() -> None:
    tmpl = _template("WeakMap", enrollment_flags=("NO_SECURITY_EXTENSION",))
    findings = detect_esc9(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC9"
    assert findings[0].severity == Severity.HIGH


def test_esc9_clean_template_no_finding() -> None:
    assert detect_esc9(_estate(templates=(_template("Clean"),))) == []


def test_esc9_evaluates_even_without_template_security() -> None:
    # ESC9 needs only enrollment flags, so it works on a real (ACL-skipped) export.
    tmpl = _template("WeakMap", enrollment_flags=("NO_SECURITY_EXTENSION",))
    findings = detect_esc9(
        _estate(templates=(tmpl,), skipped_passes=("template-security",))
    )
    assert len(findings) == 1


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
