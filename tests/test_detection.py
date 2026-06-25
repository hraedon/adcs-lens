"""Detector logic, exercised on directly-constructed model objects (no I/O)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from adcs_lens.detection import (
    detect_esc1,
    detect_esc2,
    detect_esc3,
    detect_esc4,
    detect_esc5,
    detect_esc6,
    detect_esc7,
    detect_esc8,
    detect_esc9,
    detect_esc11,
    detect_esc13,
    detect_infra_cert_expiry,
    detect_template_acl_gaps,
    run_all,
)
from adcs_lens.model import (
    AceEntry,
    AceType,
    AclKind,
    CaKind,
    CertAuthority,
    CertKind,
    CertLifecycle,
    CertTemplate,
    Crl,
    CrlTier,
    DcConfiguration,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    IssuanceOid,
    Manifest,
    PkiObjectAcl,
    PrincipalMapping,
    SchannelMappingMethod,
    Severity,
    StrongCertBinding,
)

NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
ANY_PURPOSE = "2.5.29.37.0"
ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
LOW_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-513"  # Domain Users
HIGH_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-512"  # Domain Admins
POLICY_OID = "1.3.6.1.4.1.311.21.8.1.2.3.4.999"
DOMAIN_ADMINS_SID = "S-1-5-21-1111111111-2222222222-3333333333-512"


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
    issuance_policy_oids: tuple[str, ...] = (),
    security: tuple[AceEntry, ...] = (),
    acl_obtained: bool = True,
    schema_version: int = 2,
) -> CertTemplate:
    return CertTemplate(
        name=name,
        display_name=name,
        schema_version=schema_version,
        oid=f"1.3.6.1.4.1.311.21.8.{name}",
        ekus=ekus,
        name_flags=frozenset(name_flags),
        enrollment_flags=frozenset(enrollment_flags),
        min_key_size=2048,
        issuance_policy_oids=issuance_policy_oids,
        security=security,
        published_by=(),
        acl_obtained=acl_obtained,
    )


def _ca(
    name: str,
    *,
    kind: CaKind = CaKind.ISSUING,
    edit_flags: tuple[str, ...] = (),
    interface_flags: tuple[str, ...] = (),
    certs: tuple[CertLifecycle, ...] = (),
    security: tuple[AceEntry, ...] = (),
) -> CertAuthority:
    return CertAuthority(
        name=name,
        dns="",
        config_string=f"host\\{name}",
        kind=kind,
        edit_flags=frozenset(edit_flags),
        interface_flags=frozenset(interface_flags),
        audit_filter=None,
        validity="",
        roles=frozenset(),
        security=security,
        certs=certs,
    )


def _ctrl_ace(
    sid: str = LOW_PRIV_SID, *, right: str = "WriteDacl", ace_type: AceType = AceType.ALLOW
) -> AceEntry:
    return AceEntry(trustee_sid=sid, trustee_name="trustee", rights=(right,), ace_type=ace_type)


def _deny_enroll(sid: str = LOW_PRIV_SID) -> AceEntry:
    """A Deny-Enroll ACE on a low-priv trustee (for Deny-precedence tests)."""
    return _ctrl_ace(sid=sid, right="Enroll", ace_type=AceType.DENY)


def _pki_acl(
    kind: AclKind,
    *,
    dn: str = "CN=Obj,CN=Public Key Services,CN=Services,CN=Configuration,DC=x",
    security: tuple[AceEntry, ...] = (),
) -> PkiObjectAcl:
    return PkiObjectAcl(object_dn=dn, kind=kind, security=security)


def _endpoint(
    kind: EndpointKind = EndpointKind.WEB_ENROLLMENT,
    *,
    name: str = "/CertSrv",
    transports: tuple[str, ...] = ("http", "https"),
    ssl_required: bool = False,
    windows_auth: bool = True,
    auth_providers: tuple[str, ...] = ("negotiate", "ntlm"),
    epa: EpaPolicy = EpaPolicy.NONE,
) -> EnrollmentEndpoint:
    return EnrollmentEndpoint(
        kind=kind,
        name=name,
        transports=frozenset(transports),
        ssl_required=ssl_required,
        windows_auth=windows_auth,
        auth_providers=frozenset(auth_providers),
        epa=epa,
    )


def _estate(
    *,
    cas: tuple[CertAuthority, ...] = (),
    templates: tuple[CertTemplate, ...] = (),
    acls: tuple[PkiObjectAcl, ...] = (),
    crls: tuple[Crl, ...] = (),
    oids: tuple[IssuanceOid, ...] = (),
    endpoints: tuple[EnrollmentEndpoint, ...] = (),
    dcs: tuple[DcConfiguration, ...] = (),
    principal_mappings: tuple[PrincipalMapping, ...] = (),
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
        cas=cas,
        templates=templates,
        acls=acls,
        oids=oids,
        crls=crls,
        endpoints=endpoints,
        dcs=dcs,
        principal_mappings=principal_mappings,
        manifest=manifest,
    )


def _dc(
    name: str = "DC01",
    *,
    strong_binding: StrongCertBinding = StrongCertBinding.DISABLED,
    schannel_methods: tuple[SchannelMappingMethod, ...] = (),
) -> DcConfiguration:
    return DcConfiguration(
        name=name,
        strong_certificate_binding_enforcement=strong_binding,
        schannel_mapping_methods=frozenset(schannel_methods),
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


# --- ESC10 -----------------------------------------------------------------


def test_esc10_flagged_when_binding_disabled() -> None:
    """Case 2: StrongCertificateBindingEnforcement Disabled -> HIGH."""
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("WeakDC", strong_binding=StrongCertBinding.DISABLED),))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "WeakDC"
    assert "disabled" in findings[0].detail.lower()


def test_esc10_flagged_when_schannel_upn_bit_set() -> None:
    """Case 1: Schannel UPN mapping bit -> HIGH even under strict binding."""
    from adcs_lens.detection import detect_esc10

    estate = _estate(
        dcs=(
            _dc(
                "UpnDC",
                strong_binding=StrongCertBinding.STRICT,
                schannel_methods=(SchannelMappingMethod.UPN,),
            ),
        )
    )
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10"
    assert findings[0].severity == Severity.HIGH
    assert "upn" in findings[0].detail.lower()


def test_esc10_not_flagged_when_strict_and_no_upn() -> None:
    from adcs_lens.detection import detect_esc10

    estate = _estate(
        dcs=(
            _dc(
                "StrongDC",
                strong_binding=StrongCertBinding.STRICT,
                schannel_methods=(SchannelMappingMethod.S4U2SELF,),
            ),
        )
    )
    assert detect_esc10(estate) == []


def test_esc10_permissive_is_medium() -> None:
    """Compatibility mode without the UPN bit is a transitional MEDIUM."""
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("CompatDC", strong_binding=StrongCertBinding.PERMISSIVE),))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10"
    assert findings[0].severity == Severity.MEDIUM
    assert "compatibility" in findings[0].detail.lower()


def test_esc10_unknown_enforcement_emits_note_not_high() -> None:
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("DC-UNKNOWN", strong_binding=StrongCertBinding.UNKNOWN),))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10_ENFORCEMENT_UNKNOWN"
    assert findings[0].severity == Severity.INFO


def test_esc10_degrades_when_pass_skipped() -> None:
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("DC01"),), skipped_passes=("esc10-dc-registry",))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "DC_REGISTRY_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc10_clean_when_pass_ran_and_no_dcs() -> None:
    from adcs_lens.detection import detect_esc10

    assert detect_esc10(_estate(dcs=())) == []


def test_run_all_includes_esc10() -> None:
    estate = _estate(dcs=(_dc("DC01", strong_binding=StrongCertBinding.DISABLED),))
    assert "ESC10" in {f.check for f in run_all(estate)}


# --- ESC14 -----------------------------------------------------------------


def _weak_dc() -> DcConfiguration:
    return _dc("DC01", strong_binding=StrongCertBinding.DISABLED)


def test_esc14_flagged_when_weak_form_and_non_strict_dc() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=(
                    "X509:<I>CN=CA<S>CN=Service Account",  # issuer+subject = weak
                    "CN=Service Account,OU=SA,DC=test",  # non-X.509, ignored
                ),
            ),
        ),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14"
    assert findings[0].severity == Severity.HIGH
    assert "Service Account" in findings[0].subject


def test_esc14_not_flagged_for_strong_forms_only() -> None:
    """The KB5014754 correction: issuer+serial and SKI are STRONG, never flagged."""
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Strong,DC=test",
                mappings=(
                    "X509:<I>CN=CA<SR>1200AABBCC",  # issuer+serial = strong
                    "X509:<SKI>aB1cD2eF3",  # SKI = strong
                    "X509:<SHA1-PUKEY>cD2eF3",  # SHA1 public key = strong
                ),
            ),
        ),
    )
    assert detect_esc14(estate) == []


def test_esc14_not_flagged_when_no_x509_mappings() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Regular User,OU=Users,DC=test",
                mappings=("kerberos:user@TEST.LOCAL",),
            ),
        ),
    )
    assert detect_esc14(estate) == []


def test_esc14_not_flagged_when_all_dcs_strict() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_dc("DC01", strong_binding=StrongCertBinding.STRICT),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=("X509:<I>CN=CA<S>CN=Service Account",),
            ),
        ),
    )
    assert detect_esc14(estate) == []


def test_esc14_not_flagged_when_no_principal_mappings() -> None:
    from adcs_lens.detection import detect_esc14

    assert detect_esc14(_estate(dcs=(_weak_dc(),), principal_mappings=())) == []


def test_esc14_degrades_when_pass_skipped() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=("X509:<I>CN=CA<S>CN=Service Account",),
            ),
        ),
        skipped_passes=("esc14-altsecid",),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ALTSECID_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc14_clean_when_pass_ran_and_no_mappings() -> None:
    from adcs_lens.detection import detect_esc14

    assert detect_esc14(_estate(dcs=(_weak_dc(),), principal_mappings=())) == []


def test_esc14_enforcement_unknown_when_dc_registry_skipped() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(),
        principal_mappings=(
            PrincipalMapping(dn="CN=X,DC=test", mappings=("X509:<S>CN=X",)),
        ),
        skipped_passes=("esc10-dc-registry",),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14_ENFORCEMENT_UNKNOWN"
    assert findings[0].severity == Severity.INFO


def test_esc14_enforcement_unknown_when_binding_unreadable() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_dc("DC-UNKNOWN", strong_binding=StrongCertBinding.UNKNOWN),),
        principal_mappings=(
            PrincipalMapping(dn="CN=X,DC=test", mappings=("X509:<S>CN=X",)),
        ),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14_ENFORCEMENT_UNKNOWN"
    assert findings[0].severity == Severity.INFO


def test_x509_mapping_form_classification() -> None:
    from adcs_lens.detection import _x509_mapping_form
    from adcs_lens.model import X509MappingForm

    assert _x509_mapping_form("X509:<I>CN=CA<S>CN=Svc") is X509MappingForm.ISSUER_SUBJECT
    assert _x509_mapping_form("X509:<S>CN=Svc") is X509MappingForm.SUBJECT_ONLY
    assert _x509_mapping_form("X509:<RFC822>u@test") is X509MappingForm.RFC822
    assert _x509_mapping_form("X509:<PN>u@test") is X509MappingForm.PRINCIPAL_NAME
    assert _x509_mapping_form("X509:<I>CN=CA<SR>12AB") is X509MappingForm.ISSUER_SERIAL
    assert _x509_mapping_form("X509:<SKI>aabb") is X509MappingForm.SKI
    assert _x509_mapping_form("X509:<SHA1-PUKEY>aabb") is X509MappingForm.SHA1_PUBLIC_KEY
    # case-insensitive prefix; whitespace tolerant
    assert _x509_mapping_form("  x509:<s>CN=Svc  ") is X509MappingForm.SUBJECT_ONLY
    # non-X.509 / unrecognized
    assert _x509_mapping_form("kerberos:u@TEST") is X509MappingForm.UNKNOWN
    assert _x509_mapping_form("") is X509MappingForm.UNKNOWN
    assert _x509_mapping_form("X509:<I>CN=CA") is X509MappingForm.UNKNOWN  # issuer-only


def test_esc14_empty_mappings_not_flagged() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(PrincipalMapping(dn="CN=X,DC=test", mappings=()),),
    )
    assert detect_esc14(estate) == []


def test_esc14_lists_only_non_strict_dcs() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(
            _dc("VULN-DC", strong_binding=StrongCertBinding.DISABLED),
            _dc("SAFE-DC", strong_binding=StrongCertBinding.STRICT),
        ),
        principal_mappings=(
            PrincipalMapping(dn="CN=X,DC=test", mappings=("X509:<S>CN=X",)),
        ),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14"
    assert "VULN-DC" in findings[0].detail
    assert "SAFE-DC" not in findings[0].detail


def test_run_all_includes_esc14() -> None:
    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=("X509:<I>CN=CA<S>CN=Service Account",),
            ),
        ),
    )
    assert "ESC14" in {f.check for f in run_all(estate)}


# --- template ACL gap -----------------------------------------------------


def test_acl_gap_emits_one_info_per_unreadable_template() -> None:
    # One unreadable template (otherwise ESC1-positive) + one readable clean one.
    unreadable = _template("Unreadable", security=(_enroll_ace(),), acl_obtained=False)
    readable = _template("Readable", security=(_enroll_ace(),), acl_obtained=True)
    findings = detect_template_acl_gaps(_estate(templates=(unreadable, readable)))
    assert len(findings) == 1
    assert findings[0].check == "TEMPLATE_ACL_UNREADABLE"
    assert findings[0].severity == Severity.INFO
    assert findings[0].subject == "Unreadable"
    # Detail enumerates exactly the ACL-dependent detectors that were skipped.
    assert "ESC1/2/3/4/13" in findings[0].detail


def test_acl_gap_silent_when_template_security_not_collected() -> None:
    # Estate-level degrade owns the note when the whole pass was skipped.
    tmpl = _template("Unreadable", security=(_enroll_ace(),), acl_obtained=False)
    estate = _estate(templates=(tmpl,), skipped_passes=("template-security",))
    assert detect_template_acl_gaps(estate) == []


def test_esc1_skips_unreadable_template() -> None:
    # ESC1-positive but acl_obtained=False -> gap detector owns the note, ESC1 silent.
    tmpl = _template("Unreadable", security=(_enroll_ace(),), acl_obtained=False)
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc4_skips_unreadable_template() -> None:
    # ESC4-positive (WriteDacl to low-priv) but acl_obtained=False -> ESC4 silent.
    tmpl = _template(
        "Writable", security=(_enroll_ace(right="WriteDacl"),), acl_obtained=False
    )
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc2_skips_unreadable_template() -> None:
    # No-EKU (any-purpose) + low-priv enroll is ESC2-positive, but unreadable DACL
    # means the enroll ACL cannot be evaluated -> ESC2 silent, gap detector owns it.
    tmpl = _template("Any", ekus=(), security=(_enroll_ace(),), acl_obtained=False)
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc3_skips_unreadable_template() -> None:
    tmpl = _template(
        "Agent", ekus=(ENROLLMENT_AGENT,), security=(_enroll_ace(),), acl_obtained=False
    )
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc9_still_evaluates_unreadable_template() -> None:
    # ESC9 does not depend on the ACL — still flagged even when acl_obtained=False.
    tmpl = _template(
        "WeakMap", enrollment_flags=("NO_SECURITY_EXTENSION",), acl_obtained=False
    )
    findings = detect_esc9(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC9"


def test_acl_gap_wired_into_run_all() -> None:
    # Unreadable-template estate: TEMPLATE_ACL_UNREADABLE present, matching ESC1
    # absent, but ESC9 present because the template also has NO_SECURITY_EXTENSION.
    tmpl = _template(
        "Unreadable",
        security=(_enroll_ace(),),
        enrollment_flags=("NO_SECURITY_EXTENSION",),
        acl_obtained=False,
    )
    checks = {f.check for f in run_all(_estate(templates=(tmpl,)))}
    assert "TEMPLATE_ACL_UNREADABLE" in checks
    assert "ESC1" not in checks
    assert "ESC9" in checks


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


# --- ESC11 ----------------------------------------------------------------


def test_esc11_flagged_when_flag_absent() -> None:
    estate = _estate(cas=(_ca("IssuingCA", interface_flags=()),))
    findings = detect_esc11(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC11"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "IssuingCA"
    assert "InterfaceFlags" in findings[0].source


def test_esc11_clean_when_flag_present() -> None:
    estate = _estate(
        cas=(_ca("IssuingCA", interface_flags=("IF_ENFORCEENCRYPTICERTREQUEST",)),)
    )
    assert detect_esc11(estate) == []


def test_esc11_root_ca_not_flagged_even_if_flag_absent() -> None:
    estate = _estate(cas=(_ca("RootCA", kind=CaKind.ROOT, interface_flags=()),))
    assert detect_esc11(estate) == []


def test_esc11_flagged_when_only_unrelated_flags_present() -> None:
    # An unrelated interface flag does not mask the absence of the encryption
    # requirement — this is exactly the CA that should be flagged.
    estate = _estate(cas=(_ca("IssuingCA", interface_flags=("IF_LOCKICERTREQUEST",)),))
    findings = detect_esc11(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC11"


# --- ESC13 ----------------------------------------------------------------


def test_esc13_flagged_when_policy_linked_and_low_priv_enroll() -> None:
    tmpl = _template(
        "LinkedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    findings = detect_esc13(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC13"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "LinkedPolicy"
    assert DOMAIN_ADMINS_SID in findings[0].detail


def test_esc13_not_flagged_when_policy_not_group_linked() -> None:
    tmpl = _template(
        "UnlinkedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", None),),
    )
    assert detect_esc13(estate) == []


def test_esc13_not_flagged_without_auth_eku() -> None:
    tmpl = _template(
        "ServerPolicy",
        ekus=(SERVER_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    assert detect_esc13(estate) == []


def test_esc13_mitigated_by_manager_approval() -> None:
    tmpl = _template(
        "ApprovedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        enrollment_flags=("PEND_ALL_REQUESTS",),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    assert detect_esc13(estate) == []


def test_esc13_requires_low_priv_enroll() -> None:
    tmpl = _template(
        "AdminPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(HIGH_PRIV_SID),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    assert detect_esc13(estate) == []


def test_esc13_silent_when_template_security_not_collected() -> None:
    tmpl = _template(
        "LinkedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
        skipped_passes=("template-security",),
    )
    assert detect_esc13(estate) == []


def test_esc13_skips_unreadable_template() -> None:
    # ESC13 also depends on the enroll ACL; an unreadable-DACL template with a
    # group-linked policy is skipped (the gap detector owns the note).
    tmpl = _template(
        "UnreadablePolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
        acl_obtained=False,
    )
    estate = _estate(
        templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),)
    )
    assert detect_esc13(estate) == []
    # And the gap detector surfaces it instead.
    assert any(
        f.check == "TEMPLATE_ACL_UNREADABLE" for f in detect_template_acl_gaps(estate)
    )


def test_esc13_flagged_when_no_eku() -> None:
    # No EKU = valid for any purpose (incl. client auth) -> the dangerous
    # SubCA-equivalent case; still auth-capable, so still ESC13.
    tmpl = _template(
        "NoEkuPolicy", ekus=(), issuance_policy_oids=(POLICY_OID,), security=(_enroll_ace(),)
    )
    estate = _estate(templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),))
    assert len(detect_esc13(estate)) == 1


def test_esc13_flagged_with_any_purpose_eku() -> None:
    tmpl = _template(
        "AnyPurposePolicy",
        ekus=(ANY_PURPOSE,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),))
    assert len(detect_esc13(estate)) == 1


def test_esc13_not_flagged_when_template_has_no_policy() -> None:
    tmpl = _template("Plain", ekus=(CLIENT_AUTH,), security=(_enroll_ace(),))
    estate = _estate(
        templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),)
    )
    assert detect_esc13(estate) == []


def test_esc13_not_flagged_when_oid_absent_from_estate() -> None:
    # Template references a policy OID that is not present (or not group-linked)
    # in estate.oids -> no join -> no finding.
    tmpl = _template(
        "OrphanPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    assert detect_esc13(_estate(templates=(tmpl,), oids=())) == []


# --- ESC15 ----------------------------------------------------------------


def test_esc15_flagged_for_v1_template_low_priv_enroll() -> None:
    from adcs_lens.detection import detect_esc15

    # A v1 template with no auth EKU and no supplies-subject is still ESC15: the
    # requester injects the application policy under EKUwu.
    tmpl = _template(
        "WebServerV1",
        schema_version=1,
        ekus=("1.3.6.1.5.5.7.3.1",),  # serverAuth — not a client-auth EKU
        name_flags=(),
        security=(_enroll_ace(),),
    )
    findings = detect_esc15(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC15"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "WebServerV1"
    assert "CVE-2024-49019" in findings[0].detail


def test_esc15_not_flagged_for_v2_template() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("ModernTemplate", schema_version=2, security=(_enroll_ace(),))
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_esc15_mitigated_by_manager_approval() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template(
        "V1Approved",
        schema_version=1,
        enrollment_flags=("PEND_ALL_REQUESTS",),
        security=(_enroll_ace(),),
    )
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_esc15_requires_low_priv_enroll() -> None:
    from adcs_lens.detection import detect_esc15

    # v1 template but only a high-priv trustee can enroll -> not ESC15.
    tmpl = _template(
        "V1Restricted",
        schema_version=1,
        security=(_enroll_ace(sid="S-1-5-21-1-2-3-512"),),  # Domain Admins
    )
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_esc15_silent_when_template_security_not_collected() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("V1", schema_version=1, security=(_enroll_ace(),))
    estate = _estate(templates=(tmpl,), skipped_passes=("template-security",))
    assert detect_esc15(estate) == []


def test_esc15_skips_unreadable_template() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("V1", schema_version=1, acl_obtained=False, security=())
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_run_all_includes_esc15() -> None:
    tmpl = _template("V1", schema_version=1, security=(_enroll_ace(),))
    assert "ESC15" in {f.check for f in run_all(_estate(templates=(tmpl,)))}


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


# --- ESC8 -----------------------------------------------------------------


def test_esc8_web_enrollment_http_ntlm_is_high() -> None:
    # /certsrv over HTTP with NTLM and no EPA — the textbook relay case.
    estate = _estate(endpoints=(_endpoint(),))
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC8"
    assert findings[0].severity == Severity.HIGH
    assert "cleartext HTTP" in findings[0].detail


def test_esc8_https_only_no_epa_negotiate_is_medium() -> None:
    # HTTPS-only, Negotiate (no explicit NTLM), EPA off -> weaker (MEDIUM).
    estate = _estate(
        endpoints=(
            _endpoint(
                transports=("https",),
                ssl_required=True,
                auth_providers=("negotiate",),
                epa=EpaPolicy.NONE,
            ),
        )
    )
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_esc8_https_only_explicit_ntlm_no_epa_is_high() -> None:
    estate = _estate(
        endpoints=(
            _endpoint(
                transports=("https",),
                ssl_required=True,
                auth_providers=("negotiate", "ntlm"),
                epa=EpaPolicy.NONE,
            ),
        )
    )
    assert detect_esc8(estate)[0].severity == Severity.HIGH


def test_esc8_mitigated_when_epa_required_and_https_only() -> None:
    estate = _estate(
        endpoints=(
            _endpoint(transports=("https",), ssl_required=True, epa=EpaPolicy.REQUIRE),
        )
    )
    assert detect_esc8(estate) == []


def test_esc8_http_open_flagged_even_with_epa_required() -> None:
    # EPA Require does not help if the endpoint is still reachable over HTTP.
    estate = _estate(endpoints=(_endpoint(epa=EpaPolicy.REQUIRE),))
    assert detect_esc8(estate)[0].severity == Severity.HIGH


def test_esc8_kerberos_only_not_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(auth_providers=("kerberos",)),))
    assert detect_esc8(estate) == []


def test_esc8_no_windows_auth_not_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(windows_auth=False),))
    assert detect_esc8(estate) == []


def test_esc8_ndes_not_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(kind=EndpointKind.NDES),))
    assert detect_esc8(estate) == []


def test_esc8_ces_endpoint_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(kind=EndpointKind.CES, name="/CES"),))
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].subject == "/CES"


def test_esc8_degrades_when_pass_skipped() -> None:
    estate = _estate(endpoints=(), skipped_passes=("enrollment-endpoints",))
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].check == "ENROLLMENT_ENDPOINTS_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc8_clean_when_pass_ran_and_no_endpoints() -> None:
    assert detect_esc8(_estate(endpoints=())) == []


def test_run_all_includes_esc8() -> None:
    estate = _estate(endpoints=(_endpoint(),))
    assert "ESC8" in {f.check for f in run_all(estate)}


# --- ESC5 -----------------------------------------------------------------


def test_esc5_ntauth_writable_is_critical() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="WriteDacl"),)),),
    )
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC5"
    assert findings[0].severity == Severity.CRITICAL
    assert "NTAuthCertificates" in findings[0].detail
    assert "WriteDacl" in findings[0].detail


def test_esc5_ca_object_writable_is_critical() -> None:
    estate = _estate(acls=(_pki_acl(AclKind.CA_OBJECT, security=(_ctrl_ace(right="GenericAll"),)),))
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_esc5_container_writable_is_high() -> None:
    for kind in (AclKind.PKS_CONTAINER, AclKind.AIA, AclKind.CDP):
        estate = _estate(acls=(_pki_acl(kind, security=(_ctrl_ace(right="GenericWrite"),)),))
        findings = detect_esc5(estate)
        assert len(findings) == 1, kind
        assert findings[0].severity == Severity.HIGH, kind


def test_esc5_not_flagged_for_high_priv_trustee() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(HIGH_PRIV_SID, right="WriteDacl"),)),),
    )
    assert detect_esc5(estate) == []


def test_esc5_not_flagged_for_read_or_enroll_rights() -> None:
    estate = _estate(
        acls=(
            _pki_acl(
                AclKind.NTAUTH,
                security=(_ctrl_ace(right="ReadProperty"), _ctrl_ace(right="Enroll")),
            ),
        ),
    )
    assert detect_esc5(estate) == []


def test_esc5_not_flagged_for_scoped_writeproperty() -> None:
    # A property-scoped WriteProperty (non-blanket) is not treated as control,
    # mirroring ESC4; only WritePropertyAll / Generic* / WriteDacl / WriteOwner.
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="WriteProperty"),)),),
    )
    assert detect_esc5(estate) == []


def test_esc5_writepropertyall_is_flagged() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.CA_OBJECT, security=(_ctrl_ace(right="WritePropertyAll"),)),),
    )
    assert len(detect_esc5(estate)) == 1


def test_esc5_deny_ace_ignored() -> None:
    estate = _estate(
        acls=(
            _pki_acl(
                AclKind.NTAUTH,
                security=(_ctrl_ace(right="WriteDacl", ace_type=AceType.DENY),),
            ),
        ),
    )
    assert detect_esc5(estate) == []


def test_esc5_clean_when_pass_ran_and_no_dangerous_aces() -> None:
    estate = _estate(acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="ReadProperty"),)),))
    assert detect_esc5(estate) == []


def test_esc5_degrades_when_pass_skipped() -> None:
    estate = _estate(acls=(), skipped_passes=("pki-acls",))
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].check == "PKI_ACL_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc5_subject_falls_back_to_kind_when_dn_empty() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, dn="", security=(_ctrl_ace(right="WriteOwner"),)),),
    )
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].subject == AclKind.NTAUTH.value


def test_run_all_includes_esc5() -> None:
    estate = _estate(acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="WriteDacl"),)),))
    checks = {f.check for f in run_all(estate)}
    assert "ESC5" in checks


def test_run_all_includes_esc11_and_esc13() -> None:
    # Lock the wiring: both new detectors are reachable through run_all.
    tmpl = _template(
        "LinkedPolicy",
        ekus=(CLIENT_AUTH,),
        name_flags=(),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        cas=(_ca("RelayCA", interface_flags=()),),
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),),
    )
    checks = {f.check for f in run_all(estate)}
    assert "ESC11" in checks
    assert "ESC13" in checks


def test_severity_rank_is_worst_first_not_alphabetical() -> None:
    # run_all sorts by SEVERITY_RANK; a StrEnum would otherwise sort
    # alphabetically as critical,high,info,low,medium (INFO before MEDIUM/LOW).
    # This locks the explicit rank against such a regression.
    from adcs_lens.model import SEVERITY_RANK

    worst_first = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    assert list(SEVERITY_RANK.keys()) == worst_first
    # Ordering the enum members by the rank must NOT match naive sorted() order.
    by_rank = sorted(worst_first, key=SEVERITY_RANK.__getitem__)
    assert by_rank == worst_first
    # If this ever fails, Severity gained a natural order — revisit the rank.
    assert by_rank != sorted(worst_first)


def test_run_all_puts_info_degradation_last() -> None:
    # Real-output smoke: an INFO degradation note must sort after every actionable
    # finding, not between HIGH and (future) MEDIUM.
    cert = CertLifecycle(
        "CN=Soon", CertKind.ISSUING_CA, NOW, NOW + timedelta(days=30), "sha256", 2048
    )
    estate = _estate(
        templates=(_template("Vuln", security=(_enroll_ace(),)),),  # ESC1 CRITICAL
        cas=(_ca("CA", certs=(cert,)),),  # cert-expiry HIGH
        skipped_passes=("ca-security",),  # ESC7 INFO degradation note
    )
    findings = run_all(estate, now=NOW)
    assert findings[-1].severity == Severity.INFO
    assert findings[0].severity == Severity.CRITICAL


# --- Deny-ACE precedence --------------------------------------------------


def test_esc1_suppressed_when_same_right_denied() -> None:
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="Enroll", ace_type=AceType.DENY)
    assert detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),))) == []


def test_esc1_suppressed_by_broad_deny() -> None:
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="GenericAll", ace_type=AceType.DENY)
    assert detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),))) == []


def test_esc1_not_suppressed_when_unrelated_right_denied() -> None:
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    findings = detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"


def test_esc1_not_suppressed_when_autoenroll_denied() -> None:
    # AutoEnroll is a distinct extended right; denying it must not block Enroll.
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="AutoEnroll", ace_type=AceType.DENY)
    findings = detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"


def test_esc1_specific_deny_beats_broad_allow() -> None:
    allow = _enroll_ace(right="GenericAll")
    deny = _ctrl_ace(right="Enroll", ace_type=AceType.DENY)
    assert detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),))) == []


def test_esc1_broad_allow_survives_unrelated_deny() -> None:
    allow = _enroll_ace(right="GenericAll")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    findings = detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"


def test_esc4_suppressed_when_control_right_denied() -> None:
    allow = _enroll_ace(right="WriteDacl")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    assert detect_esc4(_estate(templates=(_template("T", security=(allow, deny)),))) == []


def test_esc4_not_suppressed_when_only_one_control_right_denied() -> None:
    allow = _enroll_ace(right="GenericAll")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    findings = detect_esc4(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC4"
    assert "WriteDacl" not in findings[0].detail
    assert "GenericAll" in findings[0].detail


def test_esc7_suppressed_when_manageca_denied() -> None:
    allow = _enroll_ace(right="ManageCA")
    deny = _ctrl_ace(right="ManageCA", ace_type=AceType.DENY)
    assert detect_esc7(_estate(cas=(_ca("CA", security=(allow, deny)),))) == []


def test_esc7_suppressed_by_broad_deny() -> None:
    allow = _enroll_ace(right="ManageCA")
    deny = _ctrl_ace(right="GenericAll", ace_type=AceType.DENY)
    assert detect_esc7(_estate(cas=(_ca("CA", security=(allow, deny)),))) == []


def test_esc7_not_suppressed_when_managecertificates_denied() -> None:
    allow = _enroll_ace(right="ManageCA")
    deny = _ctrl_ace(right="ManageCertificates", ace_type=AceType.DENY)
    findings = detect_esc7(_estate(cas=(_ca("CA", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC7"
    assert findings[0].severity == Severity.CRITICAL


def test_esc5_suppressed_when_control_right_denied() -> None:
    allow = _ctrl_ace(right="WriteDacl")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    assert (
        detect_esc5(
            _estate(acls=(_pki_acl(AclKind.NTAUTH, security=(allow, deny)),))
        )
        == []
    )


# Broad enroll rights must still fire when unblocked (guards the coverage
# expansion that the _ENROLL_RIGHTS narrowing introduced).
def test_esc1_all_extended_rights_still_fires() -> None:
    tmpl = _template("AER", security=(_enroll_ace(right="AllExtendedRights"),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


def test_esc1_full_control_still_fires() -> None:
    tmpl = _template("FC", security=(_enroll_ace(right="FullControl"),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


# Each enroll-dependent detector is wired through the shared Deny-aware path —
# one test each so a future refactor that inlines the check can't silently drop
# Deny precedence without a test catching it.
def test_esc2_suppressed_when_enroll_denied() -> None:
    tmpl = _template("Any", ekus=(ANY_PURPOSE,), security=(_enroll_ace(), _deny_enroll()))
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc3_suppressed_when_enroll_denied() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT,), security=(_enroll_ace(), _deny_enroll()))
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc13_suppressed_when_enroll_denied() -> None:
    tmpl = _template(
        "Linked",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(), _deny_enroll()),
    )
    estate = _estate(
        templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),)
    )
    assert detect_esc13(estate) == []


def test_esc15_suppressed_when_enroll_denied() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("V1", schema_version=1, security=(_enroll_ace(), _deny_enroll()))
    assert detect_esc15(_estate(templates=(tmpl,))) == []


# A single multi-right Allow ACE with one right denied: the finding still fires
# (WriteOwner survives) but only the surviving right is rendered.
def test_esc4_rendering_hides_only_blocked_right() -> None:
    allow = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="trustee",
        rights=("WriteDacl", "WriteOwner"),
        ace_type=AceType.ALLOW,
    )
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    tmpl = _template("Multi", security=(allow, deny))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert "WriteOwner" in findings[0].detail
    assert "WriteDacl" not in findings[0].detail
