"""Deterministic detectors. No AI, no I/O, no probing — pure functions over an
:class:`~adcs_lens.model.Estate`.

The checks here span both data paths: ESC1 / ESC6 / ESC9 on the config/template
path and infrastructure cert/CRL expiry on the lifecycle path. Each finding is
traceable to the exact source fact, per the charter's "evidence-producing"
principle, and ACL-dependent checks degrade to a note rather than a false
"all clear" when the collector did not capture the relevant security descriptors.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from adcs_lens.model import (
    AceEntry,
    AceType,
    CertKind,
    CertTemplate,
    Crl,
    CrlTier,
    Estate,
    Severity,
)
from adcs_lens.normalize import is_low_priv_trustee

# ESC6: requester-supplied SAN honored CA-wide regardless of template.
_EDITF_SAN2 = "EDITF_ATTRIBUTESUBJECTALTNAME2"

# --- ESC1 / ESC9: template-driven enrollment escalation ----------------------
# Name flags that let the *requester* choose the subject/SAN, so they can name a
# privileged principal. Either form qualifies (collector emits the MS names).
_ENROLLEE_SUPPLIES_SUBJECT = frozenset(
    {"ENROLLEE_SUPPLIES_SUBJECT", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"}
)
# Enrollment flag that gates issuance behind a CA manager — mitigates ESC1.
_MANAGER_APPROVAL = "PEND_ALL_REQUESTS"
# Enrollment flag behind ESC9 (issued cert omits szOID_NTDS_CA_SECURITY_EXT).
_NO_SECURITY_EXTENSION = "NO_SECURITY_EXTENSION"

# EKUs whose presence lets the issued cert authenticate as its subject. A
# template with *no* EKU is equally dangerous (valid for any purpose).
_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
_PKINIT_CLIENT_AUTH = "1.3.6.1.5.2.3.4"
_ANY_PURPOSE = "2.5.29.37.0"
_AUTH_EKUS = frozenset({_CLIENT_AUTH, _SMARTCARD_LOGON, _PKINIT_CLIENT_AUTH, _ANY_PURPOSE})

# ACE rights (lower-cased) that grant or imply the ability to enroll.
_ENROLL_RIGHTS = frozenset(
    {"enroll", "autoenroll", "allextendedrights", "genericall", "fullcontrol"}
)

# ACE rights (lower-cased) that let a principal rewrite a template object, and so
# turn it into ESC1 (enable enrollee-supplied subject + a client-auth EKU). These
# are object-wide control rights; property-scoped WriteProperty is excluded to
# avoid false positives (the ACE model does not carry the per-property ObjectType).
_DANGEROUS_TEMPLATE_CONTROL = frozenset(
    {"genericall", "genericwrite", "writedacl", "writeowner", "fullcontrol"}
)

# Manifest pass whose absence means template ACLs were not collected (collector
# Phase 1b). ESC checks needing the enroll ACL degrade to a note when it is
# listed in skipped_passes.
_TEMPLATE_SECURITY_PASS = "template-security"

# --- ESC7: CA role permissions held by low-priv principals -------------------
_CA_MANAGE_CA = "manageca"  # CA_ACCESS_ADMIN — full CA control
_CA_MANAGE_CERTS = "managecertificates"  # CA_ACCESS_OFFICER — issue/approve/revoke
_CA_SECURITY_PASS = "ca-security"


@dataclass(frozen=True)
class Finding:
    """One posture finding, traceable to a source fact."""

    check: str  # "ESC6", "CA_CERT_EXPIRY", "CRL_EXPIRY", ...
    severity: Severity
    title: str
    subject: str  # the CA / template / object the finding is about
    detail: str
    source: str  # the exact source fact (registry path, cert file, CRL, ...)
    tier: CrlTier | None = None  # root | issuing for lifecycle findings


def detect_esc6(estate: Estate) -> list[Finding]:
    """Flag any CA with ``EDITF_ATTRIBUTESUBJECTALTNAME2`` set.

    With this flag a requester can put an arbitrary SAN (e.g. a domain admin
    UPN) into *any* issued certificate, regardless of template — a CA-wide
    privilege-escalation primitive. Statically readable from the CA policy
    registry; we flag the enabling flag, we do not request a certificate.
    """
    findings: list[Finding] = []
    for ca in estate.cas:
        if _EDITF_SAN2 in ca.edit_flags:
            findings.append(
                Finding(
                    check="ESC6",
                    severity=Severity.CRITICAL,
                    title="CA honors requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)",
                    subject=ca.name,
                    detail=(
                        "Requesters can specify an arbitrary subjectAltName on any "
                        "template this CA issues, enabling authentication as any "
                        "principal. Remove the flag: certutil -setreg "
                        "policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then "
                        "restart certsvc."
                    ),
                    source=f"{ca.config_string} policy\\EditFlags",
                )
            )
    return findings


def _can_authenticate(template: CertTemplate) -> bool:
    """True if the template's EKUs permit client authentication.

    A template with no EKU at all is valid for any purpose, so it qualifies too.
    """
    if not template.ekus:
        return True
    return any(eku in _AUTH_EKUS for eku in template.ekus)


def _low_priv_allow_aces(
    template: CertTemplate, rights: frozenset[str]
) -> list[AceEntry]:
    """Allow-ACEs granting any of *rights* (lower-cased match) to a low-priv trustee."""
    out: list[AceEntry] = []
    for ace in template.security:
        if ace.ace_type is not AceType.ALLOW:
            continue
        if not is_low_priv_trustee(ace.trustee_sid):
            continue
        if any(r.strip().lower() in rights for r in ace.rights):
            out.append(ace)
    return out


def _low_priv_enrollers(template: CertTemplate) -> list[AceEntry]:
    """Allow-ACEs that grant (or imply) enroll to a low-privilege trustee."""
    return _low_priv_allow_aces(template, _ENROLL_RIGHTS)


def _template_security_collected(estate: Estate) -> bool:
    return _TEMPLATE_SECURITY_PASS not in estate.manifest.skipped_passes


def detect_esc1(estate: Estate) -> list[Finding]:
    """Flag templates that let a low-priv user enroll a cert naming any subject.

    ESC1 holds when a template (a) lets the requester supply the subject/SAN,
    (b) carries a client-authentication EKU (or no EKU), (c) does not require CA
    manager approval, and (d) is enrollable by a low-privilege principal. A
    domain user can then request a certificate *as* a domain admin and
    authenticate as them. Every condition is statically readable; we never
    enroll.

    Degrades honestly: when template security descriptors were not collected
    (collector Phase 1b — ``template-security`` in ``skipped_passes``) the enroll
    ACL cannot be evaluated, so this emits one INFO note instead of silently
    passing.
    """
    if not _template_security_collected(estate):
        return [
            Finding(
                check="TEMPLATE_ACL_NOT_EVALUATED",
                severity=Severity.INFO,
                title="Template enroll permissions not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include template security descriptors, so "
                    "ESC1 enroll-permission checks were skipped. Re-run a collector "
                    "that captures template nTSecurityDescriptor ACEs (Phase 1b)."
                ),
                source="collector-manifest.json: skipped_passes contains 'template-security'",
            )
        ]
    findings: list[Finding] = []
    for tmpl in estate.templates:
        if not (tmpl.name_flags & _ENROLLEE_SUPPLIES_SUBJECT):
            continue
        if not _can_authenticate(tmpl):
            continue
        if _MANAGER_APPROVAL in tmpl.enrollment_flags:
            continue
        enrollers = _low_priv_enrollers(tmpl)
        if not enrollers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in enrollers}))
        findings.append(
            Finding(
                check="ESC1",
                severity=Severity.CRITICAL,
                title="Template lets a low-priv enrollee supply subject + authenticate",
                subject=tmpl.display_name or tmpl.name,
                detail=(
                    f"Enrollable by {who}; the requester supplies the subject/SAN and "
                    "the template carries a client-authentication EKU (or none) with no "
                    "manager approval — a domain user can enroll as any principal. "
                    "Restrict enroll rights, require manager approval, or clear the "
                    "enrollee-supplies-subject flag. (Confirm no issuance/RA-signature "
                    "requirement also gates it — not yet modeled.)"
                ),
                source=f"template '{tmpl.name}' (oid {tmpl.oid}): name flags + enroll ACL",
            )
        )
    return findings


def detect_esc4(estate: Estate) -> list[Finding]:
    """Flag templates a low-privilege principal can rewrite (a path to ESC1).

    ESC4: a low-priv trustee holds an object-wide control right (GenericAll,
    GenericWrite, WriteDacl, WriteOwner) on the template. They can edit the
    template — e.g. turn on enrollee-supplied subjects and add a client-auth EKU
    — converting it into ESC1. We flag the standing control right; we never
    modify the template.

    Shares the ESC1 degradation: when template security was not collected the
    ESC1 detector emits the single ``TEMPLATE_ACL_NOT_EVALUATED`` note, so this
    returns nothing rather than duplicating it.

    Scope: evaluates DACL control rights only. Owner-based control and
    property-scoped ``WriteProperty`` are not yet modeled (the collector reads
    the DACL, not the owner, and ACEs do not carry the per-property ObjectType).
    """
    if not _template_security_collected(estate):
        return []
    findings: list[Finding] = []
    for tmpl in estate.templates:
        controllers = _low_priv_allow_aces(tmpl, _DANGEROUS_TEMPLATE_CONTROL)
        if not controllers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in controllers}))
        rights = ", ".join(
            sorted(
                {
                    r
                    for a in controllers
                    for r in a.rights
                    if r.strip().lower() in _DANGEROUS_TEMPLATE_CONTROL
                }
            )
        )
        findings.append(
            Finding(
                check="ESC4",
                severity=Severity.HIGH,
                title="Template object is writable by a low-privilege principal",
                subject=tmpl.display_name or tmpl.name,
                detail=(
                    f"{who} hold {rights} on the template and can rewrite it (e.g. "
                    "enable enrollee-supplied subjects + a client-auth EKU) to create "
                    "an ESC1 path. Remove the delegated control."
                ),
                source=f"template '{tmpl.name}': nTSecurityDescriptor DACL",
            )
        )
    return findings


def detect_esc7(estate: Estate) -> list[Finding]:
    """Flag CA role rights (Manage CA / Manage Certificates) held by low-priv.

    ESC7: a low-privilege principal holds **Manage CA** (can flip CA policy — e.g.
    turn on EDITF_ATTRIBUTESUBJECTALTNAME2 → ESC6, or publish a vulnerable
    template) or **Manage Certificates** (can approve pending requests / revoke).
    Read from the CA's ``CA\\Security`` registry descriptor; we flag the standing
    right, we never exercise it.

    Degrades to a note when the CA security descriptor was not collected.
    """
    if _CA_SECURITY_PASS in estate.manifest.skipped_passes:
        return [
            Finding(
                check="CA_SECURITY_NOT_EVALUATED",
                severity=Severity.INFO,
                title="CA role permissions not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include the CA security descriptor, so ESC7 "
                    "(Manage CA / Manage Certificates held by low-priv) was skipped. "
                    "Re-run a collector that captures CA\\Security."
                ),
                source="collector-manifest.json: skipped_passes contains 'ca-security'",
            )
        ]
    findings: list[Finding] = []
    for ca in estate.cas:
        by_trustee: dict[str, tuple[str, set[str]]] = {}
        for ace in ca.security:
            if ace.ace_type is not AceType.ALLOW:
                continue
            if not is_low_priv_trustee(ace.trustee_sid):
                continue
            manage = {r.strip().lower() for r in ace.rights} & {
                _CA_MANAGE_CA,
                _CA_MANAGE_CERTS,
            }
            if not manage:
                continue
            _, rights = by_trustee.setdefault(ace.trustee_sid, (ace.trustee_name, set()))
            rights |= manage
        for sid, (name, rights) in by_trustee.items():
            who = name or sid
            if _CA_MANAGE_CA in rights:
                severity = Severity.CRITICAL
                role = "Manage CA (full CA control)"
            else:
                severity = Severity.HIGH
                role = "Manage Certificates (approve/issue/revoke)"
            findings.append(
                Finding(
                    check="ESC7",
                    severity=severity,
                    title="CA role right held by a low-privilege principal",
                    subject=ca.name,
                    detail=(
                        f"{who} holds {role} on this CA. Manage CA can flip CA policy "
                        "(e.g. enable requester-supplied SANs → ESC6) or publish a "
                        "vulnerable template; Manage Certificates can approve pending "
                        "requests. Remove the role from low-privilege principals."
                    ),
                    source=f"{ca.config_string or ca.name}: CA\\Security",
                )
            )
    return findings


def detect_esc9(estate: Estate) -> list[Finding]:
    """Flag templates with CT_FLAG_NO_SECURITY_EXTENSION set.

    ESC9: certificates issued from the template omit the SID security extension,
    so on a DC where ``StrongCertificateBindingEnforcement`` is not enforcing the
    cert can be mapped to a different (higher-privilege) account. We flag the
    enabling template flag; the mapping/relay itself is out of scope. Readable
    from the template enrollment flags with no ACL dependency, so it evaluates on
    every export (unlike ESC1).
    """
    findings: list[Finding] = []
    for tmpl in estate.templates:
        if _NO_SECURITY_EXTENSION in tmpl.enrollment_flags:
            findings.append(
                Finding(
                    check="ESC9",
                    severity=Severity.HIGH,
                    title="Template omits the SID security extension (NO_SECURITY_EXTENSION)",
                    subject=tmpl.display_name or tmpl.name,
                    detail=(
                        "Certificates from this template lack szOID_NTDS_CA_SECURITY_EXT. "
                        "Where DC StrongCertificateBindingEnforcement is not enforcing, the "
                        "cert can be mapped to another account. Clear the flag unless a "
                        "specific mapping scenario requires it."
                    ),
                    source=f"template '{tmpl.name}': msPKI-Enrollment-Flag",
                )
            )
    return findings


def detect_infra_cert_expiry(
    estate: Estate,
    *,
    now: datetime | None = None,
    warn_days: int = 90,
) -> list[Finding]:
    """Flag CA/sub-CA certs and CRLs at/near expiry.

    Root-tier items get explicit top-severity treatment: the box that signs the
    root CRL is offline by design, so an expired root CRL is a silent,
    estate-wide authentication failure nobody is watching for.

    Degrades cleanly: when the export was ingested without the ``[certs]`` extra
    there is no lifecycle data, so this emits a single ``info`` note rather than
    a false "all clear".
    """
    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        raise ValueError("'now' must be timezone-aware (prefer UTC)")

    if not estate.manifest.certs_parsed:
        return [
            Finding(
                check="LIFECYCLE_NOT_EVALUATED",
                severity=Severity.INFO,
                title="Certificate lifecycle not evaluated",
                subject="(estate)",
                detail=(
                    "The export was ingested without DER cert/CRL parsing. Install "
                    "the optional extra (pip install adcs-lens[certs]) and re-run to "
                    "evaluate CA/CRL expiry."
                ),
                source="collector-manifest.json: certs_parsed=false",
            )
        ]

    findings: list[Finding] = []

    for ca in estate.cas:
        for cert in ca.certs:
            if cert.not_after is None:
                continue
            findings.extend(
                _expiry_finding(
                    ca.name, cert.subject, cert.kind, cert.not_after, now, warn_days
                )
            )

    for crl in estate.crls:
        if crl.next_update is None:
            continue
        findings.extend(
            _crl_finding(crl, now, warn_days)
        )
    return findings


def _expiry_finding(
    ca_name: str,
    subject: str,
    kind: CertKind,
    not_after: datetime,
    now: datetime,
    warn_days: int,
) -> list[Finding]:
    days = (not_after - now).days
    root = kind == CertKind.ROOT_CA
    if not_after < now:
        severity = Severity.CRITICAL
        title = "CA certificate has expired"
    elif days <= warn_days:
        # A failing root invalidates the whole estate, so escalate it.
        severity = Severity.CRITICAL if root else Severity.HIGH
        title = f"CA certificate expires in {days} day(s)"
    else:
        return []
    return [
        Finding(
            check="CA_CERT_EXPIRY",
            severity=severity,
            title=title,
            subject=subject or ca_name,
            detail=(
                f"{kind.value} certificate not_after={not_after.isoformat()}"
                + (" — root tier: failure cascades to the entire chain." if root else ".")
            ),
            source=f"CA cert for {ca_name}",
            tier=CrlTier.ROOT if root else CrlTier.ISSUING,
        )
    ]


def _crl_finding(crl: Crl, now: datetime, warn_days: int) -> list[Finding]:
    """Return CRL freshness findings.

    CRLs are typically short-lived (days or weeks), so we flag only expired CRLs
    here rather than applying the cert-style ``warn_days`` window, which would be
    excessively noisy for a 7-day CRL. An explicit early-warning window for CRLs
    can be added later when the model carries CRL validity-period policy.
    """
    del warn_days  # reserved for future CRL validity-policy check
    next_update = crl.next_update
    if next_update is None:
        return []
    root = crl.tier == CrlTier.ROOT
    if next_update < now:
        return [
            Finding(
                check="CRL_EXPIRY",
                severity=Severity.CRITICAL,
                title="Published CRL is past nextUpdate (chain validation fails)",
                subject=crl.issuer,
                detail=(
                    "Clients that fetch this CRL will treat the chain as invalid"
                    + (
                        " — and because the root CRL signer is offline, nobody is "
                        "watching it expire (silent estate-wide auth failure)."
                        if root
                        else "."
                    )
                ),
                source=f"CRL nextUpdate {next_update.isoformat()} ({crl.source})",
                tier=crl.tier,
            )
        ]
    return []


def run_all(
    estate: Estate,
    *,
    now: datetime | None = None,
    warn_days: int = 90,
) -> list[Finding]:
    """Run every detector and return findings sorted worst-first, then by check."""
    findings = [
        *detect_esc1(estate),
        *detect_esc4(estate),
        *detect_esc6(estate),
        *detect_esc7(estate),
        *detect_esc9(estate),
        *detect_infra_cert_expiry(estate, now=now, warn_days=warn_days),
    ]
    findings.sort(key=lambda f: (f.severity, f.check, f.subject))
    return findings
