"""Deterministic detectors. No AI, no I/O, no probing — pure functions over an
:class:`~adcs_lens.model.Estate`.

This first slice carries two checks that exercise both data paths end-to-end
(Plan 001 Phase 3): ESC6 on the config path and infrastructure cert/CRL expiry
on the lifecycle path. Each finding is traceable to the exact source fact, per
the charter's "evidence-producing" principle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from adcs_lens.model import CertKind, Crl, CrlTier, Estate, Severity

# ESC6: requester-supplied SAN honored CA-wide regardless of template.
_EDITF_SAN2 = "EDITF_ATTRIBUTESUBJECTALTNAME2"


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
        *detect_esc6(estate),
        *detect_infra_cert_expiry(estate, now=now, warn_days=warn_days),
    ]
    findings.sort(key=lambda f: (f.severity, f.check, f.subject))
    return findings
