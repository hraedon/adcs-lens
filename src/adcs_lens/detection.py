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

from adcs_lens.model import Estate

# Severity ordering for stable, worst-first reporting.
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# ESC6: requester-supplied SAN honored CA-wide regardless of template.
_EDITF_SAN2 = "EDITF_ATTRIBUTESUBJECTALTNAME2"


@dataclass(frozen=True)
class Finding:
    """One posture finding, traceable to a source fact."""

    check: str  # "ESC6", "CA_CERT_EXPIRY", "CRL_EXPIRY", ...
    severity: str  # critical | high | medium | low | info
    title: str
    subject: str  # the CA / template / object the finding is about
    detail: str
    source: str  # the exact source fact (registry path, cert file, CRL, ...)
    tier: str | None = None  # "root" | "issuing" for lifecycle findings


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
                    severity="critical",
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

    if not estate.manifest.certs_parsed:
        return [
            Finding(
                check="LIFECYCLE_NOT_EVALUATED",
                severity="info",
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
        if crl.next_update < now:
            root = crl.tier == "root"
            findings.append(
                Finding(
                    check="CRL_EXPIRY",
                    severity="critical",
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
                    source=f"CRL nextUpdate {crl.next_update.isoformat()} ({crl.source})",
                    tier=crl.tier,
                )
            )
    return findings


def _expiry_finding(
    ca_name: str,
    subject: str,
    kind: str,
    not_after: datetime,
    now: datetime,
    warn_days: int,
) -> list[Finding]:
    days = (not_after - now).days
    root = kind == "root_ca"
    if not_after < now:
        severity = "critical"
        title = "CA certificate has expired"
    elif days <= warn_days:
        # A failing root invalidates the whole estate, so escalate it.
        severity = "critical" if root else "high"
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
                f"{kind} certificate not_after={not_after.isoformat()}"
                + (" — root tier: failure cascades to the entire chain." if root else ".")
            ),
            source=f"CA cert for {ca_name}",
            tier="root" if root else "issuing",
        )
    ]


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
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.check, f.subject))
    return findings
