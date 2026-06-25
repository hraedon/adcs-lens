"""Generate a synthetic AD CS export directory for tests.

Declarative Python, not hand-maintained JSON/DER blobs (the gpo-lens lesson:
hand-written fixtures are a time bomb). All identifiers are synthetic
placeholders — no work-domain CA/template/OID/SID/domain names ever (AGENTS.md
hard rule).

The export models the two-tier SMB case the charter targets: an offline root CA
plus an online issuing CA, with one ESC6-positive CA and a root CRL that is past
its nextUpdate (the catastrophic-but-invisible case).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Synthetic placeholders only.
DOMAIN = "lab.example.com"
ROOT_CA = "LAB Root CA"
ISSUING_CA = "LAB Issuing CA"
LOW_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-513"  # "Domain Users"
TEMPLATE_OID = "1.3.6.1.4.1.311.21.8.1.2.3.4.100"
POLICY_OID = "1.3.6.1.4.1.311.21.8.1.2.3.4.200"


def _write_json(path: Path, obj: Any, *, bom: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoding = "utf-8-sig" if bom else "utf-8"
    path.write_text(json.dumps(obj, indent=2), encoding=encoding)


def build_export(
    out_dir: str | Path,
    *,
    with_certs: bool = False,
    now: datetime | None = None,
) -> Path:
    """Write a synthetic export into *out_dir*; return its path."""
    base = Path(out_dir)
    now = now or datetime.now(UTC)

    # collector-manifest.json — emitted with a UTF-8 BOM (PowerShell 5.1 writes
    # one) to keep the ingest BOM-tolerance honest.
    _write_json(
        base / "collector-manifest.json",
        {
            "collector_version": "0.1.0-fixture",
            "collected_at": now.isoformat(),
            "host": "LABCA01",
            "domain": DOMAIN,
            "skipped_passes": [],
        },
        bom=True,
    )

    _write_json(
        base / "ca-config.json",
        [
            {
                "name": ROOT_CA,
                "dns": "",
                "config_string": f"OFFLINE\\{ROOT_CA}",
                "kind": "root",
                "edit_flags": [],
                "interface_flags": [],
                "audit_filter": 127,
                "validity": "20 Years",
                "roles": [],
            },
            {
                "name": ISSUING_CA,
                "dns": f"labca01.{DOMAIN}",
                "config_string": f"labca01.{DOMAIN}\\{ISSUING_CA}",
                "kind": "issuing",
                # ESC6 enabling flag.
                "edit_flags": ["EDITF_ATTRIBUTESUBJECTALTNAME2"],
                "interface_flags": ["IF_ENFORCEENCRYPTICERTREQUEST"],
                "audit_filter": 0,
                "validity": "5 Years",
                "roles": ["Web Enrollment"],
            },
        ],
    )

    _write_json(
        base / "ca-security.json",
        {
            ISSUING_CA: [
                {
                    "trustee_sid": LOW_PRIV_SID,
                    "trustee_name": "Domain Users",
                    "rights": ["ManageCertificates"],
                    "ace_type": "Allow",
                }
            ]
        },
    )

    _write_json(
        base / "templates.json",
        [
            {
                "name": "LabWebServer",
                "display_name": "Lab Web Server",
                "schema_version": 2,
                "oid": TEMPLATE_OID,
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth (not client auth -> not ESC1)
                "name_flags": ["ENROLLEE_SUPPLIES_SUBJECT"],
                # ESC9 enabling flag: issued certs omit the SID security extension.
                "enrollment_flags": ["NO_SECURITY_EXTENSION"],
                "min_key_size": 2048,
                "issuance_policy_oids": [POLICY_OID],
                # Low-priv enroll is present, but the EKU is Server Auth (not a
                # client-auth EKU), so this is *not* ESC1 — exercises the template
                # security round-trip without a false positive.
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["Enroll"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # ESC15 (EKUwu): a schema v1 template, low-priv enrollable, no
                # manager approval. Server-Auth EKU and no supplies-subject keep it
                # clear of ESC1/ESC2 — the EKUwu risk is the v1 schema itself.
                "name": "LegacyV1WebServer",
                "display_name": "Legacy V1 Web Server",
                "schema_version": 1,
                "oid": "1.3.6.1.4.1.311.21.8.legacyv1",
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth
                "name_flags": [],
                "enrollment_flags": [],
                "min_key_size": 2048,
                "issuance_policy_oids": [],
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["Enroll"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # Unreadable-DACL template: the collector ran the template-security
                # pass but this template's nTSecurityDescriptor came back empty
                # (LDAP denial), so acl_obtained is False. It is configured
                # ESC1-positive (enrollee-supplied subject + a client-auth EKU) to
                # prove the detectors SKIP it rather than falsely clear it — the
                # TEMPLATE_ACL_UNREADABLE gap detector surfaces the gap instead.
                "name": "LabKrbClientUnreadable",
                "display_name": "Lab Krb Client (unreadable)",
                "schema_version": 2,
                "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.101",
                "ekus": ["1.3.6.1.5.5.7.3.2"],  # Client Auth -> would be ESC1 if readable
                "name_flags": ["ENROLLEE_SUPPLIES_SUBJECT"],
                "enrollment_flags": [],
                "min_key_size": 2048,
                "issuance_policy_oids": [],
                "security": [],  # SD not obtained
                "acl_obtained": False,
            },
        ],
    )

    _write_json(base / "enrollment-services.json", {ISSUING_CA: [TEMPLATE_OID]})

    _write_json(
        base / "pki-acls.json",
        [
            {
                # Benign: a *scoped* WriteProperty is not object control, so this
                # exercises the ingest round-trip WITHOUT a false ESC5 positive.
                "object_dn": "CN=NTAuthCertificates,...,DC=lab,DC=example,DC=com",
                "kind": "ntauth",
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["WriteProperty"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # ESC5-positive: low-priv WriteDacl on the PKS container is
                # object control (a path to a rogue template / enrollment service).
                "object_dn": "CN=Public Key Services,...,DC=lab,DC=example,DC=com",
                "kind": "pks_container",
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["WriteDacl"],
                        "ace_type": "Allow",
                    }
                ],
            },
        ],
    )

    _write_json(
        base / "oid-objects.json",
        [{"oid": POLICY_OID, "name": "Lab High Assurance", "group_link": None}],
    )

    # ESC8: Web Enrollment reachable over HTTP with NTLM and no Extended
    # Protection (the textbook relay case); a Kerberos-only CES that must NOT
    # flag (exercises the negative branch through the full pipeline).
    _write_json(
        base / "web-endpoints.json",
        [
            {
                "kind": "web_enrollment",
                "name": "/CertSrv",
                "transports": ["http", "https"],
                "ssl_required": False,
                "windows_auth": True,
                "auth_providers": ["Negotiate", "NTLM"],
                "epa": "none",
            },
            {
                "kind": "ces",
                "name": "/LAB_CES_Kerberos",
                "transports": ["https"],
                "ssl_required": True,
                "windows_auth": True,
                "auth_providers": ["Kerberos"],
                "epa": "require",
            },
        ],
    )

    # ESC10: DC registry config. The fixture models a weak configuration
    # (permissive enforcement + weak mapping methods enabled) to exercise the
    # detector. A second DC with strict enforcement exercises the negative branch.
    # LAB-DC01: ESC10 both cases — binding Disabled (case 2) + Schannel UPN bit
    # (case 1). LAB-DC02: Full enforcement, no UPN bit — the negative branch.
    _write_json(
        base / "dc-config.json",
        [
            {
                "name": "LAB-DC01",
                "strong_certificate_binding_enforcement": "disabled",
                "schannel_mapping_methods": ["upn", "s4u2self", "s4u2self_explicit"],
            },
            {
                "name": "LAB-DC02",
                "strong_certificate_binding_enforcement": "strict",
                "schannel_mapping_methods": ["s4u2self", "s4u2self_explicit"],
            },
        ],
    )

    # ESC14: a principal with a weak (reusable) issuer+subject mapping should flag
    # (LAB-DC01 is non-strict); a principal with only strong (nonreusable) forms —
    # issuer+serial and SKI — must NOT flag; a Kerberos-only principal must NOT flag.
    _write_json(
        base / "principal-mappings.json",
        [
            {
                "dn": "CN=Service Account,OU=Service Accounts,DC=lab,DC=example,DC=com",
                "mappings": [
                    "X509:<I>DC=com,DC=example,CN=LAB-CA<S>DC=com,DC=example,CN=Service Account",
                    "1.3.6.1.4.1.311.20.2.3=Service Account@lab.example.com",
                ],
            },
            {
                "dn": "CN=Strong Mapped,OU=Service Accounts,DC=lab,DC=example,DC=com",
                "mappings": [
                    "X509:<I>DC=com,DC=example,CN=LAB-CA<SR>1200000000AABBCCDD",
                    "X509:<SKI>aB1cD2eF3gH4iJ5kL6mN7oP8qR",
                ],
            },
            {
                "dn": "CN=Regular User,OU=Users,DC=lab,DC=example,DC=com",
                "mappings": [
                    "kerberos:user@LAB.EXAMPLE.COM",
                ],
            },
        ],
    )

    if with_certs:
        _write_certs(base, now=now)

    return base


def _write_certs(base: Path, *, now: datetime) -> None:
    """Write synthetic DER certs/CRLs and their index (needs cryptography)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    _DER = Encoding.DER
    certs_dir = base / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)

    def _self_signed(
        cn: str,
        not_before: datetime,
        not_after: datetime,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256())
        )
        return cert, key

    # Root cert: healthy. Issuing cert: expiring within 30 days (should flag).
    root_cert, root_key = _self_signed(
        ROOT_CA, now - timedelta(days=3650), now + timedelta(days=3650)
    )
    iss_cert, iss_key = _self_signed(
        ISSUING_CA, now - timedelta(days=1700), now + timedelta(days=30)
    )
    (certs_dir / "root.cer").write_bytes(root_cert.public_bytes(_DER))
    (certs_dir / "issuing.cer").write_bytes(iss_cert.public_bytes(_DER))

    # Root CRL: past nextUpdate (the silent estate-wide failure). Issuing CRL: fresh.
    root_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(now - timedelta(days=400))
        .next_update(now - timedelta(days=35))  # expired
        .sign(root_key, hashes.SHA256())
    )
    iss_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(iss_cert.subject)
        .last_update(now - timedelta(days=2))
        .next_update(now + timedelta(days=5))
        .sign(iss_key, hashes.SHA256())  # signed by the issuing CA, not the root
    )
    (certs_dir / "root.crl").write_bytes(root_crl.public_bytes(_DER))
    (certs_dir / "issuing.crl").write_bytes(iss_crl.public_bytes(_DER))

    _write_json(
        certs_dir / "index.json",
        {
            "certs": [
                {"file": "root.cer", "ca_name": ROOT_CA, "kind": "root_ca"},
                {"file": "issuing.cer", "ca_name": ISSUING_CA, "kind": "issuing_ca"},
            ],
            "crls": [
                {
                    "file": "root.crl",
                    "issuer": ROOT_CA,
                    "tier": "root",
                    "source": "published: AD AIA container (root is offline)",
                },
                {
                    "file": "issuing.crl",
                    "issuer": ISSUING_CA,
                    "tier": "issuing",
                    "source": "host: LABCA01",
                },
            ],
        },
    )


if __name__ == "__main__":  # manual generation for inspection
    import sys

    out = build_export(
        sys.argv[1] if len(sys.argv) > 1 else "./synthetic-export", with_certs=True
    )
    print(f"wrote synthetic export to {out}")
