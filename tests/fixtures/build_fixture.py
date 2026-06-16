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
            "skipped_passes": ["esc10_dc_registry", "esc14_altsecid"],
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
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth
                "name_flags": ["ENROLLEE_SUPPLIES_SUBJECT"],
                "enrollment_flags": [],
                "min_key_size": 2048,
                "issuance_policy_oids": [POLICY_OID],
                "security": [],
            }
        ],
    )

    _write_json(base / "enrollment-services.json", {ISSUING_CA: [TEMPLATE_OID]})

    _write_json(
        base / "pki-acls.json",
        [
            {
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
            }
        ],
    )

    _write_json(
        base / "oid-objects.json",
        [{"oid": POLICY_OID, "name": "Lab High Assurance", "group_link_sid": None}],
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
