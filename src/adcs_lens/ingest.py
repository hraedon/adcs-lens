"""Ingest a read-only collector export directory into a normalized :class:`Estate`.

Stdlib-only. Cert/CRL (DER) parsing is delegated lazily to the optional
:mod:`adcs_lens.certs` module (the ``[certs]`` extra); when it is unavailable
the import fails softly, lifecycle fields stay ``None``, and
:attr:`Manifest.certs_parsed` is ``False`` so the lifecycle detector degrades to
a note instead of producing wrong answers.

The JSON shapes read here are the ingest contract: the future PowerShell
collector (``scripts/Export-AdcsEstate.ps1``, Plan 001 Phase 1) and the
synthetic test fixtures both target them. BOM-tolerant (``utf-8-sig``) because
PowerShell 5.1 writes UTF-8 with a BOM.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adcs_lens.model import (
    AceEntry,
    CertAuthority,
    CertLifecycle,
    CertTemplate,
    Crl,
    Estate,
    IssuanceOid,
    Manifest,
    PkiObjectAcl,
)
from adcs_lens.normalize import normalize_sid


def _load(export_dir: Path, name: str) -> Any:
    """Load one JSON file, tolerating a BOM and a missing file (-> None)."""
    path = export_dir / name
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _ace(d: dict[str, Any]) -> AceEntry:
    return AceEntry(
        trustee_sid=normalize_sid(str(d.get("trustee_sid", ""))),
        trustee_name=str(d.get("trustee_name", "")),
        rights=tuple(d.get("rights", [])),
        ace_type=str(d.get("ace_type", "Allow")),
    )


def _aces(items: Any) -> tuple[AceEntry, ...]:
    return tuple(_ace(d) for d in (items or []))


def _try_load_certs() -> Any:
    """Import the optional cert parser, or return None when [certs] is absent."""
    try:
        from adcs_lens import certs

        return certs
    except ImportError:
        return None


def ingest(export_dir: str | Path) -> Estate:
    """Parse a collector export directory into a normalized :class:`Estate`."""
    base = Path(export_dir)

    raw_manifest = _load(base, "collector-manifest.json") or {}
    certs_mod = _try_load_certs()

    # --- certificates & CRLs (optional [certs] path) ---
    cert_by_ca: dict[str, list[CertLifecycle]] = {}
    crls: list[Crl] = []
    index = _load(base, "certs/index.json")
    if certs_mod is not None and index is not None:
        for entry in index.get("certs", []):
            der = (base / "certs" / entry["file"]).read_bytes()
            lifecycle = certs_mod.parse_cert(der, kind=entry.get("kind", "other"))
            cert_by_ca.setdefault(entry.get("ca_name", ""), []).append(lifecycle)
        for entry in index.get("crls", []):
            der = (base / "certs" / entry["file"]).read_bytes()
            crls.append(
                certs_mod.parse_crl(
                    der,
                    tier=entry.get("tier", "issuing"),
                    source=entry.get("source", ""),
                )
            )

    # --- CA configuration + security + roles ---
    ca_security = _load(base, "ca-security.json") or {}
    cas: list[CertAuthority] = []
    for ca in _load(base, "ca-config.json") or []:
        name = str(ca.get("name", ""))
        cas.append(
            CertAuthority(
                name=name,
                dns=str(ca.get("dns", "")),
                config_string=str(ca.get("config_string", "")),
                kind=str(ca.get("kind", "issuing")),
                edit_flags=frozenset(ca.get("edit_flags", [])),
                interface_flags=frozenset(ca.get("interface_flags", [])),
                audit_filter=ca.get("audit_filter"),
                validity=str(ca.get("validity", "")),
                roles=frozenset(ca.get("roles", [])),
                security=_aces(ca_security.get(name)),
                certs=tuple(cert_by_ca.get(name, [])),
            )
        )

    # --- templates + which enrollment service publishes them ---
    published_by: dict[str, list[str]] = {}
    for ca_name, tmpls in (_load(base, "enrollment-services.json") or {}).items():
        for ref in tmpls:
            published_by.setdefault(str(ref), []).append(str(ca_name))

    templates = []
    for t in _load(base, "templates.json") or []:
        oid = str(t.get("oid", ""))
        name = str(t.get("name", ""))
        pubs = published_by.get(oid) or published_by.get(name) or []
        templates.append(
            _template(t, oid=oid, name=name, published_by=tuple(pubs))
        )

    acls = tuple(
        PkiObjectAcl(
            object_dn=str(a.get("object_dn", "")),
            kind=str(a.get("kind", "")),
            security=_aces(a.get("security")),
        )
        for a in (_load(base, "pki-acls.json") or [])
    )

    oids = tuple(
        IssuanceOid(
            oid=str(o.get("oid", "")),
            name=str(o.get("name", "")),
            group_link_sid=(
                normalize_sid(o["group_link_sid"]) if o.get("group_link_sid") else None
            ),
        )
        for o in (_load(base, "oid-objects.json") or [])
    )

    manifest = Manifest(
        collector_version=str(raw_manifest.get("collector_version", "unknown")),
        collected_at=str(raw_manifest.get("collected_at", "")),
        host=str(raw_manifest.get("host", "")),
        domain=str(raw_manifest.get("domain", "")),
        skipped_passes=tuple(raw_manifest.get("skipped_passes", [])),
        certs_parsed=certs_mod is not None,
    )

    return Estate(
        cas=tuple(cas),
        templates=tuple(templates),
        acls=acls,
        oids=oids,
        crls=tuple(crls),
        manifest=manifest,
    )


def _template(
    t: dict[str, Any], *, oid: str, name: str, published_by: tuple[str, ...]
) -> CertTemplate:
    return CertTemplate(
        name=name,
        display_name=str(t.get("display_name", name)),
        schema_version=int(t.get("schema_version", 1)),
        oid=oid,
        ekus=tuple(t.get("ekus", [])),
        name_flags=frozenset(t.get("name_flags", [])),
        enrollment_flags=frozenset(t.get("enrollment_flags", [])),
        min_key_size=t.get("min_key_size"),
        issuance_policy_oids=tuple(t.get("issuance_policy_oids", [])),
        security=_aces(t.get("security")),
        published_by=published_by,
    )
