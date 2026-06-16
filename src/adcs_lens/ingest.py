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
    AceType,
    AclKind,
    CaKind,
    CertAuthority,
    CertKind,
    CertLifecycle,
    CertTemplate,
    Crl,
    CrlTier,
    Estate,
    IssuanceOid,
    Manifest,
    PkiObjectAcl,
)
from adcs_lens.normalize import normalize_sid


class IngestError(ValueError):
    """Raised when an export file is malformed or violates the ingest contract."""


Coerced = Any  # alias for the loosely-typed JSON surface


def _coerce_str(value: Coerced) -> str:
    return "" if value is None else str(value).strip()


def _load(export_dir: Path, name: str) -> Any:
    """Load one JSON file, tolerating a BOM and a missing file (-> None)."""
    path = export_dir / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise IngestError(f"{name}: malformed JSON ({exc})") from exc


def _require_list(export_dir: Path, name: str, data: Any) -> list[Any]:
    if data is None:
        return []
    if isinstance(data, list):
        return data
    raise IngestError(f"{name}: expected a JSON array, got {type(data).__name__}")


def _ace(d: Any) -> AceEntry:
    if not isinstance(d, dict):
        raise IngestError(f"ACE entry must be an object, got {type(d).__name__}")
    ace_type_value = _coerce_str(d.get("ace_type", "Allow"))
    try:
        ace_type = AceType(ace_type_value)
    except ValueError as exc:
        raise IngestError(f"invalid ace_type: {ace_type_value!r}") from exc
    return AceEntry(
        trustee_sid=normalize_sid(_coerce_str(d.get("trustee_sid", ""))),
        trustee_name=_coerce_str(d.get("trustee_name", "")),
        rights=tuple(_coerce_str(r) for r in d.get("rights", [])),
        ace_type=ace_type,
    )


def _aces(items: Any) -> tuple[AceEntry, ...]:
    if items is None:
        return ()
    if not isinstance(items, list):
        raise IngestError(f"expected a list of ACEs, got {type(items).__name__}")
    return tuple(_ace(d) for d in items)


def _kind(value: Any, enum: type[Any], context: str, default: str | None = None) -> Any:
    s = _coerce_str(value)
    if not s:
        s = default or ""
    try:
        return enum(s)
    except ValueError as exc:
        raise IngestError(f"invalid {context}: {s!r}") from exc


def _try_load_certs() -> Any:
    """Import the optional cert parser, or return None when [certs] is absent."""
    try:
        from adcs_lens import certs

        return certs
    except ImportError:
        return None


def _cert_file_path(base: Path, entry: Any) -> Path:
    """Resolve a cert/CRL entry's file path and reject directory traversal."""
    if not isinstance(entry, dict):
        raise IngestError("certs/index.json entry must be an object")
    name = entry.get("file")
    if not name:
        raise IngestError("certs/index.json entry missing 'file'")
    name_str = str(name)
    certs_dir = (base / "certs").resolve()
    resolved = (certs_dir / name_str).resolve()
    if not resolved.is_relative_to(certs_dir):
        raise IngestError(f"cert file escapes certs/ directory: {name_str}")
    return resolved


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
        for entry in _require_list(base, "certs/index.json", index.get("certs", [])):
            path = _cert_file_path(base, entry)
            try:
                der = path.read_bytes()
            except OSError as exc:
                raise IngestError(f"cannot read cert file {path.name}: {exc}") from exc
            kind = _kind(entry.get("kind", "other"), CertKind, "cert kind", default="other")
            lifecycle = certs_mod.parse_cert(der, kind=kind)
            cert_by_ca.setdefault(_coerce_str(entry.get("ca_name", "")), []).append(lifecycle)
        for entry in _require_list(base, "certs/index.json", index.get("crls", [])):
            path = _cert_file_path(base, entry)
            try:
                der = path.read_bytes()
            except OSError as exc:
                raise IngestError(f"cannot read CRL file {path.name}: {exc}") from exc
            tier = _kind(entry.get("tier", "issuing"), CrlTier, "CRL tier", default="issuing")
            crls.append(
                certs_mod.parse_crl(
                    der,
                    tier=tier,
                    source=_coerce_str(entry.get("source", "")),
                )
            )

    # --- CA configuration + security + roles ---
    ca_security = _load(base, "ca-security.json") or {}
    if not isinstance(ca_security, dict):
        raise IngestError("ca-security.json must be an object mapping CA name to ACEs")

    cas: list[CertAuthority] = []
    for ca in _require_list(base, "ca-config.json", _load(base, "ca-config.json")):
        if not isinstance(ca, dict):
            raise IngestError("ca-config.json entries must be objects")
        name = _coerce_str(ca.get("name", ""))
        kind = _kind(ca.get("kind", "issuing"), CaKind, "CA kind", default="issuing")
        cas.append(
            CertAuthority(
                name=name,
                dns=_coerce_str(ca.get("dns", "")),
                config_string=_coerce_str(ca.get("config_string", "")),
                kind=kind,
                edit_flags=frozenset(_coerce_str(f) for f in ca.get("edit_flags", [])),
                interface_flags=frozenset(_coerce_str(f) for f in ca.get("interface_flags", [])),
                audit_filter=ca.get("audit_filter"),
                validity=_coerce_str(ca.get("validity", "")),
                roles=frozenset(_coerce_str(r) for r in ca.get("roles", [])),
                security=_aces(ca_security.get(name)),
                certs=tuple(cert_by_ca.get(name, [])),
            )
        )

    # --- templates + which enrollment service publishes them ---
    published_by: dict[str, list[str]] = {}
    enrollment_services = _load(base, "enrollment-services.json") or {}
    if not isinstance(enrollment_services, dict):
        raise IngestError("enrollment-services.json must be an object")
    for ca_name, tmpls in enrollment_services.items():
        for ref in tmpls or []:
            published_by.setdefault(_coerce_str(ref), []).append(_coerce_str(ca_name))

    templates: list[CertTemplate] = []
    for t in _require_list(base, "templates.json", _load(base, "templates.json")):
        if not isinstance(t, dict):
            raise IngestError("templates.json entries must be objects")
        oid = _coerce_str(t.get("oid", ""))
        name = _coerce_str(t.get("name", ""))
        pubs = published_by.get(oid) or published_by.get(name) or []
        schema_version = t.get("schema_version", 1)
        try:
            schema_version = int(schema_version) if schema_version is not None else 1
        except (TypeError, ValueError) as exc:
            raise IngestError(
                f"invalid schema_version for template {name!r}: {schema_version!r}"
            ) from exc
        templates.append(
            _template(
                t,
                oid=oid,
                name=name,
                published_by=tuple(pubs),
                schema_version=schema_version,
            )
        )

    acls_data = _require_list(base, "pki-acls.json", _load(base, "pki-acls.json"))
    acls = tuple(
        PkiObjectAcl(
            object_dn=_coerce_str(a.get("object_dn", "")),
            kind=_kind(a.get("kind", ""), AclKind, "PKI ACL kind", default="pks_container"),
            security=_aces(a.get("security")),
        )
        for a in acls_data
    )

    oids = tuple(
        IssuanceOid(
            oid=_coerce_str(o.get("oid", "")),
            name=_coerce_str(o.get("name", "")),
            group_link_sid=(
                normalize_sid(_coerce_str(o["group_link_sid"])) if o.get("group_link_sid") else None
            ),
        )
        for o in _require_list(base, "oid-objects.json", _load(base, "oid-objects.json"))
    )

    manifest = Manifest(
        collector_version=_coerce_str(raw_manifest.get("collector_version", "unknown")),
        collected_at=_coerce_str(raw_manifest.get("collected_at", "")),
        host=_coerce_str(raw_manifest.get("host", "")),
        domain=_coerce_str(raw_manifest.get("domain", "")),
        skipped_passes=tuple(_coerce_str(p) for p in raw_manifest.get("skipped_passes", [])),
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
    t: dict[str, Any],
    *,
    oid: str,
    name: str,
    published_by: tuple[str, ...],
    schema_version: int,
) -> CertTemplate:
    return CertTemplate(
        name=name,
        display_name=_coerce_str(t.get("display_name", name)),
        schema_version=schema_version,
        oid=oid,
        ekus=tuple(_coerce_str(e) for e in t.get("ekus", [])),
        name_flags=frozenset(_coerce_str(f) for f in t.get("name_flags", [])),
        enrollment_flags=frozenset(_coerce_str(f) for f in t.get("enrollment_flags", [])),
        min_key_size=t.get("min_key_size"),
        issuance_policy_oids=tuple(_coerce_str(p) for p in t.get("issuance_policy_oids", [])),
        security=_aces(t.get("security")),
        published_by=published_by,
    )
