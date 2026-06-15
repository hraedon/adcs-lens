"""Normalized data model — the contract every detector depends on.

These dataclasses are the boundary between the collector's on-disk JSON/DER
export and the deterministic detectors. They are frozen and use immutable
collection types (``tuple``/``frozenset``) so a parsed :class:`Estate` cannot be
mutated out from under a detector. Every field maps to a named collector output
(see ``plans/001`` Phase 1 and the threat model's data-source columns).

Cert/CRL lifecycle fields are populated only when the optional ``[certs]`` extra
is installed; otherwise they are ``None`` and lifecycle checks degrade to a note
(:attr:`Manifest.certs_parsed` records which happened).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AceEntry:
    """One access-control entry on a PKI object (shared concept with gpo-lens)."""

    trustee_sid: str
    trustee_name: str
    rights: tuple[str, ...]
    ace_type: str  # "Allow" | "Deny"


@dataclass(frozen=True)
class CertLifecycle:
    """Lifecycle facts parsed from a CA/sub-CA certificate (``[certs]`` path)."""

    subject: str
    kind: str  # "root_ca" | "issuing_ca" | "cross_ca" | "other"
    not_before: datetime | None
    not_after: datetime | None
    sig_alg: str
    key_bits: int | None


@dataclass(frozen=True)
class Crl:
    """A certificate revocation list's freshness facts."""

    issuer: str
    this_update: datetime | None
    next_update: datetime | None
    tier: str  # "root" | "issuing"
    source: str  # where it was captured (published CDP, AD container, host)


@dataclass(frozen=True)
class CertAuthority:
    """A certification authority's configuration, security, and certs."""

    name: str
    dns: str
    config_string: str
    kind: str  # "root" | "issuing" | "standalone"
    edit_flags: frozenset[str]
    interface_flags: frozenset[str]
    audit_filter: int | None
    validity: str
    roles: frozenset[str]
    security: tuple[AceEntry, ...]
    certs: tuple[CertLifecycle, ...]


@dataclass(frozen=True)
class CertTemplate:
    """A certificate template (``pKICertificateTemplate``)."""

    name: str
    display_name: str
    schema_version: int
    oid: str
    ekus: tuple[str, ...]
    name_flags: frozenset[str]
    enrollment_flags: frozenset[str]
    min_key_size: int | None
    issuance_policy_oids: tuple[str, ...]
    security: tuple[AceEntry, ...]
    published_by: tuple[str, ...]


@dataclass(frozen=True)
class PkiObjectAcl:
    """A security descriptor on a Public Key Services object/container."""

    object_dn: str
    kind: str  # "ntauth" | "aia" | "cdp" | "pks_container" | "ca_object"
    security: tuple[AceEntry, ...]


@dataclass(frozen=True)
class IssuanceOid:
    """An enterprise issuance-policy OID and any group it is linked to (ESC13)."""

    oid: str
    name: str
    group_link_sid: str | None


@dataclass(frozen=True)
class Manifest:
    """Provenance of one collection — what was (and was not) read."""

    collector_version: str
    collected_at: str
    host: str
    domain: str
    skipped_passes: tuple[str, ...]
    # True when the lifecycle (cert/CRL) data was actually parsed; False when the
    # [certs] extra was absent at ingest time, so lifecycle checks must degrade.
    certs_parsed: bool


@dataclass(frozen=True)
class Estate:
    """The whole normalized export — the detectors' single input."""

    cas: tuple[CertAuthority, ...]
    templates: tuple[CertTemplate, ...]
    acls: tuple[PkiObjectAcl, ...]
    oids: tuple[IssuanceOid, ...]
    crls: tuple[Crl, ...]
    manifest: Manifest
