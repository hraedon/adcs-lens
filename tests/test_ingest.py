"""Ingest contract: the synthetic export round-trips to a populated Estate."""

from __future__ import annotations

from pathlib import Path

from adcs_lens.ingest import ingest
from adcs_lens.normalize import is_low_priv_trustee


def test_manifest_and_counts(json_export: Path) -> None:
    estate = ingest(json_export)
    assert estate.manifest.host == "LABCA01"
    assert estate.manifest.domain == "lab.example.com"
    assert "esc10_dc_registry" in estate.manifest.skipped_passes
    assert len(estate.cas) == 2
    assert len(estate.templates) == 1


def test_bom_tolerant(json_export: Path) -> None:
    # collector-manifest.json is written with a UTF-8 BOM; ingest must not choke.
    raw = (json_export / "collector-manifest.json").read_bytes()
    assert raw[:3] == b"\xef\xbb\xbf", "fixture should exercise the BOM path"
    assert ingest(json_export).manifest.collector_version == "0.1.0-fixture"


def test_ca_flags_and_kind(json_export: Path) -> None:
    estate = ingest(json_export)
    issuing = next(c for c in estate.cas if c.kind == "issuing")
    assert "EDITF_ATTRIBUTESUBJECTALTNAME2" in issuing.edit_flags
    root = next(c for c in estate.cas if c.kind == "root")
    assert root.edit_flags == frozenset()


def test_published_by_join(json_export: Path) -> None:
    estate = ingest(json_export)
    tmpl = estate.templates[0]
    # enrollment-services.json publishes the template by OID under the issuing CA.
    assert "LAB Issuing CA" in tmpl.published_by


def test_sid_normalized_and_low_priv(json_export: Path) -> None:
    estate = ingest(json_export)
    issuing = next(c for c in estate.cas if c.kind == "issuing")
    ace = issuing.security[0]
    assert ace.trustee_sid.startswith("S-1-5-21-")
    assert is_low_priv_trustee(ace.trustee_sid)


def test_certs_parsed_reflects_extra(json_export: Path) -> None:
    # No certs/ dir in the json-only export; certs_parsed mirrors module
    # availability (True when [certs] installed, False otherwise) — never crashes.
    estate = ingest(json_export)
    assert isinstance(estate.manifest.certs_parsed, bool)
    assert estate.crls == ()


def test_missing_files_degrade_to_empty(tmp_path: Path) -> None:
    # A near-empty export (only a manifest) ingests without raising.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    estate = ingest(tmp_path)
    assert estate.cas == ()
    assert estate.templates == ()
