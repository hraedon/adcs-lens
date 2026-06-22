"""Ingest contract: the synthetic export round-trips to a populated Estate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import CaKind, CrlTier, Severity
from adcs_lens.normalize import is_low_priv_trustee


def test_manifest_and_counts(json_export: Path) -> None:
    estate = ingest(json_export)
    assert estate.manifest.host == "LABCA01"
    assert estate.manifest.domain == "lab.example.com"
    # DC registry is collected in the fixture, so its pass is not skipped. Use the
    # hyphenated pass name the detectors actually gate on (esc10-dc-registry).
    assert "esc10-dc-registry" not in estate.manifest.skipped_passes
    assert len(estate.cas) == 2
    assert len(estate.templates) == 1
    assert len(estate.dcs) == 2


def test_bom_tolerant(json_export: Path) -> None:
    # collector-manifest.json is written with a UTF-8 BOM; ingest must not choke.
    raw = (json_export / "collector-manifest.json").read_bytes()
    assert raw[:3] == b"\xef\xbb\xbf", "fixture should exercise the BOM path"
    assert ingest(json_export).manifest.collector_version == "0.1.0-fixture"


def test_ca_flags_and_kind(json_export: Path) -> None:
    estate = ingest(json_export)
    issuing = next(c for c in estate.cas if c.kind == CaKind.ISSUING)
    assert "EDITF_ATTRIBUTESUBJECTALTNAME2" in issuing.edit_flags
    root = next(c for c in estate.cas if c.kind == CaKind.ROOT)
    assert root.edit_flags == frozenset()


def test_published_by_join(json_export: Path) -> None:
    estate = ingest(json_export)
    tmpl = estate.templates[0]
    # enrollment-services.json publishes the template by OID under the issuing CA.
    assert "LAB Issuing CA" in tmpl.published_by


def test_sid_normalized_and_low_priv(json_export: Path) -> None:
    estate = ingest(json_export)
    issuing = next(c for c in estate.cas if c.kind == CaKind.ISSUING)
    ace = issuing.security[0]
    assert ace.trustee_sid.startswith("S-1-5-21-")
    assert is_low_priv_trustee(ace.trustee_sid)


def test_template_security_round_trips(json_export: Path) -> None:
    # The collector's Phase 1b template DACL pass lands in template.security as
    # normalized ACEs; an Allow/Enroll to a low-priv trustee survives ingest.
    estate = ingest(json_export)
    tmpl = estate.templates[0]
    ace = next(a for a in tmpl.security if "Enroll" in a.rights)
    assert ace.ace_type.value == "Allow"
    assert is_low_priv_trustee(ace.trustee_sid)
    # The fixture does not emit acl_obtained -> default True (no false gap signal).
    assert tmpl.acl_obtained is True


def test_certs_parsed_bool_when_no_certs_dir(json_export: Path) -> None:
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


def test_ca_config_must_be_array(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ca-config.json").write_text('{"not": "an array"}', encoding="utf-8")
    with pytest.raises(IngestError, match="expected a JSON array"):
        ingest(tmp_path)


def test_rejects_directory_traversal(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    (certs_dir / "index.json").write_text(
        '{"certs": [{"file": "../../secret.txt"}]}', encoding="utf-8"
    )
    (tmp_path / "secret.txt").write_text("sensitive", encoding="utf-8")
    with pytest.raises(IngestError, match="escapes certs/"):
        ingest(tmp_path)


def test_null_manifest_fields_coerce_to_empty(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text(
        '{"host": null, "domain": null}', encoding="utf-8"
    )
    m = ingest(tmp_path).manifest
    assert m.host == ""
    assert m.domain == ""


def test_template_acl_obtained_round_trips(tmp_path: Path) -> None:
    # Explicit false round-trips through ingest.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "templates.json").write_text(
        json.dumps([{"name": "T", "acl_obtained": False}]), encoding="utf-8"
    )
    assert ingest(tmp_path).templates[0].acl_obtained is False

    # Absent key defaults to True (backward compat with pre-field exports).
    d2 = tmp_path / "no_key"
    d2.mkdir()
    (d2 / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (d2 / "templates.json").write_text(json.dumps([{"name": "T"}]), encoding="utf-8")
    assert ingest(d2).templates[0].acl_obtained is True

    # Non-bool values (null, string, int) fall back to True — a corrupt/wrong-type
    # field must never raise a false gap signal on a real export.
    for bad in (None, "false", "true", 0, 1):
        d3 = tmp_path / f"bad_{bad!r}"
        d3.mkdir()
        (d3 / "collector-manifest.json").write_text("{}", encoding="utf-8")
        (d3 / "templates.json").write_text(
            json.dumps([{"name": "T", "acl_obtained": bad}]), encoding="utf-8"
        )
        assert ingest(d3).templates[0].acl_obtained is True


def test_full_export_lifecycle(full_export: Path) -> None:
    estate = ingest(full_export)
    assert estate.manifest.certs_parsed is True
    assert len(estate.crls) == 2
    assert any(c.tier == CrlTier.ROOT for c in estate.crls)
    assert any(c.tier == CrlTier.ISSUING for c in estate.crls)


def test_severity_enum_round_trips(json_export: Path) -> None:
    from adcs_lens.detection import run_all
    findings = run_all(ingest(json_export))
    esc6 = next(f for f in findings if f.check == "ESC6")
    assert esc6.severity == Severity.CRITICAL
    # The fixture does not emit acl_obtained; it must default to True so no
    # spurious per-template ACL-gap note appears on backward-compat data.
    assert all(f.check != "TEMPLATE_ACL_UNREADABLE" for f in findings)


def test_esc8_detected_end_to_end(json_export: Path) -> None:
    # The fixture exposes Web Enrollment over HTTP+NTLM+no-EPA (ESC8) and a
    # Kerberos-only EPA-required CES (clean). Exercise the full
    # ingest -> EnrollmentEndpoint -> detect_esc8 pipeline.
    from adcs_lens.detection import run_all
    estate = ingest(json_export)
    assert len(estate.endpoints) == 2
    esc8 = [f for f in run_all(estate) if f.check == "ESC8"]
    assert len(esc8) == 1
    assert esc8[0].severity == Severity.HIGH
    assert esc8[0].subject == "/CertSrv"
    assert all(f.check != "ENROLLMENT_ENDPOINTS_NOT_EVALUATED" for f in run_all(estate))


def test_esc5_detected_end_to_end(json_export: Path) -> None:
    # The fixture carries a benign scoped-WriteProperty NTAuth ACE (no finding)
    # and a low-priv WriteDacl on the PKS container (ESC5). Exercise the full
    # ingest -> PkiObjectAcl -> detect_esc5 pipeline, not just hand-built objects.
    from adcs_lens.detection import run_all
    estate = ingest(json_export)
    assert len(estate.acls) == 2
    esc5 = [f for f in run_all(estate) if f.check == "ESC5"]
    assert len(esc5) == 1
    assert esc5[0].severity == Severity.HIGH
    assert "Public Key Services" in esc5[0].subject
    # The pass ran, so there must be no degrade note.
    assert all(f.check != "PKI_ACL_NOT_EVALUATED" for f in run_all(estate))
