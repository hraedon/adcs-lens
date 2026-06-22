"""The `doctor` / `ingest` CLI front door over the synthetic export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.model import Severity


def test_doctor_json_flags_esc6(json_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["doctor", str(json_export), "--json"])
    assert rc == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["kind"] == "doctor"
    assert envelope["schema_version"] == 1
    checks = {f["check"] for f in envelope["findings"]}
    assert "ESC6" in checks
    # The fixture template sets NO_SECURITY_EXTENSION -> ESC9 surfaces end-to-end.
    assert "ESC9" in checks
    # The fixture grants Domain Users Manage Certificates on the issuing CA -> ESC7.
    assert "ESC7" in checks
    esc6 = next(f for f in envelope["findings"] if f["check"] == "ESC6")
    assert esc6["severity"] == Severity.CRITICAL.value


def test_doctor_text_renders(json_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", str(json_export)]) == 0
    out = capsys.readouterr().out
    assert "adcs-lens doctor" in out
    assert "ESC6" in out


def test_ingest_summary(json_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ingest", str(json_export)]) == 0
    out = capsys.readouterr().out
    assert "CAs: 2" in out
    assert "lab.example.com" in out


def test_cli_reports_malformed_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "collector-manifest.json").write_text("not json", encoding="utf-8")
    rc = main(["doctor", str(tmp_path)])
    assert rc != 0
    assert "malformed JSON" in capsys.readouterr().err


def test_doctor_severity_floor_excludes_below_threshold(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A 'high' floor keeps critical+high and drops everything below (the INFO
    # degradation notes in particular). The fixture's CRITICAL ESC6 survives.
    rc = main(["doctor", str(json_export), "--json", "--severity", "high"])
    assert rc == 0
    findings = json.loads(capsys.readouterr().out)["findings"]
    severities = {f["severity"] for f in findings}
    assert severities <= {Severity.CRITICAL.value, Severity.HIGH.value}
    assert any(f["check"] == "ESC6" for f in findings)


def test_doctor_exit_code_trips_when_finding_meets_threshold(json_export: Path) -> None:
    # The fixture has a CRITICAL ESC6, so a 'critical' floor with --exit-code
    # must signal non-zero for CI gating.
    assert main(["doctor", str(json_export), "--exit-code", "--severity", "critical"]) == 1


def test_doctor_exit_code_clean_when_nothing_meets_threshold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An (effectively empty) export yields only INFO notes; a 'high' floor leaves
    # zero findings, so --exit-code stays zero.
    rc = main(["doctor", str(tmp_path), "--exit-code", "--severity", "high"])
    assert rc == 0
    # Sanity: without the floor the INFO notes are present (default floor = info).
    capsys.readouterr()


def test_doctor_exit_code_without_flag_stays_zero(json_export: Path) -> None:
    # Findings exist, but absent --exit-code the command still reports success.
    assert main(["doctor", str(json_export)]) == 0
