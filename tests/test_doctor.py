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
