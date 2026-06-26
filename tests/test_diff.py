"""Drift detection (Stance 2) — the diff between two posture snapshots."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import Finding
from adcs_lens.diff import diff_findings
from adcs_lens.model import Severity


def _f(check: str, subject: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check=check,
        severity=severity,
        title=f"{check} on {subject}",
        subject=subject,
        detail="d",
        source="s",
    )


def test_diff_detects_new_finding() -> None:
    old = [_f("ESC1", "TemplA")]
    new = [_f("ESC1", "TemplA"), _f("ESC8", "ca01")]
    report = diff_findings(old, new)
    assert [f.check for f in report.new] == ["ESC8"]
    assert report.resolved == ()
    assert report.unchanged == 1
    assert report.regressions is True


def test_diff_detects_resolved_finding() -> None:
    old = [_f("ESC1", "TemplA"), _f("ESC8", "ca01")]
    new = [_f("ESC1", "TemplA")]
    report = diff_findings(old, new)
    assert report.new == ()
    assert [f.check for f in report.resolved] == ["ESC8"]
    assert report.regressions is False


def test_diff_detects_severity_change_worse() -> None:
    old = [_f("ESC10", "dc01", Severity.MEDIUM)]
    new = [_f("ESC10", "dc01", Severity.HIGH)]
    report = diff_findings(old, new)
    assert report.new == ()
    assert report.resolved == ()
    assert len(report.changed) == 1
    delta = report.changed[0]
    assert delta.old.severity == Severity.MEDIUM
    assert delta.new.severity == Severity.HIGH
    assert delta.worsened is True
    assert report.regressions is True


def test_diff_severity_change_better_is_not_regression() -> None:
    old = [_f("ESC10", "dc01", Severity.HIGH)]
    new = [_f("ESC10", "dc01", Severity.MEDIUM)]
    report = diff_findings(old, new)
    assert len(report.changed) == 1
    assert report.changed[0].worsened is False
    assert report.regressions is False


def test_diff_identical_snapshots_is_no_drift() -> None:
    findings = [_f("ESC1", "TemplA"), _f("ESC8", "ca01")]
    report = diff_findings(findings, list(findings))
    assert report.new == ()
    assert report.resolved == ()
    assert report.changed == ()
    assert report.unchanged == 2
    assert report.regressions is False


def test_diff_keys_on_check_and_subject() -> None:
    # Same check, different subject -> independent findings (one resolved, one new).
    old = [_f("ESC5", "objA")]
    new = [_f("ESC5", "objB")]
    report = diff_findings(old, new)
    assert {f.subject for f in report.new} == {"objB"}
    assert {f.subject for f in report.resolved} == {"objA"}


def test_diff_new_findings_sorted_worst_first() -> None:
    old: list[Finding] = []
    new = [_f("ESCx", "s1", Severity.LOW), _f("ESCy", "s2", Severity.CRITICAL)]
    report = diff_findings(old, new)
    assert [f.severity for f in report.new] == [Severity.CRITICAL, Severity.LOW]


# --- CLI ---------------------------------------------------------------------


def test_cli_diff_no_drift_identical_exports(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["diff", str(json_export), str(json_export), "--json"])
    assert rc == 0
    env = json.loads(capsys.readouterr().out)
    assert env["kind"] == "diff"
    assert env["schema_version"] == 2
    assert env["summary"]["new"] == 0
    assert env["summary"]["resolved"] == 0
    assert env["summary"]["regressions"] is False


def test_cli_diff_regressions_against_empty_baseline(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An (effectively empty) baseline vs the populated fixture -> the fixture's
    # findings all read as new regressions; --exit-code trips.
    rc = main(["diff", str(tmp_path), str(json_export), "--exit-code"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "new" in out
    assert "ESC6" in out  # the fixture's CRITICAL surfaces as a new finding


def test_cli_diff_text_renders_no_drift(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["diff", str(json_export), str(json_export)]) == 0
    assert "no drift" in capsys.readouterr().out


def test_cli_diff_json_new_findings_embed_consequence(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["diff", str(tmp_path), str(json_export), "--json"])
    assert rc == 0
    env = json.loads(capsys.readouterr().out)
    assert env["summary"]["new"] > 0
    for f in env["new"]:
        assert "consequence" in f
        assert isinstance(f["consequence"], dict)
        assert "summary" in f["consequence"]
        assert "consequence" in f["consequence"]
        assert "remediation" in f["consequence"]


def test_cli_diff_text_new_finding_shows_plain_terms(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["diff", str(tmp_path), str(json_export)]) == 0
    out = capsys.readouterr().out
    assert "in plain terms:" in out
    assert "how to fix:" in out
