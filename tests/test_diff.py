"""Drift detection (Stance 2) — the diff between two posture snapshots."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import Finding
from adcs_lens.diff import diff_findings
from adcs_lens.display import render_diff_json, render_diff_text
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


def test_diff_source_disambiguates_same_subject() -> None:
    # Two CRL_EXPIRY findings on the same issuer but different sources (e.g. two
    # CDPs) must not collapse: a newly-expired second CRL is a real new finding,
    # not "unchanged" against the first.
    old = [Finding(check="CRL_EXPIRY", severity=Severity.CRITICAL, title="t",
                   subject="LAB CA", detail="d", source="CRL from CDP-A")]
    new = [
        Finding(check="CRL_EXPIRY", severity=Severity.CRITICAL, title="t",
                subject="LAB CA", detail="d", source="CRL from CDP-A"),
        Finding(check="CRL_EXPIRY", severity=Severity.CRITICAL, title="t",
                subject="LAB CA", detail="d", source="CRL from CDP-B"),
    ]
    report = diff_findings(old, new)
    assert len(report.new) == 1
    assert report.new[0].source == "CRL from CDP-B"
    assert report.unchanged == 1
    assert report.regressions is True


def test_diff_source_change_is_new_and_resolved_not_content() -> None:
    # A source change is a new+resolved pair (source is part of the identity),
    # not a content change on the same issue.
    old = [_f("ESC1", "TemplA")]
    new = [Finding(check="ESC1", severity=Severity.HIGH, title="ESC1 on TemplA",
                  subject="TemplA", detail="d", source="new source")]
    report = diff_findings(old, new)
    assert report.changed == ()
    assert len(report.new) == 1
    assert len(report.resolved) == 1


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


def test_cli_diff_exit_code_ignores_degradation_notes(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A degradation note (coverage-gap INFO) is a coverage signal, not a posture
    # regression. An empty baseline vs the populated fixture yields the fixture's
    # real findings as new regressions (trips --exit-code); but the reverse —
    # populated fixture vs an empty export that only emits degrade notes — must
    # NOT trip --exit-code on those notes alone. We assert the empty-export path
    # produces degrade notes that are visible but do not gate.
    # Empty export (no manifest passes declared) -> degrade notes only.
    (tmp_path / "collector-manifest.json").write_text(
        json.dumps({"skipped_passes": ["enrollment-endpoints", "pki-acls",
                                        "ca-security", "template-security"]}),
        encoding="utf-8",
    )
    rc = main(["diff", str(json_export), str(tmp_path), "--json", "--exit-code"])
    assert rc == 0
    env = json.loads(capsys.readouterr().out)
    # The JSON summary's `regressions` flag agrees with the gate (both exclude
    # degradation notes) — no display-vs-gate inconsistency.
    assert env["summary"]["regressions"] is False
    # The degrade notes are still surfaced in the `new` list (visible, not dropped).
    assert any(f["check"].endswith("_NOT_EVALUATED") for f in env["new"])


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


def test_diff_detects_content_change_same_severity() -> None:
    old = [_f("ESC1", "TemplA")]
    new = [
        Finding(
            check="ESC1",
            severity=Severity.HIGH,
            title="ESC1 on TemplA",
            subject="TemplA",
            detail="new detail",
            source="s",
        )
    ]
    report = diff_findings(old, new)
    assert len(report.changed) == 1
    delta = report.changed[0]
    assert delta.worsened is False
    assert delta.content_changed is True
    assert report.regressions is False
    assert report.unchanged == 0


def test_diff_identical_content_is_unchanged() -> None:
    old = [_f("ESC1", "TemplA")]
    new = [_f("ESC1", "TemplA")]
    report = diff_findings(old, new)
    assert report.changed == ()
    assert report.unchanged == 1
    assert report.regressions is False


def test_content_change_does_not_trip_diff_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = diff_findings(
        old=[_f("ESC1", "TemplA", Severity.HIGH)],
        new=[Finding(
            check="ESC1",
            severity=Severity.HIGH,
            title="ESC1 on TemplA",
            subject="TemplA",
            detail="wider enroller set",
            source="s",
        )],
    )
    assert report.regressions is False
    out = render_diff_text(report)
    assert "[~ CHANGED]" in out


def test_diff_json_emits_content_changed_field() -> None:
    # The --json diff envelope must surface content-only changes with a
    # content_changed flag so a CI consumer can distinguish them from
    # severity changes (WI-028).
    report = diff_findings(
        old=[_f("ESC1", "TemplA", Severity.HIGH)],
        new=[
            Finding(
                check="ESC1",
                severity=Severity.HIGH,
                title="ESC1 on TemplA",
                subject="TemplA",
                detail="changed detail",
                source="s",
            )
        ],
    )
    env = json.loads(render_diff_json(report))
    assert len(env["changed"]) == 1
    entry = env["changed"][0]
    assert entry["worsened"] is False
    assert entry["content_changed"] is True
