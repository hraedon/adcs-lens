"""Rendering of findings — text, JSON, and SARIF. Pure, stdlib-only.

The JSON envelope is the stable contract the later narration/report layers will
consume, so it is versioned and emitted even when there are zero findings.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict

from adcs_lens import __version__
from adcs_lens.consequences import consequence_for
from adcs_lens.detection import Finding
from adcs_lens.diff import DriftReport
from adcs_lens.model import Severity

SCHEMA_VERSION = 2

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity (every severity key present, zero-filled)."""
    counts = Counter(f.severity.value for f in findings)
    return {sev.value: counts.get(sev.value, 0) for sev in Severity}


def _finding_with_consequence(f: Finding) -> dict[str, object]:
    """Serialize a finding with its plain-language consequence attached."""
    data = asdict(f)
    entry = consequence_for(f.check)
    if entry is None:
        data["consequence"] = None
    else:
        data["consequence"] = {
            "summary": entry.summary,
            "consequence": entry.consequence,
            "remediation": entry.remediation,
        }
    return data


def render_json(findings: list[Finding]) -> str:
    """Serialize findings + summary as a stable JSON envelope."""
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "kind": "doctor",
        "summary": summarize(findings),
        "findings": [_finding_with_consequence(f) for f in findings],
    }
    return json.dumps(envelope, indent=2, sort_keys=True)


def render_text(findings: list[Finding]) -> str:
    """Render a human-readable, severity-ordered report."""
    lines: list[str] = []
    summary = summarize(findings)
    actionable = sum(v for k, v in summary.items() if k != Severity.INFO.value)
    header = "  ".join(f"{sev.value}={summary[sev.value]}" for sev in Severity)
    lines.append(f"adcs-lens doctor  ::  {actionable} finding(s)  [{header}]")
    if not findings:
        lines.append("  (no findings)")
        return "\n".join(lines)
    for f in findings:
        tier = f" ({f.tier.value}-tier)" if f.tier is not None else ""
        lines.append(f"\n[{f.severity.value.upper()}] {f.check}{tier}  {f.subject}")
        lines.append(f"  {f.title}")
        lines.append(f"  {f.detail}")
        lines.append(f"  source: {f.source}")
        entry = consequence_for(f.check)
        if entry is not None:
            lines.append(f"  in plain terms: {entry.summary} {entry.consequence}")
            lines.append(f"  how to fix: {entry.remediation}")
    return "\n".join(lines)


def render_diff_json(report: DriftReport) -> str:
    """Serialize a drift report as a stable JSON envelope (kind=diff)."""
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "kind": "diff",
        "summary": {
            "new": len(report.new),
            "resolved": len(report.resolved),
            "changed": len(report.changed),
            "unchanged": report.unchanged,
            "regressions": report.regressions,
        },
        "new": [_finding_with_consequence(f) for f in report.new],
        "resolved": [_finding_with_consequence(f) for f in report.resolved],
        "changed": [
            {
                "check": d.new.check,
                "subject": d.new.subject,
                "old_severity": d.old.severity.value,
                "new_severity": d.new.severity.value,
                "worsened": d.worsened,
            }
            for d in report.changed
        ],
    }
    return json.dumps(envelope, indent=2, sort_keys=True)


def render_diff_text(report: DriftReport) -> str:
    """Render a human-readable drift report, regressions first."""
    lines = [
        "adcs-lens diff  ::  "
        f"+{len(report.new)} new  -{len(report.resolved)} resolved  "
        f"~{len(report.changed)} changed  ={report.unchanged} unchanged"
    ]
    if not (report.new or report.resolved or report.changed):
        lines.append("  (no drift)")
        return "\n".join(lines)
    for f in report.new:
        lines.append(f"\n[+ NEW] [{f.severity.value.upper()}] {f.check}  {f.subject}")
        lines.append(f"  {f.title}")
        entry = consequence_for(f.check)
        if entry is not None:
            lines.append(f"  in plain terms: {entry.summary} {entry.consequence}")
            lines.append(f"  how to fix: {entry.remediation}")
    for d in report.changed:
        arrow = "worse" if d.worsened else "better"
        lines.append(
            f"\n[~ {arrow.upper()}] {d.new.check}  {d.new.subject}: "
            f"{d.old.severity.value} -> {d.new.severity.value}"
        )
    for f in report.resolved:
        lines.append(f"\n[- RESOLVED] [{f.severity.value.upper()}] {f.check}  {f.subject}")
        lines.append(f"  {f.title}")
    return "\n".join(lines)


def render_sarif(findings: list[Finding]) -> str:
    """Render findings as a SARIF v2.1.0 log for CI / GRC integration.

    SARIF is the OASIS JSON format that CI systems (GitHub Code Scanning, Azure
    DevOps) and GRC tools consume natively. Rules are de-duplicated by check id
    and sorted so ``ruleIndex`` references are deterministic; results preserve
    the input (worst-first) order. AD CS objects are not files, so the source
    fact is placed in ``logicalLocations`` rather than ``artifactLocation.uri``,
    which would require a valid URI.
    """
    check_ids = sorted({f.check for f in findings})
    index_by_check: dict[str, int] = {check: i for i, check in enumerate(check_ids)}

    rules: list[dict[str, object]] = []
    for check in check_ids:
        entry = consequence_for(check)
        if entry is not None:
            rules.append(
                {
                    "id": check,
                    "name": check,
                    "shortDescription": {"text": entry.summary},
                    "fullDescription": {"text": entry.consequence},
                    "help": {"text": entry.remediation},
                }
            )
        else:
            rules.append(
                {
                    "id": check,
                    "name": check,
                    "shortDescription": {"text": check},
                }
            )

    results: list[dict[str, object]] = []
    for f in findings:
        tier_suffix = f" ({f.tier.value}-tier)" if f.tier is not None else ""
        results.append(
            {
                "ruleId": f.check,
                "ruleIndex": index_by_check[f.check],
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.detail}{tier_suffix}"},
                "logicalLocations": [
                    {
                        "fullyQualifiedName": f.source,
                        "name": f.subject,
                    },
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "adcs-lens",
                        "version": __version__,
                        "informationUri": "https://github.com/hraedon/adcs-lens",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)
