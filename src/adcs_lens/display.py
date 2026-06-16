"""Rendering of findings — text and JSON. Pure, stdlib-only.

The JSON envelope is the stable contract the later narration/report layers will
consume, so it is versioned and emitted even when there are zero findings.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict

from adcs_lens.detection import Finding
from adcs_lens.model import Severity

SCHEMA_VERSION = 1


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity (every severity key present, zero-filled)."""
    counts = Counter(f.severity.value for f in findings)
    return {sev.value: counts.get(sev.value, 0) for sev in Severity}


def render_json(findings: list[Finding]) -> str:
    """Serialize findings + summary as a stable JSON envelope."""
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "kind": "doctor",
        "summary": summarize(findings),
        "findings": [asdict(f) for f in findings],
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
    return "\n".join(lines)
