"""Command-line front door. Stdlib ``argparse`` only.

    adcs-lens ingest <export-dir>            # parse + summarize an export
    adcs-lens doctor <export-dir> [--json]   # prioritized posture + lifecycle
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from adcs_lens import __version__
from adcs_lens.detection import run_all
from adcs_lens.diff import diff_findings
from adcs_lens.display import render_diff_json, render_diff_text, render_json, render_text
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import SEVERITY_RANK, Severity


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adcs-lens",
        description="Local-first, read-only AD CS / PKI posture analysis.",
    )
    parser.add_argument("--version", action="version", version=f"adcs-lens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="Parse a collector export and summarize it.")
    p_ingest.add_argument("export_dir", help="Directory produced by the collector.")

    p_doctor = sub.add_parser("doctor", help="Prioritized posture + lifecycle findings.")
    p_doctor.add_argument("export_dir", help="Directory produced by the collector.")
    p_doctor.add_argument("--json", action="store_true", help="Emit the JSON envelope.")
    p_doctor.add_argument(
        "--warn-days",
        type=int,
        default=90,
        help="Flag CA certs/CRLs within this many days of expiry (default: 90).",
    )
    p_doctor.add_argument(
        "--severity",
        choices=[sev.value for sev in Severity],
        default="info",
        help="Minimum severity to include in output (default: info = all).",
    )
    p_doctor.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit non-zero when any finding meets or exceeds --severity (for CI gating).",
    )

    p_diff = sub.add_parser(
        "diff", help="Drift between two exports (Stance 2): what got worse / better."
    )
    p_diff.add_argument("old_export", help="The earlier (baseline) export directory.")
    p_diff.add_argument("new_export", help="The later (current) export directory.")
    p_diff.add_argument("--json", action="store_true", help="Emit the JSON envelope.")
    p_diff.add_argument(
        "--warn-days",
        type=int,
        default=90,
        help="Flag CA certs/CRLs within this many days of expiry (default: 90).",
    )
    p_diff.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit non-zero when there are regressions (new or worsened findings).",
    )
    return parser


def _redact_none(s: str) -> str:
    return s if s not in ("", "None") else "?"


def _cmd_ingest(export_dir: str) -> int:
    estate = ingest(export_dir)
    m = estate.manifest
    print(f"Ingested export from {_redact_none(m.host)} ({_redact_none(m.domain)})")
    print(
        f"  collected: {_redact_none(m.collected_at)}"
        f"  collector: {_redact_none(m.collector_version)}"
    )
    print(f"  CAs: {len(estate.cas)}   templates: {len(estate.templates)}")
    print(f"  PKI ACLs: {len(estate.acls)}   issuance OIDs: {len(estate.oids)}")
    print(f"  CRLs: {len(estate.crls)}   lifecycle evaluated: {m.certs_parsed}")
    if m.skipped_passes:
        print(f"  skipped passes: {', '.join(m.skipped_passes)}")
    return 0


def _cmd_doctor(
    export_dir: str,
    *,
    as_json: bool,
    warn_days: int,
    severity: str,
    exit_code: bool,
) -> int:
    min_rank = SEVERITY_RANK[Severity(severity)]

    all_findings = run_all(ingest(export_dir), warn_days=warn_days)
    # Lower rank == worse; keep findings at or above the requested floor.
    findings = [f for f in all_findings if SEVERITY_RANK[f.severity] <= min_rank]

    print(render_json(findings) if as_json else render_text(findings))

    # `findings` is already filtered to the threshold, so any survivor trips the gate.
    if exit_code and findings:
        return 1
    return 0


def _cmd_diff(
    old_export: str,
    new_export: str,
    *,
    as_json: bool,
    warn_days: int,
    exit_code: bool,
) -> int:
    old = run_all(ingest(old_export), warn_days=warn_days)
    new = run_all(ingest(new_export), warn_days=warn_days)
    report = diff_findings(old, new)

    print(render_diff_json(report) if as_json else render_diff_text(report))

    if exit_code and report.regressions:
        return 1
    return 0


def _error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "ingest":
            return _cmd_ingest(args.export_dir)
        if args.command == "doctor":
            return _cmd_doctor(
                args.export_dir,
                as_json=args.json,
                warn_days=args.warn_days,
                severity=args.severity,
                exit_code=args.exit_code,
            )
        if args.command == "diff":
            return _cmd_diff(
                args.old_export,
                args.new_export,
                as_json=args.json,
                warn_days=args.warn_days,
                exit_code=args.exit_code,
            )
    except IngestError as exc:
        return _error(str(exc))
    except json.JSONDecodeError as exc:
        return _error(f"malformed JSON in export: {exc}")
    except OSError as exc:
        return _error(f"cannot read export: {exc}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
