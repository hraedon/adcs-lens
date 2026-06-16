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
from adcs_lens.display import render_json, render_text
from adcs_lens.ingest import IngestError, ingest


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


def _cmd_doctor(export_dir: str, *, as_json: bool, warn_days: int) -> int:
    findings = run_all(ingest(export_dir), warn_days=warn_days)
    print(render_json(findings) if as_json else render_text(findings))
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
            return _cmd_doctor(args.export_dir, as_json=args.json, warn_days=args.warn_days)
    except IngestError as exc:
        return _error(str(exc))
    except json.JSONDecodeError as exc:
        return _error(f"malformed JSON in export: {exc}")
    except OSError as exc:
        return _error(f"cannot read export: {exc}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
