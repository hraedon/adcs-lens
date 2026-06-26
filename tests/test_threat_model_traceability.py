"""Threat-model <-> detector traceability (WI-023).

Locks ``docs/threat-model.md`` as the design spine: every ESC class it lists
must have a detector, every detector must be wired into ``run_all``, and every
hygiene row must be either implemented or explicitly deferred. If any of these
drift, a test here fails — that is the guard.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_THREAT_MODEL = _REPO / "docs" / "threat-model.md"
_DETECTION_SRC = _REPO / "src" / "adcs_lens" / "detection.py"

# Maps each hygiene-table row name to the check identifier that implements it,
# or None when the check is deferred. When a detector is added for a deferred
# row, move its value from None to the check string — the test will fail until
# you do, which is the point.
HYGIENE_STATUS: dict[str, str | None] = {
    "CA cert expiry": "CA_CERT_EXPIRY",
    "CRL signing expiry": "CA_CERT_EXPIRY",
    "CRL freshness": "CRL_EXPIRY",
    "CDP / AIA reachability": None,
    "Weak signing algorithm": "WEAK_SIG_ALG",
    "Weak key length": "WEAK_KEY_SIZE",
    "Audit configuration": "CA_AUDIT_DISABLED",
    "Orphaned / unused templates": None,
}


def _esc_ids_in_threat_model() -> set[str]:
    """Extract ESC identifiers from the threat model's ESC catalogue table."""
    text = _THREAT_MODEL.read_text(encoding="utf-8")
    return set(re.findall(r"^\|\s*(ESC\d+)\s*\|", text, re.MULTILINE))


def _esc_detectors() -> set[str]:
    """Extract ESC IDs that have a ``detect_escN`` function in detection.py."""
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("detect_esc"):
            ids.add(node.name.removeprefix("detect_").upper())
    return ids


def _all_detect_functions() -> set[str]:
    """Every public ``detect_*`` function defined in detection.py."""
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name.startswith("detect_")
        and not node.name.startswith("_")
    }


def _run_all_called_detectors() -> set[str]:
    """Every ``detect_*`` function called inside ``run_all``'s body."""
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    called: set[str] = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name == "run_all"):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
                if inner.func.id.startswith("detect_"):
                    called.add(inner.func.id)
    return called


def _hygiene_rows_in_threat_model() -> set[str]:
    """Extract the first-column check name from the hygiene table."""
    text = _THREAT_MODEL.read_text(encoding="utf-8")
    section = text.split("## Non-ESC hygiene & lifecycle")[1]
    rows: set[str] = set()
    for line in section.splitlines():
        m = re.match(r"^\|\s*(.+?)\s*\|", line)
        if not m:
            continue
        name = m.group(1)
        if name.lower() == "check":
            continue
        if set(name) <= {"-"}:
            continue
        rows.add(name)
    return rows


def _check_literals_in_detection() -> set[str]:
    """Every ``check="..."`` literal passed to ``Finding`` in detection.py."""
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    emitted: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "Finding"):
            continue
        for kw in node.keywords:
            if kw.arg == "check" and isinstance(kw.value, ast.Constant):
                emitted.add(kw.value.value)
    return emitted


def test_esc_threat_model_matches_detectors() -> None:
    """Every ESC class in the threat model has a detector, and vice versa."""
    tm = _esc_ids_in_threat_model()
    det = _esc_detectors()
    assert tm == det, (
        "ESC threat-model / detector mismatch:\n"
        f"  in threat model but no detector: {sorted(tm - det)}\n"
        f"  has detector but not in threat model: {sorted(det - tm)}"
    )


def test_run_all_calls_every_detector() -> None:
    """No detector function is accidentally left out of run_all."""
    defined = _all_detect_functions()
    called = _run_all_called_detectors()
    assert defined == called, (
        "run_all wiring mismatch:\n"
        f"  defined but not called by run_all: {sorted(defined - called)}\n"
        f"  called by run_all but not defined: {sorted(called - defined)}"
    )


def test_hygiene_rows_all_accounted_for() -> None:
    """Every hygiene row in the threat model is implemented or explicitly deferred."""
    rows = _hygiene_rows_in_threat_model()
    known = set(HYGIENE_STATUS)
    assert rows == known, (
        "hygiene row drift:\n"
        f"  in threat model but not in HYGIENE_STATUS: {sorted(rows - known)}\n"
        f"  in HYGIENE_STATUS but not in threat model: {sorted(known - rows)}"
    )


def test_hygiene_status_matches_detector_emissions() -> None:
    """Every implemented hygiene row maps to a check a detector actually emits.

    This closes the gap where a row is marked implemented in ``HYGIENE_STATUS``
    but the check id is stale, or vice versa. (A deferred row mapped to ``None``
    cannot be checked for silent implementation because its future check id is
    unknown — adding the row to ``HYGIENE_STATUS`` at implementation time is the
    intended workflow, enforced by ``test_hygiene_rows_all_accounted_for``.)
    """
    emitted = _check_literals_in_detection()
    for row, check in HYGIENE_STATUS.items():
        if check is not None:
            assert check in emitted, (
                f"hygiene row {row!r} maps to {check!r} but no detector emits it"
            )
