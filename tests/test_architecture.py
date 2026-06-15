"""Architecture guard: the deterministic truth path is stdlib-only.

The core modules (model, normalize, ingest, detection, display, cli) must not
import any third-party package at module scope, and must not import the optional
``certs`` module at module scope (it may only be imported lazily inside a
function, behind the [certs] extra). This is the charter's "no AI / no deps in
the truth path" made executable.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

CORE_MODULES = ["model", "normalize", "ingest", "detection", "display", "cli"]
_SRC = Path(__file__).resolve().parent.parent / "src" / "adcs_lens"


def _top_level_imports(path: Path) -> list[str]:
    """Root module names imported at module scope (not inside functions)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: list[str] = []
    for node in tree.body:  # module scope only — function-local imports excluded
        if isinstance(node, ast.Import):
            roots += [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.append(node.module.split(".")[0])
    return roots


def test_core_modules_import_only_stdlib_or_self() -> None:
    allowed = set(sys.stdlib_module_names) | {"adcs_lens"}
    offenders: dict[str, list[str]] = {}
    for mod in CORE_MODULES:
        bad = [r for r in _top_level_imports(_SRC / f"{mod}.py") if r not in allowed]
        if bad:
            offenders[mod] = bad
    assert not offenders, f"third-party imports in the truth path: {offenders}"


def test_core_does_not_import_certs_at_module_scope() -> None:
    # certs.py is the dependency boundary; the core may only reach it lazily.
    for mod in CORE_MODULES:
        src = (_SRC / f"{mod}.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("certs"):
                raise AssertionError(f"{mod} imports certs at module scope")
