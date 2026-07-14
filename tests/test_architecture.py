"""Architecture guard: the deterministic truth path is stdlib-only.

The core modules (model, normalize, ingest, detection, display, cli, __init__)
must not import any third-party package at module scope, and must not import
the optional ``certs`` module anywhere (it may only be reached lazily inside a
function, behind the [certs] extra). This is the charter's "no AI / no deps in
the truth path" made executable.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

CORE_MODULES = [
    "__init__",
    "model",
    "normalize",
    "ingest",
    "detection",
    "consequences",
    "display",
    "cli",
    "suppression",
]
_SRC = Path(__file__).resolve().parent.parent / "src" / "adcs_lens"
_FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "build_fixture.py"


def _top_level_imports(path: Path) -> list[str]:
    """Root module names imported at module scope (not inside functions)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: list[str] = []
    body = list(tree.body)
    # For __init__.py, also inspect top-level class/function decorators and
    # assignments, all of which execute at import time.
    for node in body:
        if isinstance(node, ast.Import):
            roots += [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.append(node.module.split(".")[0])
    return roots


def _all_imports(path: Path) -> list[str]:
    """All module names imported anywhere in the file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots += [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.append(node.module.split(".")[0])
    return roots


def _imports_certs(path: Path) -> bool:
    """True if the file imports the certs module by any syntax."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == "certs" or alias.name.endswith(".certs") for alias in node.names):
                return True
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "certs" or module.endswith(".certs"):
                return True
            # 'from adcs_lens import certs'
            if module == "adcs_lens" and any(alias.name == "certs" for alias in node.names):
                return True
    return False


def test_core_modules_import_only_stdlib_or_self() -> None:
    allowed = set(sys.stdlib_module_names) | {"adcs_lens"}
    offenders: dict[str, list[str]] = {}
    for mod in CORE_MODULES:
        bad = [r for r in _top_level_imports(_SRC / f"{mod}.py") if r not in allowed]
        if bad:
            offenders[mod] = bad
    assert not offenders, f"third-party imports in the truth path: {offenders}"


def test_core_does_not_import_certs_at_module_scope() -> None:
    # certs.py is the dependency boundary; the core may only reach it lazily
    # inside a function. Module-scope imports of certs are forbidden.
    for mod in CORE_MODULES:
        if mod == "__init__":
            continue
        src = (_SRC / f"{mod}.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.endswith(".certs") or node.module == "certs":
                    raise AssertionError(f"{mod} imports certs at module scope")
                # 'from adcs_lens import certs' at module scope is also forbidden.
                if (
                    node.module == "adcs_lens"
                    and any(alias.name == "certs" for alias in node.names)
                ):
                    raise AssertionError(f"{mod} imports certs at module scope")


def test_fixture_import_boundary() -> None:
    """The fixture builder is allowed stdlib + cryptography only."""
    stdlib = set(sys.stdlib_module_names)
    allowed = stdlib | {"tests"}  # local test package references
    non_stdlib = {r for r in _all_imports(_FIXTURE) if r not in allowed}
    assert non_stdlib == {"cryptography"}, (
        f"fixture builder imports unexpected non-stdlib modules: {non_stdlib}"
    )
