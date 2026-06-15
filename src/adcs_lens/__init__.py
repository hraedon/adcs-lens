"""adcs-lens — local-first, read-only AD CS / PKI posture analysis.

The deterministic core (``model``, ``normalize``, ``ingest``, ``detection``,
``display``) imports only the standard library. Cert/CRL parsing lives behind
the optional ``[certs]`` extra (``certs`` module); narration and web are later,
optional layers that import the core, never the reverse.
"""

from __future__ import annotations


def _load_version() -> str:
    # Single source of truth: installed package metadata (from pyproject).
    # A hand-maintained constant drifts (cert-watch learned this the hard way).
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    try:
        return _pkg_version("adcs-lens")
    except PackageNotFoundError:
        return "0.0.0"


__version__ = _load_version()
