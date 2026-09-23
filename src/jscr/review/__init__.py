"""Review: findings, prompting, verification and the engine.

The engine is resolved on first use rather than on import. It pulls in the
scanner runner, which imports every scanner, and each scanner imports the
finding types from this package — so importing the engine here made the
success of "import jscr.scanners.base" depend on which module the caller
imported first. The names below behave exactly as before; only the moment
the engine module is executed has moved.
"""

from typing import Any

from .findings import Finding, Severity, dedupe, sort_findings

__all__ = ["Finding", "Severity", "dedupe", "sort_findings", "ReviewEngine", "ReviewResult"]

_LAZY = ("ReviewEngine", "ReviewResult")


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        from . import engine

        return getattr(engine, name)
    raise AttributeError("module {0!r} has no attribute {1!r}".format(__name__, name))


def __dir__():
    return sorted(list(globals()) + list(_LAZY))
