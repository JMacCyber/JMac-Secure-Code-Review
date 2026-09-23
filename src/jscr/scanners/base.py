"""The scanner interface.

A scanner is deterministic: the same input gives the same findings, with no
network and no model. External scanners are separate programs, so running one
is an execution decision, and it is made by the policy layer rather than
here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

from ..boundary.fs import RepositoryBoundary

if TYPE_CHECKING:  # pragma: no cover - typing only
    # Imported for annotations alone. At runtime this module must not pull in
    # the review package, because the review engine imports the scanner
    # runner, and the cycle makes "import jscr.scanners.base" fail depending
    # on which module a caller happens to import first.
    from ..review.findings import Finding


class ScannerResult(object):
    """What one scanner produced, including how it failed."""

    __slots__ = ("name", "ran", "findings", "error", "duration_seconds", "version")

    def __init__(
        self,
        name: str,
        ran: bool,
        findings: Optional[List["Finding"]] = None,
        error: str = "",
        duration_seconds: float = 0.0,
        version: str = "",
    ) -> None:
        self.name = name
        self.ran = ran
        self.findings: List["Finding"] = findings or []
        self.error = error
        self.duration_seconds = duration_seconds
        self.version = version

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ran": self.ran,
            "findings": len(self.findings),
            "error": self.error,
            "duration_seconds": round(self.duration_seconds, 3),
            "version": self.version,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<ScannerResult {0} ran={1} findings={2}>".format(
            self.name, self.ran, len(self.findings)
        )


class Scanner(object):
    """Base class for scanners."""

    #: Configuration key under ``scanners``.
    name = "base"

    #: True when the scanner shells out to another program.
    external = False

    def scan(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        timeout: int = 300,
    ) -> ScannerResult:
        raise NotImplementedError
