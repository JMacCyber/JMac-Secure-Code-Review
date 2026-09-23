"""Licence obligations, reported as facts rather than verdicts.

A licence is a condition on how you may ship the code, not a defect in it. So
this scanner reports at Info and Low by default and only rises when the
obligation is one that reaches your own source: a strong or network copyleft
dependency changes what you must publish, and an undeclared licence means
nobody has checked.

What it cannot do is stated in the finding: a declaration in a manifest is
what the author wrote, not what a lawyer confirmed, and a package with no
declaration is unknown, never assumed permissive.
"""

from __future__ import annotations

import time
from typing import List, Sequence

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..review.findings import INFO, LOW, MEDIUM, SOURCE_SCANNER, Finding
from ..supply.inventory import read_inventory
from ..supply.licences import (
    CATEGORY_NETWORK_COPYLEFT,
    CATEGORY_SOURCE_AVAILABLE,
    CATEGORY_STRONG_COPYLEFT,
    CATEGORY_UNKNOWN,
    classify,
)
from .base import Scanner, ScannerResult

_SEVERITY = {
    CATEGORY_NETWORK_COPYLEFT: MEDIUM,
    CATEGORY_STRONG_COPYLEFT: MEDIUM,
    CATEGORY_SOURCE_AVAILABLE: MEDIUM,
    CATEGORY_UNKNOWN: LOW,
}

_REPORTED = tuple(_SEVERITY)


class LicenceScanner(Scanner):
    """Declared licences of declared dependencies."""

    name = "licences"
    external = False

    def scan(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        timeout: int = 300,
    ) -> ScannerResult:
        del timeout
        started = time.time()

        def reader(path: str) -> str:
            return boundary.read_text(path)

        try:
            packages = read_inventory(reader, paths)
        except (OSError, UnicodeDecodeError, BoundaryViolation):
            packages = []

        findings: List[Finding] = []
        counted = 0
        for package in packages:
            if package.scope == "self":
                continue
            counted += 1
            if not package.licence:
                # Absence of a declaration is not a permissive licence. It is
                # only reported once a lockfile could have carried one.
                if package.declared_in.endswith("lock.json"):
                    findings.append(_unknown(package))
                continue
            category, obligation = classify(package.licence)
            if category not in _REPORTED:
                continue
            findings.append(
                Finding(
                    path=package.declared_in,
                    line=1,
                    title="{0} is under {1}".format(package.name, package.licence),
                    detail=(
                        "Category: {0}. {1} This is the identifier the package declares, "
                        "read from {2}. It has not been checked against the licence text "
                        "in the package itself, and it is not legal advice."
                    ).format(category, obligation, package.declared_in),
                    severity=_SEVERITY[category],
                    evidence="",
                    recommendation=(
                        "Confirm the obligation applies to how you ship this. If it does "
                        "not fit, find a replacement now rather than at release."
                    ),
                    rule_id="jscr/licence-{0}".format(category),
                    cwe="",
                    confidence=0.7,
                    source=SOURCE_SCANNER,
                )
            )

        if counted and not findings:
            findings.append(
                Finding(
                    path=packages[0].declared_in if packages else "",
                    line=1,
                    title="{0} dependencies declared, none with a reaching obligation".format(
                        counted
                    ),
                    detail=(
                        "Every declared licence read as permissive, public domain or weak "
                        "copyleft. Only what the manifests and lockfiles say was read: a "
                        "dependency that declares nothing anywhere is not in this count."
                    ),
                    severity=INFO,
                    evidence="",
                    recommendation="Keep the SBOM with the release so this can be re-checked later.",
                    rule_id="jscr/licence-clear",
                    cwe="",
                    confidence=0.6,
                    source=SOURCE_SCANNER,
                )
            )

        return ScannerResult(
            name=self.name,
            ran=True,
            findings=findings,
            duration_seconds=time.time() - started,
            version="packages={0}".format(counted),
        )


def _unknown(package) -> Finding:
    return Finding(
        path=package.declared_in,
        line=1,
        title="{0} declares no licence".format(package.name),
        detail=(
            "The lockfile records a licence field for other packages and none for this "
            "one. No licence means no permission granted by default, so this is a gap "
            "to close, not a clean result."
        ),
        severity=LOW,
        evidence="",
        recommendation=(
            "Read the package's own repository for a LICENSE file. If there is none, "
            "ask the author or replace the dependency."
        ),
        rule_id="jscr/licence-undeclared",
        cwe="",
        confidence=0.5,
        source=SOURCE_SCANNER,
    )
