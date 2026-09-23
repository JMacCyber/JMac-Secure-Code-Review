"""Running the configured scanners.

Every external scanner is an execution of another program, so each one is put
to the policy layer as ``exec.run`` before it starts. A denied scanner is
recorded as denied, never as clean.
"""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..errors import PolicyDenied
from ..policy import EXEC_RUN, Policy
from .artefacts import ArtefactScanner
from .base import Scanner, ScannerResult
from .builtin import BuiltinScanner
from .external import GitleaksScanner, SemgrepScanner, TrivyScanner
from .iac import IacScanner
from .licences import LicenceScanner
from .manifest import ManifestScanner
from .secrets import SecretScanner
from .workflow import WorkflowPermissionScanner

#: Scanners that read the repository and start no other process. They are
#: gated by configuration but never by the execution policy, because there is
#: no execution to permit.
_INTERNAL: Dict[str, type] = {
    WorkflowPermissionScanner.name: WorkflowPermissionScanner,
    ManifestScanner.name: ManifestScanner,
    IacScanner.name: IacScanner,
    ArtefactScanner.name: ArtefactScanner,
    LicenceScanner.name: LicenceScanner,
}

_EXTERNAL: Dict[str, type] = {
    SemgrepScanner.name: SemgrepScanner,
    GitleaksScanner.name: GitleaksScanner,
    TrivyScanner.name: TrivyScanner,
}


def available_scanners(config=None) -> List[Tuple[str, bool, bool]]:
    """(name, installed, enabled) for every external scanner.

    "Installed" is checked by looking for the program, not by running it.
    The distinction between "not installed" and "disabled" is kept because
    they need different answers from the operator.
    """
    rows: List[Tuple[str, bool, bool]] = []
    for name, factory in sorted(_EXTERNAL.items()):
        scanner = factory()
        enabled = bool(config.get("scanners.{0}".format(name), False)) if config else False
        rows.append((name, scanner.installed(), enabled))
    return rows


def scanner_names() -> List[str]:
    return [BuiltinScanner.name, SecretScanner.name] + sorted(_INTERNAL) + sorted(_EXTERNAL)


def run_scanners(
    policy: Policy,
    boundary: RepositoryBoundary,
    paths: Sequence[str],
) -> List[ScannerResult]:
    """Run the built-in scanner plus whichever external ones are enabled."""
    timeout = int(policy.config.get("scanners.timeout_seconds", 300))
    results: List[ScannerResult] = [
        BuiltinScanner().scan(boundary, paths, timeout),
        SecretScanner(policy.config).scan(boundary, paths, timeout),
    ]

    for name, factory in sorted(_INTERNAL.items()):
        if not policy.config.get("scanners.{0}".format(name), True):
            results.append(ScannerResult(name, ran=False, error="disabled by configuration"))
            continue
        results.append(factory().scan(boundary, paths, timeout))

    for name, factory in sorted(_EXTERNAL.items()):
        if not policy.config.get("scanners.{0}".format(name)):
            continue
        scanner: Scanner = factory(policy.config)
        try:
            policy.require(EXEC_RUN, name)
        except PolicyDenied as exc:
            results.append(ScannerResult(name, ran=False, error=exc.reason))
            continue
        results.append(scanner.scan(boundary, paths, timeout))
    return results


def scanner_notes(results: Sequence[ScannerResult], limit: int = 60) -> str:
    """A compact, plain-text digest of scanner output for the review prompt.

    The model is told what the deterministic tools found so that it can
    corroborate or contradict them, rather than rediscovering the same
    pattern matches and inflating the count.
    """
    lines: List[str] = []
    for result in results:
        if not result.ran:
            lines.append("{0}: did not run ({1})".format(result.name, result.error or "unknown"))
            continue
        lines.append("{0}: {1} finding(s)".format(result.name, len(result.findings)))
        for finding in result.findings[:limit]:
            lines.append(
                "  {0}:{1} [{2}] {3} ({4})".format(
                    finding.path, finding.line, finding.severity, finding.title, finding.rule_id
                )
            )
        if len(result.findings) > limit:
            lines.append("  ... {0} more".format(len(result.findings) - limit))
    return "\n".join(lines)


def split_results(results: Sequence[ScannerResult]) -> Tuple[List, List[Dict[str, object]]]:
    """Return ``(findings, report_rows)``."""
    findings: List = []
    rows: List[Dict[str, object]] = []
    for result in results:
        findings.extend(result.findings)
        rows.append(result.as_dict())
    return findings, rows
