"""GitHub Actions permission analysis.

A workflow runs with a token. What that token may do is decided by the
``permissions`` block, and the block is easy to get wrong in a way nothing
else notices: leaving it out at all means the repository default applies, and
a repository whose default is read and write hands every workflow — including
one triggered by a fork — a token that can push code and publish packages.

This is read line by line rather than through a YAML parser, because JSCR
carries no dependencies and a permission block is a shape a regular
expression can see: a key, a colon, and an indentation level.
"""

from __future__ import annotations

import re
import time
from typing import List, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..review.findings import HIGH, LOW, MEDIUM, SOURCE_SCANNER, Finding
from .base import Scanner, ScannerResult

_WORKFLOW_DIR = ".github/workflows/"
_YAML = (".yml", ".yaml")

_PERMISSIONS = re.compile(r"^(\s*)permissions\s*:\s*(.*)$")
_JOB_HEADER = re.compile(r"^  (\w[\w-]*)\s*:\s*$")
_ON_LINE = re.compile(r"^\s*on\s*:")
_SCOPE = re.compile(r"^(\s*)([a-z][a-z-]*)\s*:\s*(read|write|none)\s*$")

#: Scopes that let a token change the repository or what it publishes.
_WRITE_IS_SERIOUS = {
    "contents": (
        HIGH,
        "A token with contents: write can push commits and move tags, so a "
        "workflow step that runs untrusted code can rewrite the repository.",
    ),
    "packages": (
        HIGH,
        "A token with packages: write can publish a package under this "
        "repository's name, which every consumer then installs.",
    ),
    "id-token": (
        HIGH,
        "A token with id-token: write can mint an OIDC token and assume a "
        "cloud role, so the blast radius leaves GitHub entirely.",
    ),
    "actions": (
        MEDIUM,
        "A token with actions: write can change or delete workflow runs, "
        "which is how an attacker removes the evidence.",
    ),
    "deployments": (MEDIUM, "A token with deployments: write can start a deployment."),
    "issues": (LOW, "A token with issues: write can comment and close issues."),
    "pull-requests": (LOW, "A token with pull-requests: write can approve or merge."),
}


def _is_workflow(path: str) -> bool:
    return path.replace("\\", "/").startswith(_WORKFLOW_DIR) and path.endswith(_YAML)


def _finding(
    path: str,
    line: int,
    title: str,
    detail: str,
    severity: str,
    evidence: str,
    recommendation: str,
    rule: str,
    cwe: str,
) -> Finding:
    return Finding(
        path=path,
        line=line,
        title=title,
        detail=detail,
        severity=severity,
        evidence=evidence.rstrip(),
        recommendation=recommendation,
        rule_id="jscr/{0}".format(rule),
        cwe=cwe,
        confidence=0.9,
        source=SOURCE_SCANNER,
    )


class WorkflowPermissionScanner(Scanner):
    """Reads the permissions block of every workflow, including its absence."""

    name = "workflow-permissions"
    external = False
    rules = ("ci-permissions-missing", "ci-permissions-write-all", "ci-permissions-broad")

    def scan(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        timeout: int = 300,
    ) -> ScannerResult:
        del timeout
        started = time.time()
        findings: List[Finding] = []
        for path in paths:
            if not _is_workflow(path):
                continue
            try:
                text = boundary.read_text(path)
            except (OSError, UnicodeDecodeError, BoundaryViolation):
                continue
            findings.extend(self._scan_one(path, text))
        return ScannerResult(
            name=self.name,
            ran=True,
            findings=findings,
            duration_seconds=time.time() - started,
            version="rules={0}".format(len(self.rules)),
        )

    def _scan_one(self, path: str, text: str) -> List[Finding]:
        lines = text.splitlines()
        findings: List[Finding] = []
        blocks = self._permission_blocks(lines)

        if not blocks:
            first = next((i for i, line in enumerate(lines, 1) if _ON_LINE.match(line)), 1)
            findings.append(
                _finding(
                    path,
                    first,
                    "workflow does not set permissions",
                    "No permissions block was found in this file, so the repository default "
                    "applies to every job. Where that default is read and write, this "
                    "workflow's token can push commits and publish packages even though "
                    "nothing here asked for that.",
                    MEDIUM,
                    lines[first - 1] if first <= len(lines) else "",
                    "Add permissions: { contents: read } at the top of the file and grant "
                    "each job only what it needs.",
                    "ci-permissions-missing",
                    "CWE-276",
                )
            )
            return findings

        for number, indent, inline, scopes in blocks:
            if inline in ("write-all", "read-all"):
                if inline == "write-all":
                    findings.append(
                        _finding(
                            path,
                            number,
                            "workflow grants write-all",
                            "write-all gives the token every write scope at once, which is "
                            "strictly more than any job needs.",
                            HIGH,
                            lines[number - 1],
                            "Replace write-all with the two or three scopes the job uses.",
                            "ci-permissions-write-all",
                            "CWE-250",
                        )
                    )
                continue
            del indent
            for scope_line, scope, value in scopes:
                if value != "write" or scope not in _WRITE_IS_SERIOUS:
                    continue
                severity, why = _WRITE_IS_SERIOUS[scope]
                findings.append(
                    _finding(
                        path,
                        scope_line,
                        "workflow grants {0}: write".format(scope),
                        why + " Confirm the job genuinely writes; a job that only reads should "
                        "not hold the scope.",
                        severity,
                        lines[scope_line - 1],
                        "Drop the scope, or set it to read. Keep write on the one job that "
                        "needs it rather than on the whole workflow.",
                        "ci-permissions-broad",
                        "CWE-250",
                    )
                )
        return findings

    @staticmethod
    def _permission_blocks(
        lines: Sequence[str],
    ) -> List[Tuple[int, int, str, List[Tuple[int, str, str]]]]:
        """Every permissions block: (line, indent, inline value, scope rows)."""
        blocks: List[Tuple[int, int, str, List[Tuple[int, str, str]]]] = []
        for index, line in enumerate(lines):
            match = _PERMISSIONS.match(line)
            if not match:
                continue
            indent = len(match.group(1))
            inline = match.group(2).strip().strip("{}").strip()
            scopes: List[Tuple[int, str, str]] = []
            if inline and ":" in inline:
                # permissions: { contents: read, issues: write }
                for part in inline.split(","):
                    bits = part.split(":")
                    if len(bits) == 2:
                        scopes.append((index + 1, bits[0].strip(), bits[1].strip()))
                inline = ""
            elif not inline:
                for offset in range(index + 1, len(lines)):
                    nested = _SCOPE.match(lines[offset])
                    if not nested or len(nested.group(1)) <= indent:
                        if lines[offset].strip() and not lines[offset].lstrip().startswith("#"):
                            break
                        continue
                    scopes.append((offset + 1, nested.group(2), nested.group(3)))
            blocks.append((index + 1, indent, inline, scopes))
        return blocks
