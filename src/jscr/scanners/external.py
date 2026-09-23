"""Wrappers for external scanners.

Each wrapper runs a separate program over the repository and translates its
output into :class:`~jscr.review.findings.Finding` objects. The rules are the
same for all of them:

* the program is off unless configuration turns it on;
* it is invoked with an argument list, never a shell string;
* it runs with the repository root as its working directory and is given a
  minimal environment;
* it gets a timeout, and a timeout is reported rather than swallowed;
* a missing program is reported as "not installed", not as "no findings";
* no wrapper may reach the network. A scanner that downloads its rules at
  run time is a network call wearing a scanner's name, so semgrep is given
  a rule file that is on disk.

That last point matters more than it looks. A scanner that silently does
nothing when it is absent turns a clean report into a lie.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..review.findings import SOURCE_SCANNER, Finding, Severity
from .base import Scanner, ScannerResult


class ExternalScanner(Scanner):
    """Shared plumbing for programs JSCR shells out to."""

    external = True
    binary = ""

    #: True when the program writes its report to a file instead of stdout.
    report_file = False

    def __init__(self, config: Any = None) -> None:
        self.config = config

    def setting(self, key: str, default: Any = "") -> Any:
        """One configuration value, or the default when there is no config."""
        if self.config is None:
            return default
        return self.config.get(key, default)

    def environment(self) -> Dict[str, str]:
        """Environment variables this program needs on top of the small set
        every external scanner gets. Empty for most of them."""
        return {}

    def command(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        report_path: Optional[str] = None,
    ) -> List[str]:
        raise NotImplementedError

    def parse(self, stdout: str, boundary: RepositoryBoundary) -> List[Finding]:
        raise NotImplementedError

    def version(self) -> str:
        try:
            completed = self._run([self.binary, "--version"], cwd=os.getcwd(), timeout=20)
        except Exception:
            return ""
        return (
            (completed.stdout or b"").decode("utf-8", "replace").strip().splitlines()[:1][0]
            if completed.stdout
            else ""
        )

    def installed(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        timeout: int = 300,
    ) -> ScannerResult:
        started = time.time()
        if not self.installed():
            return ScannerResult(
                self.name,
                ran=False,
                error="{0} is not installed or not on PATH".format(self.binary),
            )
        report_path = _report_path() if self.report_file else None
        try:
            argv = self.command(boundary, paths, report_path)
            completed = self._run(
                argv,
                cwd=boundary.root,
                timeout=timeout,
                extra_environment=self.environment(),
            )
        except subprocess.TimeoutExpired:
            _discard(report_path)
            return ScannerResult(
                self.name,
                ran=False,
                error="timed out after {0}s".format(timeout),
                duration_seconds=time.time() - started,
            )
        except OSError as exc:
            _discard(report_path)
            return ScannerResult(self.name, ran=False, error=str(exc))

        if report_path is not None:
            stdout = _read_report(report_path)
            _discard(report_path)
        else:
            stdout = (completed.stdout or b"").decode("utf-8", "replace")
        stderr = (completed.stderr or b"").decode("utf-8", "replace")
        try:
            findings = self.parse(stdout, boundary)
        except ValueError as exc:
            return ScannerResult(
                self.name,
                ran=False,
                error="could not read output: {0}".format(exc),
                duration_seconds=time.time() - started,
            )
        return ScannerResult(
            self.name,
            ran=True,
            findings=findings,
            error=stderr.strip()[:400] if completed.returncode not in self.ok_returncodes else "",
            duration_seconds=time.time() - started,
            version=self.version(),
        )

    #: Return codes that mean "ran successfully", including "found something".
    ok_returncodes = (0, 1)

    @staticmethod
    def _run(
        argv: Sequence[str],
        cwd: str,
        timeout: int,
        extra_environment: Optional[Dict[str, str]] = None,
    ) -> "subprocess.CompletedProcess":
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SYSTEMROOT", "TMPDIR")
        }
        environment.setdefault("PATH", "/usr/bin:/bin")
        environment.update(extra_environment or {})
        return subprocess.run(  # noqa: S603 - argv built by the wrapper, never a shell string
            list(argv),
            cwd=cwd,
            env=environment,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )


#: The rule file shipped with JSCR, used when nothing else is configured.
BUNDLED_SEMGREP_RULES = os.path.join(os.path.dirname(__file__), "rules", "semgrep-default.yml")


class SemgrepScanner(ExternalScanner):
    name = "semgrep"
    binary = "semgrep"

    def rules(self, boundary: RepositoryBoundary) -> str:
        """The rule file to run, in order: configured, repository, bundled.

        ``--config=auto`` is not an option here. It downloads a rule set from
        semgrep.dev, which is a network call, and semgrep refuses it outright
        while metrics are off. A rule file on disk is the only form that can
        be audited and repeated.
        """
        configured = str(self.setting("scanners.semgrep_config", "") or "")
        if configured:
            return configured
        for name in (".semgrep.yml", ".semgrep.yaml"):
            if boundary.exists(name):
                return name
        return BUNDLED_SEMGREP_RULES

    def command(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        report_path: Optional[str] = None,
    ) -> List[str]:
        del report_path
        argv = [
            self.binary,
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--config={0}".format(self.rules(boundary)),
        ]
        argv.append("--")
        argv.extend(paths or ["."])
        return argv

    def parse(self, stdout: str, boundary: RepositoryBoundary) -> List[Finding]:
        data = _json(stdout)
        findings: List[Finding] = []
        for result in data.get("results", []) or []:
            extra = result.get("extra") or {}
            metadata = extra.get("metadata") or {}
            start = result.get("start") or {}
            path = _relative(result.get("path", ""), boundary)
            line = int(start.get("line") or 0)
            quoted = str(extra.get("lines") or "").strip()
            evidence = _source_line(boundary, path, line).strip() or quoted
            findings.append(
                Finding(
                    path=path,
                    line=line,
                    end_line=int((result.get("end") or {}).get("line") or 0) or None,
                    title=str(extra.get("message") or result.get("check_id") or "semgrep finding"),
                    detail=str(extra.get("message") or ""),
                    severity=Severity.normalise(extra.get("severity")),
                    evidence=evidence[:400],
                    recommendation=str(extra.get("fix") or metadata.get("fix") or ""),
                    rule_id=_short_check_id(str(result.get("check_id") or "")),
                    cwe=_first_cwe(metadata.get("cwe")),
                    confidence=_confidence(metadata.get("confidence"), 0.75),
                    source=SOURCE_SCANNER,
                )
            )
        return findings


class GitleaksScanner(ExternalScanner):
    name = "gitleaks"
    binary = "gitleaks"
    report_file = True

    def command(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        report_path: Optional[str] = None,
    ) -> List[str]:
        """Scan the working tree, and take the report from a file.

        ``detect`` scanned git history and was dropped in gitleaks 8.30. The
        working tree is what the rest of the review reads, and a finding in a
        commit nobody can open would fail anchoring anyway. The report goes to
        a file because gitleaks refuses to write to ``/dev/stdout``.
        """
        del paths
        return [
            self.binary,
            "dir",
            "--no-banner",
            "--no-color",
            "--redact",
            "--report-format=json",
            "--report-path={0}".format(report_path or ""),
            ".",
        ]

    def parse(self, stdout: str, boundary: RepositoryBoundary) -> List[Finding]:
        data = _json(stdout, default_list=True)
        findings: List[Finding] = []
        for item in data if isinstance(data, list) else []:
            path = _relative(str(item.get("File") or ""), boundary)
            line = int(item.get("StartLine") or 0)
            evidence = _secret_free_evidence(
                _source_line(boundary, path, line), int(item.get("StartColumn") or 0)
            )
            findings.append(
                Finding(
                    path=path,
                    line=line,
                    title="Secret detected: {0}".format(item.get("RuleID") or "unknown rule"),
                    detail=str(item.get("Description") or ""),
                    severity=Severity.CRITICAL,
                    evidence=evidence,
                    recommendation="Remove the value, rotate the credential, and keep it in a secret manager.",
                    rule_id="gitleaks/{0}".format(item.get("RuleID") or ""),
                    cwe="CWE-798",
                    confidence=0.9,
                    source=SOURCE_SCANNER,
                )
            )
        return findings


class TrivyScanner(ExternalScanner):
    name = "trivy"
    binary = "trivy"

    def environment(self) -> Dict[str, str]:
        """An empty Docker configuration directory.

        trivy pulls its vulnerability database from a registry, and on the way
        it reads ~/.docker/config.json. A machine that once had Docker Desktop
        leaves a credential helper named there that is no longer installed, and
        trivy then exits 1 having scanned nothing. Pointing it at an empty
        directory skips the helper without touching the real file.
        """
        return {"DOCKER_CONFIG": tempfile.mkdtemp(prefix="jscr-trivy-docker-")}

    def command(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        report_path: Optional[str] = None,
    ) -> List[str]:
        del paths, report_path
        return [
            self.binary,
            "filesystem",
            "--format=json",
            "--quiet",
            "--scanners=vuln,misconfig",
            "--offline-scan",
            ".",
        ]

    def parse(self, stdout: str, boundary: RepositoryBoundary) -> List[Finding]:
        data = _json(stdout)
        findings: List[Finding] = []
        for result in data.get("Results", []) or []:
            target = _relative(str(result.get("Target") or ""), boundary)
            index = _package_lines(boundary, target)
            for vulnerability in result.get("Vulnerabilities", []) or []:
                line, evidence = index.get(str(vulnerability.get("PkgName") or ""), (1, ""))
                findings.append(
                    Finding(
                        path=target,
                        line=line,
                        evidence=evidence,
                        title="{0} in {1} {2}".format(
                            vulnerability.get("VulnerabilityID", "vulnerability"),
                            vulnerability.get("PkgName", "package"),
                            vulnerability.get("InstalledVersion", ""),
                        ),
                        detail=str(vulnerability.get("Description") or "")[:1000],
                        severity=Severity.normalise(vulnerability.get("Severity")),
                        recommendation="Upgrade to {0}.".format(
                            vulnerability.get("FixedVersion") or "a fixed version, when one exists"
                        ),
                        rule_id=str(vulnerability.get("VulnerabilityID") or ""),
                        cwe=_first_cwe(vulnerability.get("CweIDs")),
                        confidence=0.9,
                        source=SOURCE_SCANNER,
                    )
                )
            for misconfiguration in result.get("Misconfigurations", []) or []:
                cause = misconfiguration.get("CauseMetadata") or {}
                findings.append(
                    Finding(
                        path=target,
                        line=int(cause.get("StartLine") or 0),
                        title=str(misconfiguration.get("Title") or "misconfiguration"),
                        detail=str(misconfiguration.get("Description") or ""),
                        severity=Severity.normalise(misconfiguration.get("Severity")),
                        recommendation=str(misconfiguration.get("Resolution") or ""),
                        rule_id=str(misconfiguration.get("ID") or ""),
                        confidence=0.8,
                        source=SOURCE_SCANNER,
                    )
                )
        return findings


def _package_lines(boundary: RepositoryBoundary, path: str) -> Dict[str, "Tuple[int, str]"]:
    """Where each package is named in a manifest, by name.

    trivy reports a vulnerable package, not a line: its JSON for a lockfile
    carries no position at all. Anchoring needs one, and a finding with no
    line is rejected as unanchorable even though the package is really
    there. The first line that quotes the package name is that position, and
    the line itself is evidence a reader can check.
    """
    lines: Dict[str, "Tuple[int, str]"] = {}
    if not path:
        return lines
    try:
        content = boundary.read_text(path)
    except (BoundaryViolation, OSError, UnicodeDecodeError):
        return lines
    installed = set()
    for number, text in enumerate(content.splitlines(), start=1):
        for quoted in re.findall(r'"([^"\s]{2,})"\s*:', text):
            name = quoted.rsplit("node_modules/", 1)[-1]
            here = "node_modules/" in quoted
            if name in lines and (name in installed or not here):
                continue
            lines[name] = (number, text.strip()[:200])
            if here:
                installed.add(name)
    return lines


def _source_line(boundary: RepositoryBoundary, path: str, line: int) -> str:
    """The line itself, read back through the boundary.

    An external scanner reports the line it matched, but what it hands back as
    the quote is its own business: semgrep returns ``requires login`` for a
    logged-out run, gitleaks returns ``REDACTED``. Neither string is in the
    file, so anchoring rejects the finding. Reading the line here means the
    evidence is always the file's own text. Empty when the file cannot be read.
    """
    if not path or line < 1:
        return ""
    try:
        content = boundary.read_text(path)
    except (BoundaryViolation, OSError, UnicodeDecodeError):
        return ""
    lines = content.splitlines()
    if line > len(lines):
        return ""
    return lines[line - 1]


def _secret_free_evidence(line: str, start_column: int = 0) -> str:
    """The head of a matched line, cut before the value.

    A secret finding still has to be anchored, and anchoring compares the
    quoted evidence with the file. Quoting the whole line would print a live
    credential into every report. The cut is made at the first quote, equals
    or colon, so what is left is the name the value was given - real file
    text, which anchors, and is not the value. A line with no such character
    is not quoted at all, because there is no safe place to cut it.

    ``start_column`` is used as a ceiling only, never as the cut itself: it
    is gitleaks' own count and one off from a Python index here, so it is
    trusted to say "the value starts no earlier than this" and nothing more.
    """
    if not line:
        return ""
    cut = len(line)
    if start_column > 0:
        cut = min(cut, start_column - 2)
    for character in ('"', "'", "`"):
        found = line.find(character)
        if found != -1:
            cut = min(cut, found)
    for character in ("=", ":"):
        found = line.find(character)
        if found != -1:
            cut = min(cut, found + 1)
    if cut >= len(line) or cut <= 0:
        return ""
    head = line[:cut].strip()
    return head[:200] if len(head) >= 4 else ""


def _short_check_id(check_id: str) -> str:
    """Drop the file path semgrep prefixes onto a local rule's id.

    A rule read from a file is reported as the path to that file with the
    separators turned into dots, so the same rule gets a different id on a
    different machine. Registry ids such as ``python.lang.security.x`` are
    left alone: their prefix is the rule's name, not a path.
    """
    if "jscr-" not in check_id:
        return check_id
    return check_id[check_id.rindex("jscr-") :]


def _report_path() -> str:
    """A path for a scanner's report file. The file is this session's, so it
    is removed once it has been read."""
    handle = tempfile.NamedTemporaryFile(prefix="jscr-report-", suffix=".json", delete=False)
    handle.close()
    return handle.name


def _read_report(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _discard(path: Optional[str]) -> None:
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


def _json(text: str, default_list: bool = False) -> Any:
    text = (text or "").strip()
    if not text:
        return [] if default_list else {}
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


def _relative(path: str, boundary: RepositoryBoundary) -> str:
    if not path:
        return ""
    try:
        return boundary.relative(boundary.resolve(path))
    except Exception:
        return path.replace(os.sep, "/").lstrip("./")


def _first_cwe(value: Any) -> str:
    if isinstance(value, list) and value:
        return str(value[0])
    if isinstance(value, str):
        return value
    return ""


def _confidence(value: Any, fallback: float) -> float:
    mapping = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
    if isinstance(value, str):
        return mapping.get(value.upper(), fallback)
    return fallback
