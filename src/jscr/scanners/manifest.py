"""What a package manager runs, and where it fetches from.

Three questions about the same files. Does installing this repository execute
anything? Does what it executes look like the things that steal credentials?
And could a name in it be answered by a registry other than the one the author
meant?

Every finding here quotes the manifest line it came from, so a reader can
disagree with it by looking at one line. None of it asks a registry anything:
a name that is absent from the public index is a fact this scanner cannot
establish without network access it does not have, so it reports the shape of
the risk and says what would confirm it.
"""

from __future__ import annotations

import json
import re
import time
from typing import Dict, List, Sequence

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..review.findings import HIGH, LOW, MEDIUM, SOURCE_SCANNER, Finding
from .base import Scanner, ScannerResult

#: Hooks npm runs on its own, without anyone typing the script name.
_AUTOMATIC = ("preinstall", "install", "postinstall", "prepare", "prepublish")

#: Shapes that turn an install into code execution from somewhere else.
_DANGEROUS = (
    (
        re.compile(r"curl[^|&;]*\|\s*(?:ba|z|d)?sh", re.I),
        "downloads a script and pipes it into a shell",
        HIGH,
    ),
    (
        re.compile(r"wget[^|&;]*\|\s*(?:ba|z|d)?sh", re.I),
        "downloads a script and pipes it into a shell",
        HIGH,
    ),
    (re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b"), "decodes base64 and runs the result", HIGH),
    (re.compile(r"\bnode\s+-e\b"), "runs JavaScript given on the command line", HIGH),
    (re.compile(r"\bpython3?\s+-c\b"), "runs Python given on the command line", HIGH),
    (re.compile(r"\beval\b"), "evaluates a built string as a command", HIGH),
    (
        re.compile(r"~/\.(?:ssh|aws|npmrc|docker|gnupg)|\$HOME/\.(?:ssh|aws)"),
        "reads a credential directory",
        HIGH,
    ),
    (
        re.compile(r"\benv\b\s*\|\s*|printenv|process\.env"),
        "reads the environment, where CI secrets live",
        MEDIUM,
    ),
    (
        re.compile(r"chmod\s+\+x|\bsudo\b"),
        "changes permissions or escalates during install",
        MEDIUM,
    ),
    (re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}"), "contacts a bare IP address", HIGH),
)

#: A registry line that redirects every unscoped name somewhere else.
_REGISTRY = re.compile(r"^\s*registry\s*=\s*(\S+)", re.I)
_SCOPED_REGISTRY = re.compile(r"^\s*(@[\w.-]+):registry\s*=\s*(\S+)", re.I)
_PIP_INDEX = re.compile(r"(--extra-index-url|--index-url)[=\s]+(\S+)", re.I)
_PUBLIC_NPM = ("registry.npmjs.org",)
_PUBLIC_PYPI = ("pypi.org", "files.pythonhosted.org")


def _is_public(url: str, hosts: Sequence[str]) -> bool:
    return any(host in url for host in hosts)


class ManifestScanner(Scanner):
    """Install scripts, malicious script shapes, and registry redirection."""

    name = "manifest"
    external = False

    def scan(
        self,
        boundary: RepositoryBoundary,
        paths: Sequence[str],
        timeout: int = 300,
    ) -> ScannerResult:
        del timeout
        started = time.time()
        findings: List[Finding] = []
        seen = 0
        for path in paths:
            base = path.replace("\\", "/").split("/")[-1]
            if "node_modules/" in path.replace("\\", "/"):
                continue
            try:
                text = boundary.read_text(path)
            except (OSError, UnicodeDecodeError, BoundaryViolation):
                continue
            if base == "package.json":
                seen += 1
                findings.extend(self._package_json(path, text))
            elif base == ".npmrc":
                seen += 1
                findings.extend(self._npmrc(path, text))
            elif base.startswith("requirements") and base.endswith(".txt"):
                seen += 1
                findings.extend(self._pip_index(path, text))
            elif base in ("Dockerfile", "pip.conf"):
                seen += 1
                findings.extend(self._pip_index(path, text))
        return ScannerResult(
            name=self.name,
            ran=True,
            findings=findings,
            duration_seconds=time.time() - started,
            version="manifests={0}".format(seen),
        )

    # -- package.json -----------------------------------------------------

    def _package_json(self, path: str, text: str) -> List[Finding]:
        try:
            data = json.loads(text)
        except ValueError:
            return []
        if not isinstance(data, dict):
            return []
        lines = text.splitlines()
        findings: List[Finding] = []
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            # No scripts block is not the end of the file: the dependency names
            # still have to be looked at.
            return self._confusable(path, lines, data)
        for hook in _AUTOMATIC:
            body = scripts.get(hook)
            if not isinstance(body, str) or not body.strip():
                continue
            line = _line_of(lines, '"{0}"'.format(hook))
            reasons = [(why, sev) for rule, why, sev in _DANGEROUS if rule.search(body)]
            if reasons:
                worst = HIGH if any(sev == HIGH for _, sev in reasons) else MEDIUM
                findings.append(
                    Finding(
                        path=path,
                        line=line,
                        title="install hook {0} runs a dangerous command".format(hook),
                        detail=(
                            "npm runs {0} automatically during install, before anyone reads the "
                            "code. This one {1}. An install hook runs with the developer's "
                            "credentials on a workstation and with the job's token in CI."
                        ).format(hook, " and ".join(why for why, _ in reasons)),
                        severity=worst,
                        evidence=_evidence(lines, line),
                        recommendation=(
                            "Move the work out of the automatic hook into a named script the "
                            "caller runs on purpose, and install with --ignore-scripts in CI. "
                            "If the download is needed, pin it to a version and check its hash."
                        ),
                        rule_id="jscr/install-script-dangerous",
                        cwe="CWE-829",
                        confidence=0.8,
                        source=SOURCE_SCANNER,
                    )
                )
            else:
                findings.append(
                    Finding(
                        path=path,
                        line=line,
                        title="install hook {0} executes on every install".format(hook),
                        detail=(
                            "npm runs {0} automatically. Nothing in it matched a known-bad "
                            "shape, so this is reported as something to know rather than "
                            "something wrong: anyone who can change this line can run code "
                            "on every machine that installs the package."
                        ).format(hook),
                        severity=LOW,
                        evidence=_evidence(lines, line),
                        recommendation=(
                            "Keep the hook short and readable, and install with "
                            "--ignore-scripts in CI so a dependency's hook cannot run there."
                        ),
                        rule_id="jscr/install-script-present",
                        cwe="CWE-829",
                        confidence=0.6,
                        source=SOURCE_SCANNER,
                    )
                )
        findings.extend(self._confusable(path, lines, data))
        return findings

    def _confusable(self, path: str, lines: Sequence[str], data: Dict) -> List[Finding]:
        """Private-looking names that an unscoped public registry could answer."""
        findings: List[Finding] = []
        block = data.get("dependencies")
        if not isinstance(block, dict):
            return findings
        private_markers = ("internal", "-int-", "corp", "private")
        for name, spec in sorted(block.items()):
            if name.startswith("@"):
                continue  # A scope binds the name to whoever owns the scope.
            lowered = name.lower()
            if not any(marker in lowered for marker in private_markers):
                continue
            line = _line_of(lines, '"{0}"'.format(name))
            findings.append(
                Finding(
                    path=path,
                    line=line,
                    title="unscoped dependency name reads as internal: {0}".format(name),
                    detail=(
                        "The name has no scope, so npm resolves it from whichever registry "
                        "is configured, and the public registry answers first for anyone "
                        "who has not set an override. Whether the name is taken on the "
                        "public registry is not checked here: this scanner makes no network "
                        "requests. Version requested: {0}."
                    ).format(str(spec)),
                    severity=MEDIUM,
                    evidence=_evidence(lines, line),
                    recommendation=(
                        "Publish internal packages under an owned scope and bind that scope "
                        "to the internal registry in .npmrc. Confirm the bare name is not "
                        "claimable on the public registry."
                    ),
                    rule_id="jscr/dependency-confusion-name",
                    cwe="CWE-427",
                    confidence=0.5,
                    source=SOURCE_SCANNER,
                )
            )
        return findings

    # -- registries -------------------------------------------------------

    def _npmrc(self, path: str, text: str) -> List[Finding]:
        lines = text.splitlines()
        scoped = {}
        default = None
        for index, line in enumerate(lines, start=1):
            bound = _SCOPED_REGISTRY.match(line)
            if bound:
                scoped[bound.group(1)] = index
                continue
            match = _REGISTRY.match(line)
            if match:
                default = (index, match.group(1))
        if default is None:
            return []
        index, url = default
        if _is_public(url, _PUBLIC_NPM):
            return []
        if scoped:
            return []
        return [
            Finding(
                path=path,
                line=index,
                title="every unscoped package comes from a non-public registry",
                detail=(
                    "registry is set to {0} with no scope bound to it, so every dependency "
                    "name in this project is resolved there. If that host ever answers a "
                    "name it does not own, or stops answering, the install silently changes "
                    "where code comes from."
                ).format(url),
                severity=MEDIUM,
                evidence=_evidence(lines, index),
                recommendation=(
                    "Bind the internal packages to a scope — @acme:registry=... — and leave "
                    "the default registry pointing at the public index, so a name can only "
                    "be served by the party that owns the scope."
                ),
                rule_id="jscr/registry-default-override",
                cwe="CWE-427",
                confidence=0.6,
                source=SOURCE_SCANNER,
            )
        ]

    def _pip_index(self, path: str, text: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = text.splitlines()
        for index, line in enumerate(lines, start=1):
            match = _PIP_INDEX.search(line)
            if not match or _is_public(match.group(2), _PUBLIC_PYPI):
                continue
            extra = match.group(1).lower() == "--extra-index-url"
            findings.append(
                Finding(
                    path=path,
                    line=index,
                    title="pip is given a second index to search",
                    detail=(
                        "pip queries every index it is given and installs the highest "
                        "version it finds anywhere, so a name published on the public "
                        "index with a higher version wins over the internal one. "
                        "Index: {0}."
                    ).format(match.group(2))
                    if extra
                    else (
                        "pip is pointed at {0} instead of the public index. Every name in "
                        "this file is resolved there."
                    ).format(match.group(2)),
                    severity=HIGH if extra else LOW,
                    evidence=_evidence(lines, index),
                    recommendation=(
                        "Use --index-url with a proxy that mirrors the public index, not "
                        "--extra-index-url. A proxy decides which name wins; two indexes "
                        "let the version number decide."
                    ),
                    rule_id="jscr/pip-extra-index" if extra else "jscr/pip-index-override",
                    cwe="CWE-427",
                    confidence=0.75 if extra else 0.5,
                    source=SOURCE_SCANNER,
                )
            )
        return findings


def _line_of(lines: Sequence[str], needle: str) -> int:
    for index, line in enumerate(lines, start=1):
        if needle in line:
            return index
    return 1


def _evidence(lines: Sequence[str], number: int) -> str:
    if 1 <= number <= len(lines):
        return lines[number - 1].strip()[:200]
    return ""
