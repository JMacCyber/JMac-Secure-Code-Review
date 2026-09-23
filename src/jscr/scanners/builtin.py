"""The built-in deterministic scanner.

It ships in the box, runs with no network, no credential and no external
program, and it is what makes the default configuration of JSCR do something
useful. It is not a replacement for Semgrep; it is a small set of rules with
a high enough precision to be worth reporting without a second opinion.

A rule earns its place by being hard to argue with. Anything that needs to
know how a function is called, what a variable holds, or whether input is
trusted belongs in Semgrep or in the AI pass, not here.
"""

from __future__ import annotations

import os
import re
import time
from typing import List, Pattern, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..review.findings import CRITICAL, HIGH, INFO, LOW, MEDIUM, SOURCE_SCANNER, Finding
from .base import Scanner, ScannerResult

# (rule_id, suffixes, pattern, severity, cwe, title, recommendation)
_Rule = Tuple[str, Tuple[str, ...], Pattern, str, str, str, str]

_PY = (".py",)
_JS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
_ANY = ()

RULES: Tuple[_Rule, ...] = (
    (
        "py-shell-true",
        _PY,
        re.compile(
            r"subprocess\.(?:run|call|check_output|check_call|Popen)\((?:[^)]*?)shell\s*=\s*True"
        ),
        HIGH,
        "CWE-78",
        "subprocess call with shell=True",
        "Pass the command as a list of arguments and leave shell at its default of False.",
    ),
    (
        "py-os-system",
        _PY,
        re.compile(r"\bos\.system\s*\("),
        HIGH,
        "CWE-78",
        "os.system runs a string through the shell",
        "Use subprocess.run with an argument list.",
    ),
    (
        "py-eval-exec",
        _PY,
        re.compile(r"(?<![\w.])(?:eval|exec)\s*\("),
        HIGH,
        "CWE-95",
        "eval or exec on a runtime value",
        "Parse the value instead. ast.literal_eval covers literal data.",
    ),
    (
        "py-pickle-load",
        _PY,
        re.compile(r"\bpickle\.loads?\s*\("),
        HIGH,
        "CWE-502",
        "pickle deserialises arbitrary objects",
        "Use JSON, or a format that cannot construct objects, for untrusted data.",
    ),
    (
        "py-yaml-load",
        _PY,
        re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)"),
        HIGH,
        "CWE-502",
        "yaml.load without a safe loader constructs arbitrary Python objects",
        "Use yaml.safe_load, or pass Loader=yaml.SafeLoader.",
    ),
    (
        "py-verify-off",
        _PY,
        re.compile(r"verify\s*=\s*False"),
        HIGH,
        "CWE-295",
        "TLS certificate verification disabled",
        "Leave verification on. For a private CA, pass its bundle to verify.",
    ),
    (
        "py-md5-sha1-password",
        _PY,
        re.compile(
            r"hashlib\.(?:md5|sha1)\s*\([^)]*(?:password|passwd|secret|token)", re.IGNORECASE
        ),
        HIGH,
        "CWE-916",
        "password hashed with a fast digest",
        "Use a password hash with a work factor: argon2, scrypt or bcrypt.",
    ),
    (
        "py-sql-format",
        _PY,
        re.compile(
            r"""(?i)\b(?:execute|executemany)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\.format\()|["'][^"']*["']\s*\+)"""
        ),
        HIGH,
        "CWE-89",
        "SQL built by string formatting",
        "Pass parameters to the driver: execute(sql, (value,)).",
    ),
    (
        "py-assert-auth",
        _PY,
        re.compile(r"^\s*assert\s+.*(?:auth|permission|is_admin|role|token)", re.IGNORECASE),
        MEDIUM,
        "CWE-617",
        "security check written as an assert",
        "assert is removed under python -O. Raise an exception instead.",
    ),
    (
        "py-tempfile-mktemp",
        _PY,
        re.compile(r"\btempfile\.mktemp\s*\("),
        MEDIUM,
        "CWE-377",
        "tempfile.mktemp is racy",
        "Use tempfile.NamedTemporaryFile or mkstemp.",
    ),
    (
        "py-bind-all",
        _PY,
        re.compile(r"""["']0\.0\.0\.0["']"""),
        LOW,
        "CWE-1327",
        "service binds to every interface",
        "Bind to a specific interface unless the service is meant to be public.",
    ),
    (
        "js-eval",
        _JS,
        re.compile(r"(?<![\w.])eval\s*\(|new\s+Function\s*\("),
        HIGH,
        "CWE-95",
        "eval or new Function on a runtime value",
        "Use JSON.parse for data, or a lookup table for dispatch.",
    ),
    (
        "js-inner-html",
        _JS,
        re.compile(r"\.innerHTML\s*=(?!\s*['\"]{2}\s*;?\s*$)"),
        MEDIUM,
        "CWE-79",
        "innerHTML assignment can introduce script",
        "Use textContent, or sanitise the value before assigning it.",
    ),
    (
        "js-child-process-exec",
        _JS,
        re.compile(r"child_process\.exec\s*\(|\bexec\s*\(\s*`"),
        HIGH,
        "CWE-78",
        "child_process.exec runs a string through the shell",
        "Use execFile or spawn with an argument list.",
    ),
    (
        "js-tls-reject-off",
        _JS,
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0|rejectUnauthorized\s*:\s*false"),
        HIGH,
        "CWE-295",
        "TLS certificate verification disabled",
        "Leave verification on. For a private CA, pass its certificate instead.",
    ),
    (
        "js-math-random-token",
        _JS,
        re.compile(
            r"Math\.random\s*\(\s*\)[^\n]*(?:token|secret|password|key|nonce|session)",
            re.IGNORECASE,
        ),
        HIGH,
        "CWE-338",
        "security value generated from Math.random",
        "Use crypto.randomUUID or crypto.getRandomValues.",
    ),
    (
        "generic-private-key",
        _ANY,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        CRITICAL,
        "CWE-798",
        "private key committed to the repository",
        "Remove it, rotate the key, and keep keys in a secret manager.",
    ),
    (
        "ci-pull-request-target",
        (".yml", ".yaml"),
        re.compile(r"^\s*(?:-\s*)?pull_request_target\s*:?\s*$", re.MULTILINE),
        HIGH,
        "CWE-269",
        "workflow triggers on pull_request_target",
        "This runs with repository secrets against a fork's code. Use pull_request, "
        "or never check out the fork's head in this workflow.",
    ),
    (
        "ci-unpinned-action",
        (".yml", ".yaml"),
        re.compile(
            # A step is written as a list item, so "- uses:" is the common
            # form and an anchor that only allows "uses:" misses nearly
            # every real workflow.
            r"^\s*(?:-\s+)?uses:\s*[\w.\-]+/[\w.\-]+@(?:main|master|v?\d+(?:\.\d+)*)\s*$",
            re.MULTILINE,
        ),
        LOW,
        "CWE-1357",
        "action pinned to a tag, not a commit",
        "Pin third-party actions to a full commit SHA. A tag can be moved.",
    ),
    (
        "ci-script-injection",
        (".yml", ".yaml"),
        re.compile(
            r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)\.[\w.]*(?:title|body|head\.ref|login)"
        ),
        HIGH,
        "CWE-94",
        "workflow interpolates attacker-controlled text into a script",
        'Pass the value through an env: variable and reference it as "$VAR".',
    ),
    (
        "docker-root-user",
        _ANY,
        re.compile(r"^\s*USER\s+root\s*$", re.MULTILINE),
        LOW,
        "CWE-250",
        "container runs as root",
        "Add a non-root USER before the entrypoint.",
    ),
    (
        "generic-todo-security",
        _ANY,
        re.compile(
            r"(?i)(?:#|//|/\*)\s*(?:TODO|FIXME|XXX|HACK)\b[^\n]*(?:secur|auth|inject|escape|sanit|crypt|password)"
        ),
        INFO,
        "",
        "unresolved security TODO",
        "Resolve it or record it where it will be seen.",
    ),
)

_DOCKERFILE_NAMES = ("dockerfile",)


class BuiltinScanner(Scanner):
    name = "builtin"
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
        for path in paths:
            suffix = os.path.splitext(path)[1].lower()
            basename = os.path.basename(path).lower()
            try:
                text = boundary.read_text(path)
            except (OSError, UnicodeDecodeError, BoundaryViolation):
                # A file that cannot be read is not scanned. Narrow on
                # purpose: a bare except here would also swallow a
                # boundary bug, and a boundary bug must not be survivable.
                continue
            lines = text.splitlines()
            for rule_id, suffixes, pattern, severity, cwe, title, fix in RULES:
                if suffixes and suffix not in suffixes:
                    if not (basename in _DOCKERFILE_NAMES and rule_id.startswith("docker-")):
                        continue
                for number, line in enumerate(lines, start=1):
                    if not pattern.search(line):
                        continue
                    findings.append(
                        Finding(
                            path=path,
                            line=number,
                            title=title,
                            detail=(
                                "Matched the deterministic rule {0}. This is a pattern "
                                "match, so confirm that the value involved is "
                                "attacker-influenced before treating it as exploitable."
                            ).format(rule_id),
                            severity=severity,
                            evidence=line.strip()[:400],
                            recommendation=fix,
                            rule_id="jscr/{0}".format(rule_id),
                            cwe=cwe,
                            confidence=0.85,
                            source=SOURCE_SCANNER,
                        )
                    )
        return ScannerResult(
            name=self.name,
            ran=True,
            findings=findings,
            duration_seconds=time.time() - started,
            version="rules={0}".format(len(RULES)),
        )
