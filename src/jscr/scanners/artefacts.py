"""Code a person is not meant to read.

Minified and obfuscated files are not wrong in themselves — a build writes
them every day. They matter because every other rule in this engine reads
source, and a 400,000-character line defeats all of them. So the point of
this scanner is not to say "this is bad", it is to say "nothing else here
looked at this file, and here is why".

The four signals are kept apart rather than summed, because they mean
different things: minified is a build output, obfuscated is a deliberate
choice to hide meaning, and a large encoded blob is a payload.
"""

from __future__ import annotations

import re
import time
from typing import List, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..review.findings import HIGH, INFO, LOW, MEDIUM, SOURCE_SCANNER, Finding
from .base import Scanner, ScannerResult

#: A line this long is not written by hand.
_LONG_LINE = 500

#: The signature the common JavaScript packer leaves at the top of its output.
_PACKER = re.compile(r"eval\(function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e")

#: Identifiers renamed to hex, the default of the widely used obfuscators.
_HEX_NAME = re.compile(r"_0x[0-9a-f]{4,}")

#: Character-by-character escaping, used to keep strings out of a grep.
_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")

#: A base64 run long enough to hold code rather than a key or an image name.
_B64 = re.compile(r"[A-Za-z0-9+/]{240,}={0,2}")

_SOURCE_SUFFIX = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".php", ".rb", ".sh")
_BUILD_HINT = (
    "/dist/",
    "/build/",
    "/vendor/",
    "/node_modules/",
    ".min.",
    "-min.",
    "/out/",
    "/.next/",
    "/coverage/",
)


class ArtefactScanner(Scanner):
    """Minified, obfuscated and encoded content in source directories."""

    name = "artefacts"
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
        read = 0
        for path in paths:
            normalised = path.replace("\\", "/")
            if not normalised.endswith(_SOURCE_SUFFIX):
                continue
            try:
                text = boundary.read_text(path)
            except (OSError, UnicodeDecodeError, BoundaryViolation):
                continue
            read += 1
            findings.extend(self._file(path, normalised, text))
        return ScannerResult(
            name=self.name,
            ran=True,
            findings=findings,
            duration_seconds=time.time() - started,
            version="files={0}".format(read),
        )

    def _file(self, path: str, normalised: str, text: str) -> List[Finding]:
        lines = text.splitlines()
        if not lines:
            return []
        findings: List[Finding] = []
        # Leading slash so that "dist/x.js" matches "/dist/" the same way
        # "src/dist/x.js" does.
        built = any(hint in "/" + normalised for hint in _BUILD_HINT)

        widest, widest_line = 0, 1
        for index, line in enumerate(lines, start=1):
            if len(line) > widest:
                widest, widest_line = len(line), index

        packed = _first(lines, _PACKER)
        if packed:
            number, _ = packed
            findings.append(
                Finding(
                    path=path,
                    line=number,
                    title="packed JavaScript: the file is generated and then evaluated",
                    detail=(
                        "The file starts with the eval(function(p,a,c,k,e signature, which "
                        "means the code that runs is built from a string at load time. "
                        "Nothing in this repository shows what that code does."
                    ),
                    severity=HIGH,
                    evidence=_clip(lines, number),
                    recommendation=(
                        "Replace the packed file with the source it was built from, and "
                        "build it as part of the pipeline. If it came from elsewhere, pin "
                        "the version, record where it came from, and check its hash."
                    ),
                    rule_id="jscr/packed-code",
                    cwe="CWE-506",
                    confidence=0.85,
                    source=SOURCE_SCANNER,
                )
            )

        hex_names = len(set(_HEX_NAME.findall(text)))
        if hex_names >= 5:
            number = _first(lines, _HEX_NAME)[0] if _first(lines, _HEX_NAME) else 1
            findings.append(
                Finding(
                    path=path,
                    line=number,
                    title="obfuscated identifiers: {0} names rewritten to hex".format(hex_names),
                    detail=(
                        "Names of the form _0x1a2b3c are what JavaScript obfuscators emit. "
                        "A minifier shortens names to a, b, c; it does not encode them. "
                        "The choice here was to make the file unreadable, not smaller."
                    ),
                    severity=HIGH,
                    evidence=_clip(lines, number),
                    recommendation=(
                        "Get the original source. If this is a third-party file, treat it "
                        "as untrusted code you are shipping: check where it came from and "
                        "whether the publisher's hash matches."
                    ),
                    rule_id="jscr/obfuscated-identifiers",
                    cwe="CWE-506",
                    confidence=0.8,
                    source=SOURCE_SCANNER,
                )
            )

        escapes = len(_HEX_ESCAPE.findall(text))
        if escapes >= 40 and not packed:
            number = _first(lines, _HEX_ESCAPE)[0] if _first(lines, _HEX_ESCAPE) else 1
            findings.append(
                Finding(
                    path=path,
                    line=number,
                    title="{0} hex-escaped characters hide the strings".format(escapes),
                    detail=(
                        "Strings written as \\x68\\x65\\x6c\\x6c\\x6f read the same to the "
                        "runtime and differently to every search. A file that hides its "
                        "own strings is hiding them from a reader, not from a parser."
                    ),
                    severity=MEDIUM,
                    evidence=_clip(lines, number),
                    recommendation=(
                        "Decode the strings and read them before this ships. If the file "
                        "is a dependency, check the published source against it."
                    ),
                    rule_id="jscr/hex-escaped-strings",
                    cwe="CWE-506",
                    confidence=0.6,
                    source=SOURCE_SCANNER,
                )
            )

        blob = _first(lines, _B64)
        if blob:
            number, match = blob
            findings.append(
                Finding(
                    path=path,
                    line=number,
                    title="{0}-character encoded blob in source".format(len(match)),
                    detail=(
                        "A base64 run this long holds a file, not a key or an identifier. "
                        "What it decodes to is not checked here. It is reported because a "
                        "blob in a source file is content no review has read."
                    ),
                    severity=MEDIUM if not built else LOW,
                    evidence=_clip(lines, number),
                    recommendation=(
                        "Decode it and confirm what it is. If it is an asset, keep it as a "
                        "file the build references, so it can be diffed and replaced."
                    ),
                    rule_id="jscr/encoded-blob",
                    cwe="CWE-506",
                    confidence=0.5,
                    source=SOURCE_SCANNER,
                )
            )

        if widest >= _LONG_LINE and not packed and not hex_names:
            findings.append(
                Finding(
                    path=path,
                    line=widest_line,
                    title="minified file: longest line is {0} characters".format(widest),
                    detail=(
                        "Every line-based rule in this engine reads one line at a time, so "
                        "a file like this is effectively unreviewed: a weakness inside it "
                        "is reported at one line number with {0} characters of context. "
                        "This is the expected shape of build output."
                    ).format(widest),
                    severity=INFO if built else LOW,
                    evidence="",
                    recommendation=(
                        "If this is build output, exclude the directory from review and "
                        "scan the source instead. If it is committed third-party code, "
                        "move it to a dependency so its version and hash are recorded."
                    ),
                    rule_id="jscr/minified-file",
                    cwe="",
                    confidence=0.7,
                    source=SOURCE_SCANNER,
                )
            )
        return findings


def _first(lines: Sequence[str], pattern) -> Tuple[int, str]:
    for index, line in enumerate(lines, start=1):
        match = pattern.search(line)
        if match:
            return index, match.group(0)
    return ()  # type: ignore[return-value]


def _clip(lines: Sequence[str], number: int) -> str:
    """Evidence must be text that is really at the cited line, and short."""
    if 1 <= number <= len(lines):
        return lines[number - 1].strip()[:160]
    return ""
