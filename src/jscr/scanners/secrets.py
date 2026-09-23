"""The committed-secret scanner.

The redaction layer already knows what a secret looks like: it has to, because
it refuses to send one to a model. A credential sitting in the repository is
the same fact seen from the other side, so this scanner reads the same rules
rather than keeping a second, drifting copy of them.

The finding never repeats the secret. Evidence is deliberately empty and the
detail carries a short preview and a fingerprint, because a report is itself
somewhere a credential can leak to.
"""

from __future__ import annotations

import time
from typing import List, Sequence

from ..boundary.fs import RepositoryBoundary
from ..config import Config
from ..errors import BoundaryViolation
from ..redaction.secrets import Redactor
from ..review.findings import CRITICAL, SOURCE_SCANNER, Finding
from .base import Scanner, ScannerResult


class SecretScanner(Scanner):
    name = "secrets"
    external = False

    def __init__(self, config: Config = None) -> None:  # type: ignore[assignment]
        extra = config.get("redaction.extra_patterns", ()) if config is not None else ()
        # block_on_secret is an egress decision and has nothing to do with
        # reporting: a run that sends nothing still reports what it found.
        self.redactor = Redactor(enabled=True, block_on_secret=False, extra_patterns=extra)

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
            try:
                text = boundary.read_text(path)
            except (OSError, UnicodeDecodeError, BoundaryViolation):
                continue
            # The whole file is scanned in one pass, not line by line: a
            # private key block spans many lines, and a rule that can only
            # see one line at a time can never match it.
            for hit in self.redactor.scan(text):
                number = text.count("\n", 0, hit.start) + 1
                findings.append(
                    Finding(
                        path=path,
                        line=number,
                        title="credential committed to the repository",
                        detail=(
                            "Matched the secret rule {0}. The value is not repeated "
                            "here: {1} (fingerprint {2}). Treat it as disclosed to "
                            "everyone who can read this history."
                        ).format(hit.rule, hit.preview, hit.fingerprint),
                        severity=CRITICAL,
                        evidence="",
                        recommendation=(
                            "Rotate the credential first, then remove it from the "
                            "code and read it from a secret manager or the "
                            "environment. Removing it from the working tree does "
                            "not remove it from the history."
                        ),
                        rule_id="jscr/committed-secret",
                        cwe="CWE-798",
                        confidence=0.85,
                        source=SOURCE_SCANNER,
                    )
                )
        return ScannerResult(
            name=self.name,
            ran=True,
            findings=findings,
            duration_seconds=time.time() - started,
            version="rules={0}".format(len(self.redactor.rules)),
        )
