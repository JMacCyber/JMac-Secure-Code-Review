"""Second-pass verification.

A first-pass reviewer, model or scanner, produces candidates. Publishing
those candidates directly is how a review tool earns a reputation for noise.
Verification is two checks, in this order:

1. **Anchoring**, which is deterministic. Does the file exist in the review?
   Does the cited line exist? Does the quoted evidence actually appear at or
   near that line? Is the line inside the diff? A finding that fails
   anchoring is corrected where it can be, and rejected where it cannot.
2. **Adversarial review**, which asks the model to argue against each
   surviving finding.

Anchoring runs whether or not a model is configured, so the deterministic
half of verification is always on.

Two rules keep anchoring from deleting true findings:

* The content it checks against is the file, not only the context bundle.
  The bundle is capped at a file count and a byte budget, so a finding in a
  file the budget left out is not wrong - it is unchecked. The file is read
  through the boundary, and the bundle's copy is the fallback.
* A scanner quotes the line it matched. If that quote turns up elsewhere in
  the file, the file moved under the run, not the scanner. A scanner finding
  is relocated to the quote. A model finding in the same position is still
  rejected, because a model can invent a line number.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..context.bundle import Bundle
from ..errors import BoundaryViolation
from .findings import SOURCE_SCANNER, Finding, Severity

#: How far from the cited line the evidence may appear before the finding is
#: treated as mis-anchored rather than merely off by an editor's margin.
ANCHOR_WINDOW = 8


class AnchorResult(object):
    """What anchoring concluded about one finding."""

    __slots__ = ("ok", "reason", "corrected_line")

    def __init__(self, ok: bool, reason: str = "", corrected_line: Optional[int] = None) -> None:
        self.ok = ok
        self.reason = reason
        self.corrected_line = corrected_line


def _content(path: str, bundle: Bundle, boundary: Optional[RepositoryBoundary]) -> Optional[str]:
    """The text to anchor against: the file itself, else the bundle's copy.

    The file wins because the bundle's copy was taken when the bundle was
    built and can be minutes old by the time anchoring runs.
    """
    if boundary is not None:
        try:
            return boundary.read_text(path)
        except (BoundaryViolation, OSError, UnicodeDecodeError):
            pass
    for candidate in bundle.files:
        if candidate.path == path:
            return candidate.content
    return None


def anchor(
    finding: Finding, bundle: Bundle, boundary: Optional[RepositoryBoundary] = None
) -> AnchorResult:
    """Check a finding against the content it claims to describe."""
    content = _content(finding.path, bundle, boundary)
    if content is None:
        return AnchorResult(False, "file {0!r} could not be read for checking".format(finding.path))

    lines = content.splitlines()
    if finding.line < 1 or finding.line > len(lines):
        relocated = _find_evidence(finding.evidence, lines)
        if relocated is None:
            return AnchorResult(
                False,
                "line {0} does not exist in {1} ({2} lines)".format(
                    finding.line, finding.path, len(lines)
                ),
            )
        return AnchorResult(True, "line corrected from evidence", relocated)

    if finding.evidence:
        at_line = lines[finding.line - 1]
        if _matches(finding.evidence, at_line):
            return AnchorResult(True, "evidence found at the cited line")
        nearby = _find_evidence(finding.evidence, lines, around=finding.line)
        if nearby is not None:
            return AnchorResult(True, "line corrected from evidence", nearby)
        relocated = _find_evidence(finding.evidence, lines)
        if relocated is not None:
            if finding.source == SOURCE_SCANNER:
                # The scanner read this exact line out of this exact file. A
                # distance means the file changed during the run, not that the
                # match was invented, so move the finding to the line that
                # holds it.
                return AnchorResult(
                    True,
                    "line corrected from evidence: the file moved during the run",
                    relocated,
                )
            return AnchorResult(
                False,
                "evidence is at line {0}, not {1}; too far to be a rounding error".format(
                    relocated, finding.line
                ),
                relocated,
            )
        return AnchorResult(
            False, "the quoted evidence does not appear in {0}".format(finding.path)
        )
    return AnchorResult(True, "line exists; no evidence quoted to check")


def apply_anchoring(
    findings: Sequence[Finding],
    bundle: Bundle,
    boundary: Optional[RepositoryBoundary] = None,
) -> Tuple[List[Finding], List[Finding]]:
    """Return ``(kept, rejected)`` after deterministic anchoring."""
    kept: List[Finding] = []
    rejected: List[Finding] = []
    for finding in findings:
        result = anchor(finding, bundle, boundary)
        if result.corrected_line and result.ok:
            finding.line = result.corrected_line
            finding.end_line = max(finding.end_line, result.corrected_line)
        diff = bundle.diff_for(finding.path)
        finding.in_diff = bool(diff and finding.line in set(diff.positions_touched()))
        if result.ok:
            finding.verification_note = result.reason
            kept.append(finding)
        else:
            finding.verified = False
            finding.verification_note = result.reason
            rejected.append(finding)
    return kept, rejected


def apply_verdicts(
    findings: Sequence[Finding], payload: str
) -> Tuple[List[Finding], List[Finding]]:
    """Apply a verification model's verdicts. Unmentioned findings survive.

    A verifier that returns nothing, or malformed output, must not silently
    delete the review. Only an explicit rejection rejects.
    """
    verdicts = _parse_verdicts(payload)
    kept: List[Finding] = []
    rejected: List[Finding] = []
    for index, finding in enumerate(findings):
        verdict = verdicts.get(index)
        if verdict is None:
            finding.verified = None
            if not finding.verification_note:
                finding.verification_note = "no verdict returned; kept unverified"
            kept.append(finding)
            continue
        note = str(verdict.get("note") or verdict.get("reason") or verdict.get("why") or "").strip()
        severity = verdict.get("severity")
        if severity:
            finding.severity = Severity.normalise(severity)
        confidence = verdict.get("confidence")
        if confidence is not None:
            try:
                finding.confidence = max(0.0, min(1.0, float(confidence)))
            except (TypeError, ValueError):
                pass
        if _is_rejection(verdict.get("verdict")):
            finding.verified = False
            finding.verification_note = note or "rejected by verification pass"
            rejected.append(finding)
        else:
            finding.verified = True
            finding.verification_note = note or "confirmed by verification pass"
            kept.append(finding)
    return kept, rejected


# Words that mean "this finding is wrong". Anything else, including
# silence, an unexpected word, or a missing field, keeps the finding. Only
# an explicit rejection rejects, because the cost runs one way: a wrongly
# kept finding wastes a reviewer's minute, and a wrongly deleted one is a
# vulnerability nobody ever hears about.
_REJECTION_WORDS = frozenset(
    {
        "reject",
        "rejected",
        "false",
        "false_positive",
        "false-positive",
        "invalid",
        "incorrect",
        "not_a_finding",
        "no",
    }
)


def _is_rejection(value: Any) -> bool:
    return str(value or "").strip().lower().replace(" ", "_") in _REJECTION_WORDS


def _parse_verdicts(payload: str) -> Dict[int, Dict[str, Any]]:
    data = parse_json_object(payload)
    verdicts: Dict[int, Dict[str, Any]] = {}
    # A bare list is accepted as well as {"verdicts": [...]}. The prompt asks
    # for one shape; being strict about which one a model chose would throw
    # away a valid answer over punctuation.
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("verdicts") or data.get("results") or []
    else:
        return verdicts
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            index = int(entry.get("index", -1))
        except (TypeError, ValueError):
            continue
        verdicts[index] = entry
    return verdicts


def parse_json_object(payload: str) -> Optional[Any]:
    """Read a JSON object out of model output.

    Models wrap JSON in prose or in a fenced block often enough that failing
    on it would be pedantry. The parser tries the whole string, then a fenced
    block, then the outermost braces. It never evaluates anything.
    """
    if not payload:
        return None
    text = payload.strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    fenced = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1).strip())
        except ValueError:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except ValueError:
            return None
    return None


def _matches(evidence: str, line: str) -> bool:
    return _normalise(evidence.splitlines()[0] if evidence else "") in _normalise(line)


def _find_evidence(
    evidence: str, lines: Sequence[str], around: Optional[int] = None
) -> Optional[int]:
    if not evidence:
        return None
    needle = _normalise(evidence.splitlines()[0])
    if not needle:
        return None
    if around is not None:
        low = max(1, around - ANCHOR_WINDOW)
        high = min(len(lines), around + ANCHOR_WINDOW)
        for number in range(low, high + 1):
            if needle in _normalise(lines[number - 1]):
                return number
        return None
    for number, line in enumerate(lines, start=1):
        if needle in _normalise(line):
            return number
    return None


def _normalise(text: str) -> str:
    return " ".join(str(text or "").split())
