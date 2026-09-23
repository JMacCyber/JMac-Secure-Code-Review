"""Findings.

A finding is a claim about a specific place in the code. It is only useful if
a reader can check it, so every finding carries the file, the line, the code
at that line, and the reason — and a finding whose line is not in the diff is
demoted rather than published as though it were reviewed.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
INFO = "Info"

SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW, INFO)
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

SOURCE_MODEL = "model"
SOURCE_SCANNER = "scanner"


class Severity(object):
    """Severity names, capitalised, with a total order for sorting."""

    CRITICAL = CRITICAL
    HIGH = HIGH
    MEDIUM = MEDIUM
    LOW = LOW
    INFO = INFO
    ALL = SEVERITIES

    @staticmethod
    def normalise(value: Any) -> str:
        text = str(value or "").strip().lower()
        for name in SEVERITIES:
            if text == name.lower():
                return name
        # Accept the vocabularies external scanners use.
        aliases = {
            "error": HIGH,
            "warning": MEDIUM,
            "warn": MEDIUM,
            "note": LOW,
            "informational": INFO,
            "blocker": CRITICAL,
            "severe": CRITICAL,
            "moderate": MEDIUM,
            "minor": LOW,
        }
        return aliases.get(text, MEDIUM)

    @staticmethod
    def rank(value: str) -> int:
        return _SEVERITY_RANK.get(value, _SEVERITY_RANK[MEDIUM])

    @staticmethod
    def at_least(value: str, floor: str) -> bool:
        return Severity.rank(value) <= Severity.rank(floor)


class Finding(object):
    """One reviewable claim."""

    __slots__ = (
        "path",
        "line",
        "end_line",
        "severity",
        "title",
        "detail",
        "evidence",
        "recommendation",
        "rule_id",
        "cwe",
        "confidence",
        "source",
        "verified",
        "verification_note",
        "in_diff",
    )

    def __init__(
        self,
        path: str,
        line: int,
        title: str,
        detail: str = "",
        severity: str = MEDIUM,
        evidence: str = "",
        recommendation: str = "",
        rule_id: str = "",
        cwe: str = "",
        confidence: float = 0.5,
        source: str = SOURCE_MODEL,
        end_line: Optional[int] = None,
    ) -> None:
        self.path = path
        self.line = int(line or 0)
        self.end_line = int(end_line or self.line)
        self.severity = Severity.normalise(severity)
        self.title = _one_line(title)
        self.detail = detail.strip()
        self.evidence = evidence.rstrip()
        self.recommendation = recommendation.strip()
        self.rule_id = rule_id.strip()
        self.cwe = cwe.strip()
        self.confidence = _clamp(confidence)
        self.source = source
        self.verified: Optional[bool] = None
        self.verification_note = ""
        self.in_diff: Optional[bool] = None

    # -- identity -------------------------------------------------------
    def fingerprint(self) -> str:
        """Stable across runs, so a finding can be suppressed or tracked.

        Deliberately excludes the line number: a finding that moves because
        lines were inserted above it is the same finding.
        """
        basis = "|".join(
            [
                self.path,
                self.rule_id or _slug(self.title),
                _slug(self.evidence[:120]),
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint(),
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "confidence": round(self.confidence, 3),
            "source": self.source,
            "verified": self.verified,
            "verification_note": self.verification_note,
            "in_diff": self.in_diff,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source: str = SOURCE_MODEL) -> "Finding":
        finding = cls(
            path=str(data.get("path") or data.get("file") or ""),
            line=_as_int(data.get("line") or data.get("start_line")),
            title=str(data.get("title") or data.get("message") or ""),
            detail=str(data.get("detail") or data.get("description") or ""),
            severity=str(data.get("severity") or ""),
            evidence=str(data.get("evidence") or data.get("snippet") or ""),
            recommendation=str(data.get("recommendation") or data.get("fix") or ""),
            rule_id=str(data.get("rule_id") or data.get("rule") or ""),
            cwe=str(data.get("cwe") or ""),
            confidence=data.get("confidence", 0.5),
            source=source,
            end_line=_as_int(data.get("end_line")) or None,
        )
        return finding

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Finding {0} {1}:{2} {3}>".format(
            self.severity, self.path, self.line, self.title[:48]
        )


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Most severe first, then by file and line, so output is stable."""
    return sorted(
        findings,
        key=lambda f: (Severity.rank(f.severity), -f.confidence, f.path, f.line, f.title),
    )


def dedupe(findings: Sequence[Finding]) -> List[Finding]:
    """Collapse findings that say the same thing about the same place.

    Two findings merge when they share a fingerprint, or when they sit on the
    same file and line with the same rule. The survivor keeps the highest
    severity and confidence of the pair, and prefers a scanner's wording:
    a deterministic rule is citable, a model's phrasing is not.
    """
    kept: Dict[str, Finding] = {}
    order: List[str] = []
    for finding in findings:
        key = finding.fingerprint()
        line_key = "{0}:{1}:{2}".format(finding.path, finding.line, finding.rule_id or "")
        merged_key = None
        if key in kept:
            merged_key = key
        elif finding.rule_id:
            for existing_key in order:
                existing = kept[existing_key]
                if (
                    existing.path == finding.path
                    and existing.line == finding.line
                    and existing.rule_id == finding.rule_id
                ):
                    merged_key = existing_key
                    break
        if merged_key is None:
            kept[key] = finding
            order.append(key)
            continue
        del line_key
        kept[merged_key] = _merge(kept[merged_key], finding)
    return [kept[k] for k in order]


def _merge(first: Finding, second: Finding) -> Finding:
    winner = first
    loser = second
    if first.source != SOURCE_SCANNER and second.source == SOURCE_SCANNER:
        winner, loser = second, first
    if Severity.rank(loser.severity) < Severity.rank(winner.severity):
        winner.severity = loser.severity
    winner.confidence = max(winner.confidence, loser.confidence)
    if not winner.cwe and loser.cwe:
        winner.cwe = loser.cwe
    if not winner.recommendation and loser.recommendation:
        winner.recommendation = loser.recommendation
    if loser.detail and loser.detail not in winner.detail:
        # Corroboration from a second source is worth keeping, briefly.
        winner.detail = "{0}\n\nAlso reported by {1}: {2}".format(
            winner.detail, loser.source, loser.detail
        ).strip()
    return winner


def _one_line(text: str) -> str:
    return " ".join(str(text or "").split())[:200]


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")


def _clamp(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, number))


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
