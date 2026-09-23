"""The human-readable report.

Written for someone reading a terminal at the end of a working day. The
first screen answers three questions: what is wrong, where, and what was
the tool not permitted to check. The third is on the first screen on
purpose. A reviewer who does not know that the dependency scanner never
ran will read an empty dependency section as good news.
"""

from __future__ import annotations

from typing import Any, List

BAR = "-" * 72

_MARK = {
    "Critical": "[Critical]",
    "High": "[High]    ",
    "Medium": "[Medium]  ",
    "Low": "[Low]     ",
    "Info": "[Info]    ",
}


def render_text(result: Any, verbose: bool = False, colour: bool = False) -> str:
    out: List[str] = []
    add = out.append

    add(BAR)
    add("JMac Secure Code Review  -  {0}".format(result.target))
    add(BAR)

    counts = result.counts()
    total = len(result.findings)
    if total:
        summary = "  ".join(
            "{0} {1}".format(counts[name], name)
            for name in ("Critical", "High", "Medium", "Low", "Info")
            if counts.get(name)
        )
        add("{0} finding(s): {1}".format(total, summary))
    else:
        add("No findings above the confidence floor.")
    add("")

    _limits(add, result)

    if total:
        add("")
        add("Findings")
        add(BAR)
        for index, finding in enumerate(result.findings, 1):
            _finding(add, index, finding, verbose)

    if verbose and result.rejected:
        add("")
        add("Rejected before reporting ({0})".format(len(result.rejected)))
        add(BAR)
        for finding in result.rejected:
            add("  {0}:{1}  {2}".format(finding.path, finding.line or "?", finding.title))
            if finding.verification_note:
                add("      reason: {0}".format(finding.verification_note))

    add("")
    add(BAR)
    add(_verdict(result))
    return "\n".join(out)


def _limits(add, result: Any) -> None:
    """What the tool did, and what it was not allowed to do."""
    add("What ran")
    add(BAR)
    provider = result.provider or {}
    used = provider.get("used")
    if used and used != "null":
        add("  AI review      {0} ({1})".format(used, provider.get("model") or "model unset"))
    elif used == "null":
        add("  AI review      not run: the null provider is configured")
    else:
        add("  AI review      not run")

    for row in result.scanners:
        if row.get("ran"):
            add(
                "  {0:<14} {1} finding(s) in {2:.1f}s".format(
                    row["name"], row.get("findings", 0), row.get("duration_seconds", 0.0)
                )
            )
        else:
            add("  {0:<14} did not run: {1}".format(row["name"], row.get("error") or "unknown"))

    redaction = result.redaction or {}
    if redaction.get("applied"):
        add(
            "  redaction      {0} probable secret(s) removed before egress".format(
                redaction.get("hits")
            )
        )

    denials = (result.policy or {}).get("denied") or []
    if denials:
        add("")
        add("  Refused by policy:")
        for entry in denials:
            add("    - {0} {1}: {2}".format(entry["action"], entry["subject"], entry["reason"]))

    if result.errors:
        add("")
        add("  Errors:")
        for text in result.errors:
            add("    - {0}".format(text))
    if result.warnings:
        add("")
        add("  Notes:")
        for text in result.warnings:
            add("    - {0}".format(text))


def _finding(add, index: int, finding: Any, verbose: bool) -> None:
    add("")
    add("{0:>3}. {1} {2}".format(index, _MARK.get(finding.severity, "[?]       "), finding.title))
    add("     {0}:{1}".format(finding.path, finding.line or "?"))
    if finding.evidence:
        add("     > {0}".format(finding.evidence.strip()[:160]))
    if finding.detail:
        for line in _wrap(finding.detail, 66):
            add("     {0}".format(line))
    if finding.recommendation:
        add("     Fix: {0}".format(finding.recommendation.strip()))
    tail = []
    if finding.cwe:
        tail.append(finding.cwe)
    if finding.rule_id:
        tail.append(finding.rule_id)
    tail.append("confidence {0:.2f}".format(finding.confidence))
    tail.append(finding.source)
    if not finding.in_diff:
        tail.append("not in the diff")
    add("     ({0})".format(" - ".join(tail)))
    if verbose and finding.verification_note:
        add("     verified: {0}".format(finding.verification_note))


def _verdict(result: Any) -> str:
    worst = result.worst_severity()
    if worst in ("Critical", "High"):
        return "Result: Red - {0} finding(s) need attention before merge.".format(
            sum(1 for f in result.findings if f.severity in ("Critical", "High"))
        )
    if worst in ("Medium", "Low"):
        return "Result: Amber - nothing blocking, but there are issues worth reading."
    if result.errors:
        return "Result: Amber - the review completed with errors; read the notes above."
    return "Result: Green - nothing found. This is not proof the change is safe."


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = "{0} {1}".format(current, word).strip()
    if current:
        lines.append(current)
    return lines
