"""SARIF 2.1.0 output, for code scanning tools that consume it.

Every finding becomes a rule and a result. Findings that were rejected are
not emitted: SARIF has no vocabulary for "we considered this and decided it
was wrong", and inventing one would put unreviewed text in front of a
reviewer as though it had passed.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
VERSION = "2.1.0"

_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Info": "note",
}


def render_sarif(result: Any, indent: int = 2) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in result.findings:
        rule_id = finding.rule_id or "jscr/ai-review"
        if rule_id not in rules:
            rules[rule_id] = _rule(rule_id, finding)
        results.append(_result(rule_id, finding))

    from .. import __version__

    doc = {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "JMac Secure Code Review",
                        "informationUri": "https://github.com/JMacCyber/JMac-Secure-Code-Review",
                        "semanticVersion": __version__,
                        "version": __version__,
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": text}} for text in result.errors
                        ]
                        + [
                            {"level": "warning", "message": {"text": text}}
                            for text in result.warnings
                        ],
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=indent, default=str)


def _rule(rule_id: str, finding: Any) -> Dict[str, Any]:
    rule: Dict[str, Any] = {
        "id": rule_id,
        "name": rule_id.replace("/", "."),
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {"level": _LEVEL.get(finding.severity, "warning")},
        "properties": {"problem.severity": finding.severity.lower()},
    }
    if finding.cwe:
        rule["properties"]["tags"] = ["security", finding.cwe]
        rule["properties"]["security-severity"] = _security_severity(finding.severity)
    else:
        rule["properties"]["tags"] = ["security"]
    return rule


def _result(rule_id: str, finding: Any) -> Dict[str, Any]:
    body = finding.detail or finding.title
    if finding.recommendation:
        body = "{0}\n\nRecommendation: {1}".format(body, finding.recommendation)
    entry: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVEL.get(finding.severity, "warning"),
        "message": {"text": body},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, int(finding.line or 1))},
                }
            }
        ],
        "properties": {
            "confidence": finding.confidence,
            "source": finding.source,
            "in_diff": finding.in_diff,
        },
    }
    if finding.evidence:
        region = entry["locations"][0]["physicalLocation"]["region"]
        region["snippet"] = {"text": finding.evidence}
    entry["partialFingerprints"] = {"jscr/v1": finding.fingerprint()}
    return entry


def _security_severity(severity: str) -> str:
    return {
        "Critical": "9.5",
        "High": "8.0",
        "Medium": "5.5",
        "Low": "3.0",
        "Info": "1.0",
    }.get(severity, "5.5")
