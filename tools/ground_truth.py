"""Measure what the deterministic scanners find, against known defects.

Coverage says which lines ran. This says which planted defects were named.
The corpus lives in ``tests/ground_truth.py``: files written at run time with
one defect each, plus decoys that must stay quiet.

Three numbers come out of it.

recall
    planted defects reported, over planted defects. A miss here is a silent
    pass on a defect this tool claims to detect, which is the one failure the
    product cannot have.
false positives
    findings on a decoy file. A decoy is code that looks like the defect to a
    careless pattern and is not it.
extras
    findings on a planted file that the case did not ask for. These are
    counted and listed, never failed: one file can honestly trip two rules.

External scanners are not part of this. They are separate programs with their
own rules, so their recall is theirs to measure, not this repository's.

Usage:
    python3 tools/ground_truth.py [--json PATH] [--quiet]
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell
import sys
import tempfile
from typing import Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

from tests.ground_truth import CASES, expectations, materialise  # noqa: E402

from jscr.boundary.fs import RepositoryBoundary  # noqa: E402
from jscr.config import DEFAULTS, Config  # noqa: E402
from jscr.policy import Policy  # noqa: E402
from jscr.scanners.runner import run_scanners  # noqa: E402


def _commit() -> str:
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - git from PATH
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:  # pragma: no cover - git absent
        return "unknown"
    return out.stdout.decode("utf-8", "replace").strip() or "unknown"


def measure() -> Dict[str, object]:
    """Run the internal scanners over the corpus and score them."""
    import copy

    root = tempfile.mkdtemp(prefix="jscr-ground-truth-")
    try:
        paths = materialise(root)
        boundary = RepositoryBoundary(root)
        policy = Policy(Config(copy.deepcopy(DEFAULTS), None))
        results = run_scanners(policy, boundary, paths)

        found: List[Tuple[str, int, str]] = []
        for result in results:
            for finding in result.findings:
                found.append(
                    (finding.path.replace(os.sep, "/"), int(finding.line), finding.rule_id)
                )
        found_set = set(found)

        planted = expectations()
        hits: List[Dict[str, object]] = []
        misses: List[Dict[str, object]] = []
        for row in planted:
            key = (str(row["path"]), int(row["line"]), str(row["rule"]))
            (hits if key in found_set else misses).append(row)

        decoy_paths = {case.path for case in CASES if case.decoy}
        expected_keys = {(str(row["path"]), int(row["line"]), str(row["rule"])) for row in planted}
        false_positives = [
            {"path": path, "line": line, "rule": rule}
            for path, line, rule in sorted(set(found))
            if path in decoy_paths
        ]
        extras = [
            {"path": path, "line": line, "rule": rule}
            for path, line, rule in sorted(set(found))
            if path not in decoy_paths and (path, line, rule) not in expected_keys
        ]

        by_rule: Dict[str, Dict[str, int]] = {}
        for row in planted:
            rule = str(row["rule"])
            entry = by_rule.setdefault(rule, {"planted": 0, "found": 0})
            entry["planted"] += 1
        for row in hits:
            by_rule[str(row["rule"])]["found"] += 1

        scanners = [
            {"name": r.name, "ran": r.ran, "findings": len(r.findings), "error": r.error}
            for r in results
        ]
        return {
            "commit": _commit(),
            "measured_at": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "python": platform.python_version(),
            "cases": len(CASES),
            "decoys": len(decoy_paths),
            "planted": len(planted),
            "detected": len(hits),
            "recall_percent": round(100.0 * len(hits) / len(planted), 2) if planted else 0.0,
            "false_positives": false_positives,
            "extras": extras,
            "misses": misses,
            "by_rule": by_rule,
            "scanners": scanners,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def report(data: Dict[str, object]) -> str:
    lines: List[str] = []
    lines.append(
        "Ground truth: {0} of {1} planted defects detected ({2}%)".format(
            data["detected"], data["planted"], data["recall_percent"]
        )
    )
    lines.append(
        "Corpus: {0} files, {1} decoys. False positives on decoys: {2}.".format(
            data["cases"],
            data["decoys"],
            len(data["false_positives"]),  # type: ignore[arg-type]
        )
    )
    misses = data["misses"]
    if misses:
        lines.append("")
        lines.append("Not detected:")
        for row in misses:  # type: ignore[union-attr]
            lines.append(
                "  {0}  {1}:{2}  {3}".format(row["case"], row["path"], row["line"], row["rule"])
            )
    for row in data["false_positives"]:  # type: ignore[union-attr]
        lines.append("  FALSE POSITIVE {0}:{1} {2}".format(row["path"], row["line"], row["rule"]))
    extras = data["extras"]
    if extras:
        lines.append("")
        lines.append("Also reported, not planted ({0}):".format(len(extras)))  # type: ignore[arg-type]
        for row in extras:  # type: ignore[union-attr]
            lines.append("  {0}:{1} {2}".format(row["path"], row["line"], row["rule"]))
    return "\n".join(lines)


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", dest="json_path", default="", help="write the result here")
    parser.add_argument("--quiet", action="store_true", help="print nothing on success")
    args = parser.parse_args(argv)

    data = measure()
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
    if not args.quiet:
        print(report(data))
    return 0 if not data["misses"] and not data["false_positives"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
