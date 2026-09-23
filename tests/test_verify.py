"""Deterministic anchoring, and what a verifier is permitted to do.

Anchoring answers a question no model can be trusted with about its own
output: does the line it cited exist, and does the evidence it quoted
actually appear there? A finding that fails that check is removed before
anyone reads it.
"""

from __future__ import annotations

import json
import unittest

from jscr.boundary.fs import RepositoryBoundary
from jscr.context.bundle import build_bundle
from jscr.review.findings import (
    SOURCE_MODEL,
    SOURCE_SCANNER,
    Finding,
    Severity,
    dedupe,
    sort_findings,
)
from jscr.review.verify import apply_anchoring, apply_verdicts, parse_json_object
from jscr.vcs.diff import parse_unified_diff

from .support import RepoTestCase

SOURCE = """import os


def run(name):
    os.system("echo " + name)
    return True
"""


class Anchoring(RepoTestCase):
    def setUp(self):
        super().setUp()
        self.repo.write("app.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("app.py", SOURCE)
        self.repo.git("add", "-A")
        diffs = parse_unified_diff(self.repo.git("diff", "--cached", "--no-color", "-U3"))
        self.bundle = build_bundle(RepositoryBoundary(self.repo.root), diffs, target="test")

    def finding(self, **kwargs):
        defaults = dict(  # noqa: C408 - reads as a record of test defaults
            path="app.py",
            line=5,
            title="shell injection",
            detail="os.system with a runtime value",
            severity=Severity.HIGH,
            evidence='os.system("echo " + name)',
            confidence=0.9,
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_a_correct_finding_survives(self):
        kept, rejected = apply_anchoring([self.finding()], self.bundle)
        self.assertEqual(len(kept), 1)
        self.assertEqual(rejected, [])
        self.assertTrue(kept[0].in_diff)

    def test_a_finding_citing_a_file_not_in_the_bundle_is_rejected(self):
        kept, rejected = apply_anchoring([self.finding(path="not_reviewed.py")], self.bundle)
        self.assertEqual(kept, [])
        self.assertEqual(len(rejected), 1)

    def test_a_line_past_the_end_with_real_evidence_is_corrected(self):
        """The quoted evidence is the anchor; the number is only a hint.

        Models miscount lines routinely. Rejecting a true finding over an
        off-by-forty line number would throw away the finding to protect
        the citation, which is the wrong way round.
        """
        kept, _ = apply_anchoring([self.finding(line=9999)], self.bundle)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].line, 5)

    def test_a_line_past_the_end_with_no_real_evidence_is_rejected(self):
        kept, rejected = apply_anchoring([self.finding(line=9999, evidence="")], self.bundle)
        self.assertEqual(kept, [])
        self.assertEqual(len(rejected), 1)

    def test_evidence_that_does_not_appear_anywhere_is_rejected(self):
        kept, _ = apply_anchoring(
            [self.finding(evidence="subprocess.call(shell=True)")], self.bundle
        )
        self.assertEqual(kept, [])

    def test_evidence_a_few_lines_off_is_corrected_not_rejected(self):
        """Models miscount lines. The evidence is the anchor, not the number."""
        kept, _ = apply_anchoring([self.finding(line=3)], self.bundle)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].line, 5)

    def test_a_finding_outside_the_diff_is_kept_but_marked(self):
        """Changed code can break code that did not change."""
        self.repo.write("helper.py", "import os\n")
        finding = self.finding(path="app.py", line=1, evidence="import os")
        kept, _ = apply_anchoring([finding], self.bundle)
        self.assertEqual(len(kept), 1)


class Verdicts(unittest.TestCase):
    def finding(self, title="a finding"):
        return Finding(path="app.py", line=1, title=title, severity=Severity.HIGH)

    def test_an_explicit_rejection_removes_the_finding(self):
        findings = [self.finding("one")]
        payload = json.dumps(
            {"verdicts": [{"index": 0, "verdict": "reject", "reason": "not reachable"}]}
        )
        kept, rejected = apply_verdicts(findings, payload)
        self.assertEqual(kept, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("not reachable", rejected[0].verification_note)

    def test_an_explicit_confirmation_keeps_the_finding(self):
        findings = [self.finding()]
        payload = json.dumps([{"index": 0, "verdict": "confirm"}])
        kept, rejected = apply_verdicts(findings, payload)
        self.assertEqual(len(kept), 1)
        self.assertEqual(rejected, [])

    def test_silence_is_not_rejection(self):
        """A verifier that returns nothing must not delete the review."""
        findings = [self.finding("one"), self.finding("two")]
        kept, rejected = apply_verdicts(findings, "")
        self.assertEqual(len(kept), 2)
        self.assertEqual(rejected, [])

    def test_malformed_output_is_not_rejection(self):
        findings = [self.finding()]
        kept, _ = apply_verdicts(findings, "I'm not going to answer that.")
        self.assertEqual(len(kept), 1)

    def test_an_unmentioned_finding_survives(self):
        findings = [self.finding("one"), self.finding("two")]
        payload = json.dumps({"verdicts": [{"index": 0, "verdict": "reject"}]})
        kept, _ = apply_verdicts(findings, payload)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].title, "two")

    def test_an_out_of_range_index_is_ignored_rather_than_crashing(self):
        findings = [self.finding()]
        payload = json.dumps({"verdicts": [{"index": 42, "verdict": "reject"}]})
        kept, _ = apply_verdicts(findings, payload)
        self.assertEqual(len(kept), 1)


class JsonExtraction(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(parse_json_object('{"a": 1}'), {"a": 1})

    def test_fenced_json(self):
        self.assertEqual(parse_json_object('```json\n{"a": 1}\n```'), {"a": 1})

    def test_json_with_chatter_around_it(self):
        self.assertEqual(
            parse_json_object('Sure! Here you go:\n{"a": 1}\nHope that helps.'), {"a": 1}
        )

    def test_nothing_parseable_returns_none(self):
        self.assertIsNone(parse_json_object("no json here"))

    def test_it_never_evaluates_anything(self):
        """A model returning Python is not a reason to run Python."""
        self.assertIsNone(parse_json_object("__import__('os').system('true')"))


class FindingHygiene(unittest.TestCase):
    def test_fingerprint_ignores_the_line_number(self):
        """A finding that moves is still the same finding."""
        first = Finding(path="a.py", line=10, title="t", severity=Severity.HIGH, evidence="e")
        second = Finding(path="a.py", line=40, title="t", severity=Severity.HIGH, evidence="e")
        self.assertEqual(first.fingerprint(), second.fingerprint())

    def test_duplicates_are_merged(self):
        findings = [
            Finding(path="a.py", line=1, title="t", severity=Severity.HIGH, evidence="e"),
            Finding(path="a.py", line=1, title="t", severity=Severity.HIGH, evidence="e"),
        ]
        self.assertEqual(len(dedupe(findings)), 1)

    def test_sorting_puts_the_worst_first(self):
        findings = [
            Finding(path="a.py", line=1, title="low", severity=Severity.LOW),
            Finding(path="a.py", line=2, title="critical", severity=Severity.CRITICAL),
            Finding(path="a.py", line=3, title="medium", severity=Severity.MEDIUM),
        ]
        self.assertEqual([f.title for f in sort_findings(findings)], ["critical", "medium", "low"])

    def test_severity_words_are_capitalised(self):
        for value in ("high", "HIGH", "High", "error"):
            self.assertIn(Severity.normalise(value), Severity.ALL)
        self.assertEqual(Severity.normalise("high"), "High")

    def test_an_unknown_severity_becomes_medium_not_critical(self):
        self.assertEqual(Severity.normalise("banana"), Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()


class AnchoringReadsTheFileNotOnlyTheBundle(RepoTestCase):
    """The bundle is a budget, not the truth about what the repository holds.

    ``build_bundle`` caps the files and bytes it carries. Anchoring a
    finding only against that copy means a finding in a file the budget
    left out is thrown away for being unchecked, and a file that changed
    while the run was going is read as a scanner error.
    """

    def setUp(self):
        super().setUp()
        self.repo.write("app.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("app.py", SOURCE)
        self.repo.write("other.py", "import os\nos.system(cmd)\n")
        self.repo.git("add", "-A")
        diffs = parse_unified_diff(self.repo.git("diff", "--cached", "--no-color", "-U3"))
        self.boundary = RepositoryBoundary(self.repo.root)
        self.bundle = build_bundle(
            self.boundary, [d for d in diffs if d.path == "app.py"], target="test"
        )

    def scanner_finding(self, **kwargs):
        defaults = dict(  # noqa: C408 - reads as a record of test defaults
            path="app.py",
            line=5,
            title="shell injection",
            severity=Severity.HIGH,
            evidence='os.system("echo " + name)',
            source=SOURCE_SCANNER,
        )
        defaults.update(kwargs)
        return Finding(**defaults)

    def test_a_file_outside_the_bundle_is_read_through_the_boundary(self):
        finding = self.scanner_finding(path="other.py", line=2, evidence="os.system(cmd)")
        kept, rejected = apply_anchoring([finding], self.bundle, self.boundary)
        self.assertEqual(rejected, [])
        self.assertEqual(len(kept), 1)

    def test_a_file_that_is_not_there_at_all_is_still_rejected(self):
        finding = self.scanner_finding(path="absent.py")
        kept, rejected = apply_anchoring([finding], self.bundle, self.boundary)
        self.assertEqual(kept, [])
        self.assertEqual(len(rejected), 1)

    def test_a_scanner_finding_is_relocated_when_the_file_moved(self):
        """A scanner quotes the line it matched, so a distance is the file's."""
        moved = "\n".join(["# line {0}".format(n) for n in range(40)]) + "\n" + SOURCE
        self.repo.write("app.py", moved)
        finding = self.scanner_finding(line=5)
        kept, rejected = apply_anchoring([finding], self.bundle, self.boundary)
        self.assertEqual(rejected, [])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].line, 45)
        self.assertIn("moved during the run", kept[0].verification_note)

    def test_a_model_finding_in_the_same_position_is_still_rejected(self):
        moved = "\n".join(["# line {0}".format(n) for n in range(40)]) + "\n" + SOURCE
        self.repo.write("app.py", moved)
        finding = self.scanner_finding(line=5, source=SOURCE_MODEL)
        kept, rejected = apply_anchoring([finding], self.bundle, self.boundary)
        self.assertEqual(kept, [])
        self.assertEqual(len(rejected), 1)
