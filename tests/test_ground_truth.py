"""The scanners are measured against defects whose answers are known.

Coverage counts lines that ran. These tests count defects that were named.
A rule can be fully covered by a test that asserts nothing about the code it
was written for, and a miss here is the failure that matters: a scan that
finishes, reports nothing, and exits Passed over a real defect.
"""

from __future__ import annotations

import unittest

from tools.ground_truth import measure

from jscr.redaction.secrets import Redactor
from tests.ground_truth import CASES, expectations


class WhatTheScannersFindInTheCorpus(unittest.TestCase):
    """One run of every internal scanner over the planted corpus."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.result = measure()

    def test_every_planted_defect_is_reported(self):
        misses = [
            "{0} {1}:{2} {3}".format(row["case"], row["path"], row["line"], row["rule"])
            for row in self.result["misses"]
        ]
        self.assertEqual(misses, [], "planted defects nothing reported")

    def test_no_decoy_is_reported(self):
        self.assertEqual(self.result["false_positives"], [])

    def test_the_corpus_is_not_empty_and_carries_decoys(self):
        # A corpus with no decoys measures recall and nothing else, and a
        # rule that reports everything would score perfectly on it.
        self.assertGreaterEqual(self.result["planted"], 50)
        self.assertGreaterEqual(self.result["decoys"], 5)

    def test_every_internal_scanner_ran(self):
        for scanner in self.result["scanners"]:
            if scanner["name"] in ("semgrep", "gitleaks", "trivy"):
                continue
            self.assertTrue(scanner["ran"], scanner)


class WhatTheCorpusItselfContains(unittest.TestCase):
    """The corpus is written as fragments, and this is what enforces it."""

    def test_no_case_is_missing_the_line_it_names(self):
        for row in expectations():
            self.assertGreater(row["line"], 0, row)

    def test_no_case_has_an_empty_reason(self):
        for case in CASES:
            self.assertTrue(case.why.strip(), case.case_id)

    def test_the_corpus_source_holds_no_credential_shaped_literal(self):
        # The planted secrets are assembled at run time. If one were ever
        # written as a literal, this repository would be carrying it.
        with open("tests/ground_truth.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertEqual(Redactor(enabled=True, block_on_secret=False).scan(source), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
