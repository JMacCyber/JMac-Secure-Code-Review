"""Reports must not imply more assurance than the run actually produced."""

from __future__ import annotations

import json
import unittest

from jscr.report import FORMATS, render_html, render_json, render_sarif, render_text
from jscr.review.engine import ReviewEngine
from jscr.review.findings import Finding
from jscr.vcs.git import GitRange

from .support import RepoTestCase, config

VULNERABLE = 'import os\n\n\ndef go(name):\n    os.system("echo " + name)\n'


class Reports(RepoTestCase):
    def setUp(self):
        super().setUp()
        self.repo.write("app.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("app.py", VULNERABLE)
        self.repo.git("add", "-A")
        self.result = ReviewEngine(config(), self.repo.root).review(GitRange(staged=True))

    # -- text -----------------------------------------------------------
    def test_text_report_says_what_did_not_run(self):
        text = render_text(self.result)
        self.assertIn("What ran", text)
        self.assertIn("AI review", text)

    def test_text_report_names_disabled_scanners_rather_than_omitting_them(self):
        text = render_text(self.result)
        self.assertIn("builtin", text)

    def test_a_clean_run_does_not_claim_the_code_is_safe(self):
        empty = ReviewEngine(config(), self.repo.root)
        result = empty.review(GitRange(base="HEAD", head="HEAD"))
        text = render_text(result)
        self.assertNotIn(
            "Result: Green - nothing found.\n",
            text.replace(
                "Result: Green - nothing found. This is not proof the change is safe.", ""
            ),
        )

    def test_status_words_are_capitalised(self):
        text = render_text(self.result)
        self.assertIn("[High]", text)
        self.assertTrue("Result: Red" in text or "Result: Amber" in text)

    def test_verbose_shows_what_was_rejected(self):
        text = render_text(self.result, verbose=True)
        self.assertIsInstance(text, str)

    # -- json -----------------------------------------------------------
    def test_json_is_valid_and_complete(self):
        data = json.loads(render_json(self.result))
        for key in ("summary", "findings", "scanners", "policy", "egress", "errors", "warnings"):
            self.assertIn(key, data)

    def test_json_includes_rejected_findings(self):
        data = json.loads(render_json(self.result))
        self.assertIn("rejected", data)

    def test_json_records_that_no_connection_was_made(self):
        data = json.loads(render_json(self.result))
        self.assertEqual(data["egress"], [])

    # -- sarif ----------------------------------------------------------
    def test_sarif_shape(self):
        data = json.loads(render_sarif(self.result))
        self.assertEqual(data["version"], "2.1.0")
        run = data["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "JMac Secure Code Review")
        self.assertTrue(run["results"])

    def test_every_sarif_result_has_a_declared_rule(self):
        data = json.loads(render_sarif(self.result))
        run = data["runs"][0]
        declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        for entry in run["results"]:
            self.assertIn(entry["ruleId"], declared)

    def test_sarif_locations_are_repository_relative(self):
        data = json.loads(render_sarif(self.result))
        for entry in data["runs"][0]["results"]:
            uri = entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertFalse(uri.startswith("/"), uri)

    def test_sarif_carries_a_stable_fingerprint(self):
        data = json.loads(render_sarif(self.result))
        for entry in data["runs"][0]["results"]:
            self.assertIn("jscr/v1", entry["partialFingerprints"])

    def test_sarif_does_not_present_rejected_findings_as_results(self):
        data = json.loads(render_sarif(self.result))
        self.assertEqual(len(data["runs"][0]["results"]), len(self.result.findings))

    # -- html -----------------------------------------------------------
    def test_html_is_one_self_contained_document(self):
        page = render_html(self.result)
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertTrue(page.rstrip().endswith("</html>"))
        # Nothing to fetch: a report that needs the network renders blank offline.
        self.assertNotIn("http://", page)
        self.assertNotIn("https://", page)
        self.assertNotIn("<link", page)

    def test_html_is_an_offered_format(self):
        self.assertIn("html", FORMATS)

    def test_html_says_what_did_not_run(self):
        page = render_html(self.result)
        self.assertIn("What Ran", page)
        self.assertIn("What This Report Does Not Cover", page)
        self.assertIn("AI Review", page)

    def test_a_clean_html_run_does_not_claim_the_code_is_safe(self):
        empty = ReviewEngine(config(), self.repo.root)
        page = render_html(empty.review(GitRange(base="HEAD", head="HEAD")))
        self.assertIn("Result: Green", page)
        self.assertIn("not proof the change is safe", page)

    def test_html_escapes_a_finding_that_carries_markup(self):
        """A repository must not be able to write script into the report about it."""
        self.result.findings.append(
            Finding(
                path="<img src=x onerror=alert(1)>",
                line=1,
                title="<script>alert(2)</script>",
                detail="<b>bold</b>",
                evidence="<script>alert(3)</script>",
            )
        )
        page = render_html(self.result)
        # The property is that no untrusted text reaches the page inside a live
        # tag. The characters may appear; an opening bracket before them may not.
        self.assertNotIn("<script>alert(", page)
        self.assertNotIn("<img", page)
        self.assertNotIn("<b>bold", page)
        self.assertIn("&lt;script&gt;alert(2)", page)

    def test_html_payload_holds_no_bracket_the_parser_could_act_on(self):
        self.result.findings.append(
            Finding(path="a.py", line=1, title="t", evidence="</script><script>alert(4)")
        )
        page = render_html(self.result)
        payload = page.split('id="jscr-data">', 1)[1].split("</script>", 1)[0]
        self.assertNotIn("<", payload)
        self.assertNotIn(">", payload)
        # Escaped, not lost: the browser reads back the characters that were scanned.
        restored = json.loads(payload)
        self.assertEqual(restored[-1]["evidence"], "</script><script>alert(4)")

    def test_html_shows_rejected_findings_separately_from_findings(self):
        self.result.rejected.append(Finding(path="ghost.py", line=9, title="Unanchored claim"))
        page = render_html(self.result)
        self.assertIn("Rejected Before Reporting (1)", page)
        rows = page.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
        self.assertNotIn("ghost.py", rows)

    def test_html_status_words_are_capitalised(self):
        page = render_html(self.result)
        self.assertNotIn("Result: green", page)
        self.assertNotIn("Result: amber", page)
        self.assertNotIn("Result: red", page)

    def test_html_verdict_is_amber_when_nothing_blocks(self):
        self.result.findings = [
            f for f in self.result.findings if f.severity not in ("Critical", "High")
        ]
        self.result.findings.append(Finding(path="a.py", line=1, title="Worth reading"))
        page = render_html(self.result)
        self.assertIn("Result: Amber", page)
        self.assertNotIn("Result: Red", page)

    def test_html_verdict_is_amber_when_a_clean_run_errored(self):
        empty = ReviewEngine(config(), self.repo.root)
        result = empty.review(GitRange(base="HEAD", head="HEAD"))
        result.errors.append("the dependency scanner crashed")
        page = render_html(result)
        self.assertIn("Result: Amber", page)
        self.assertNotIn("Result: Green", page)

    def test_html_names_the_provider_that_answered(self):
        self.result.provider = {"used": "claude_cli", "model": "claude-opus-5"}
        page = render_html(self.result)
        self.assertIn("claude_cli (claude-opus-5)", page)

    def test_html_names_a_scanner_that_did_not_run_twice(self):
        """Once in What Ran, once in what the report does not cover."""
        self.result.scanners.append({"name": "trivy", "ran": False, "error": "not installed"})
        page = render_html(self.result)
        self.assertIn("Did not run: not installed", page)
        self.assertIn("whole class of defect was never looked for: trivy", page)

    def test_html_states_redaction_and_what_policy_refused(self):
        self.result.redaction = {"applied": True, "hits": 3}
        self.result.policy = {
            "denied": [{"action": "network", "subject": "example.invalid", "reason": "not allowed"}]
        }
        self.result.errors.append("semgrep exited 2")
        page = render_html(self.result)
        self.assertIn("3 probable secret(s) removed before egress", page)
        self.assertIn("Refused By Policy", page)
        self.assertIn("semgrep exited 2", page)

    def test_html_carries_a_prompt_for_the_readers_own_ai(self):
        """The reader's next move is to ask an agent to fix this. Give it the order of work."""
        page = render_html(self.result)
        self.assertIn("Hand This To Your AI", page)
        self.assertIn("Copy The Prompt", page)
        block = page.split('id="fixprompt">', 1)[1].split("</pre>", 1)[0]
        self.assertIn("1. Save a major save marker.", block)
        self.assertIn("2. Branch, then fix.", block)
        self.assertIn("3. Test before you hand over.", block)
        self.assertIn("4. Hand to a human for QA.", block)

    def test_the_prompt_lists_every_finding_worst_first(self):
        self.result.findings.append(
            Finding(path="low.py", line=2, title="Minor thing", severity="Low")
        )
        self.result.findings.append(
            Finding(
                path="bad.py",
                line=9,
                title="Command injection",
                severity="High",
                detail="Shell call takes user input.",
                recommendation="Pass a list, never a string.",
                rule_id="py.subprocess",
                cwe="CWE-78",
            )
        )
        block = render_html(self.result).split('id="fixprompt">', 1)[1].split("</pre>", 1)[0]
        self.assertLess(block.index("[High] bad.py:9"), block.index("[Low] low.py:2"))
        self.assertIn("Fix: Pass a list, never a string.", block)
        self.assertIn("py.subprocess", block)
        self.assertIn("CWE-78", block)

    def test_the_prompt_repeats_what_the_run_did_not_cover(self):
        """An agent handed only findings will call the rest of the repository clean."""
        self.result.scanners.append({"name": "trivy", "ran": False})
        block = render_html(self.result).split('id="fixprompt">', 1)[1].split("</pre>", 1)[0]
        self.assertIn("does not cover", block)
        self.assertIn("trivy", block)

    def test_the_prompt_says_there_is_nothing_to_fix_without_claiming_safety(self):
        self.result.findings = []
        block = render_html(self.result).split('id="fixprompt">', 1)[1].split("</pre>", 1)[0]
        self.assertIn("Nothing to fix", block)
        self.assertIn("not proof", block)

    def test_the_prompt_cannot_carry_markup_out_of_its_block(self):
        self.result.findings.append(
            Finding(path="a.py", line=1, title="</pre><script>alert(5)</script>")
        )
        page = render_html(self.result)
        block = page.split('id="fixprompt">', 1)[1].split("</pre>", 1)[0]
        self.assertNotIn("<", block)
        self.assertIn("&lt;/pre&gt;", block)


if __name__ == "__main__":
    unittest.main()
