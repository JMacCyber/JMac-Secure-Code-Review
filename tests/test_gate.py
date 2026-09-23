"""The commit gate: what it blocks, what it writes, and what approval creates."""

from __future__ import annotations

import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from jscr import gate
from jscr.cli import EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK, EXIT_UNUSABLE, main

from .support import RepoTestCase

VULNERABLE = 'import os\n\n\ndef go(name):\n    os.system("echo " + name)\n'


class Gate(RepoTestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def stage_a_vulnerability(self):
        self.repo.write("app.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("app.py", VULNERABLE)
        self.repo.git("add", "-A")

    def stage_something_clean(self):
        self.repo.write("notes.md", "# notes\n")
        self.repo.commit("base")
        self.repo.write("notes.md", "# notes\n\nA second line.\n")
        self.repo.git("add", "-A")


class Blocking(Gate):
    def test_any_finding_blocks_the_commit(self):
        """The gate stops at the first finding of any severity, not just High."""
        self.stage_a_vulnerability()
        code, out, _err = self.run_cli("gate", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("finding(s)", out)

    def test_a_clean_change_passes_without_claiming_safety(self):
        self.stage_something_clean()
        code, out, _err = self.run_cli("gate", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Nothing found", out)
        self.assertIn("not proof", out)

    def test_it_refuses_outside_a_repository(self):
        code, _out, err = self.run_cli("gate", "--repo", os.path.dirname(self.repo.root))
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("not a git repository", err)


class TheFastPass(Gate):
    def test_the_fast_pass_calls_no_model_even_when_configured_to(self):
        """A repository that is set up for the model must still commit in seconds."""
        self.stage_a_vulnerability()
        code, out, _err = self.run_cli(
            "gate",
            "--repo",
            self.repo.root,
            "--set",
            'provider.name="claude_cli"',
            "--set",
            "provider.allow_cli=true",
            "--set",
            'egress.allow_hosts=["api.example.invalid"]',
            "--set",
            "egress.enabled=true",
        )
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("fast pass", out)
        with open(self._written_report(), encoding="utf-8") as handle:
            report = handle.read()
        self.assertIn("No AI review ran", report)

    def test_the_fast_pass_offers_the_deeper_dive(self):
        self.stage_a_vulnerability()
        _code, out, _err = self.run_cli("gate", "--repo", self.repo.root)
        self.assertIn("jscr gate --deep", out)
        self.assertIn("jscr gate --approve", out)
        self.assertIn("git commit --no-verify", out)

    def _written_report(self):
        directory = os.path.join(self.repo.root, gate.REPORT_DIR)
        names = sorted(n for n in os.listdir(directory) if n.startswith("gate-"))
        self.assertEqual(len(names), 1)
        return os.path.join(directory, names[0])

    def test_the_report_lands_where_the_gate_says_it_did(self):
        self.stage_a_vulnerability()
        _code, out, _err = self.run_cli("gate", "--repo", self.repo.root)
        path = self._written_report()
        self.assertIn(path, out)
        with open(path, encoding="utf-8") as handle:
            self.assertTrue(handle.read().startswith("<!doctype html>"))

    def test_the_report_carries_the_prompt_for_the_fix(self):
        self.stage_a_vulnerability()
        self.run_cli("gate", "--repo", self.repo.root)
        with open(self._written_report(), encoding="utf-8") as handle:
            report = handle.read()
        self.assertIn("Hand This To Your AI", report)
        self.assertIn("1. Save a major save marker.", report)


class AnIncompleteRun(Gate):
    def test_a_run_that_did_not_complete_is_not_a_pass(self):
        """A gate that reports 'the model was unreachable' as clean is worse than none."""
        self.stage_a_vulnerability()
        code, out, _err = self.run_cli(
            "gate",
            "--repo",
            self.repo.root,
            "--deep",
            "--set",
            "provider.name=anthropic",
        )
        self.assertEqual(code, EXIT_INCOMPLETE)
        self.assertIn("did not complete", out)
        self.assertIn("deep pass", out)


class Approval(Gate):
    def test_approval_saves_the_version_and_branches(self):
        self.stage_a_vulnerability()
        code, out, _err = self.run_cli(
            "gate", "--repo", self.repo.root, "--approve", "--mark", "testmark"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("jscr-marker-testmark", self.repo.git("tag", "--list"))
        self.assertEqual(
            self.repo.git("rev-parse", "--abbrev-ref", "HEAD").strip(), "jscr-fix-testmark"
        )
        self.assertIn("Version saved", out)

    def test_approval_commits_nothing_and_keeps_the_change_staged(self):
        """Approval is a save point, not a commit. The person still approves the commit."""
        self.stage_a_vulnerability()
        before = self.repo.git("rev-parse", "HEAD").strip()
        self.run_cli("gate", "--repo", self.repo.root, "--approve", "--mark", "m2")
        self.assertEqual(self.repo.git("rev-parse", "HEAD").strip(), before)
        self.assertIn("app.py", self.repo.git("diff", "--cached", "--name-only"))

    def test_the_marker_holds_the_tree_as_it_was(self):
        """The marker must restore the staged work, or it is not a way back."""
        self.stage_a_vulnerability()
        self.run_cli("gate", "--repo", self.repo.root, "--approve", "--mark", "m3")
        saved = self.repo.git("show", "jscr-marker-m3:app.py")
        self.assertIn("os.system", saved)


class Names(unittest.TestCase):
    def test_a_marker_and_its_branch_share_one_stamp(self):
        mark = gate.stamp()
        self.assertTrue(gate.marker_tag(mark).endswith(mark))
        self.assertTrue(gate.fix_branch(mark).endswith(mark))

    def test_the_way_back_matches_what_the_marker_holds(self):
        """A stash-shaped marker is applied, a plain commit is checked out."""
        stashed = "\n".join(gate.approval_note("t", "abc123def456", "b", True))
        plain = "\n".join(gate.approval_note("t", "abc123def456", "b", False))
        self.assertIn("git stash apply t", stashed)
        self.assertNotIn("git checkout t", stashed)
        self.assertIn("git checkout t", plain)
        self.assertNotIn("git stash apply t", plain)

    def test_the_count_line_names_every_severity_present(self):
        class Result(object):
            findings = [1, 2, 3]

            def counts(self):
                return {"High": 1, "Low": 2}

        line = gate.counts_line(Result())
        self.assertIn("3 finding(s)", line)
        self.assertIn("1 High", line)
        self.assertIn("2 Low", line)
        self.assertNotIn("Critical", line)


if __name__ == "__main__":
    unittest.main()
