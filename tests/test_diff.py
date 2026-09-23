"""Unified diff parsing.

A finding is only useful if it points at the right line, so the parser is
tested against output git actually produced rather than against a diff
written by hand to suit the parser.
"""

from __future__ import annotations

import unittest

from jscr.vcs.diff import STATUS_RENAMED, parse_unified_diff, summarise

from .support import RepoTestCase


class RealGitOutput(RepoTestCase):
    def diff(self):
        self.repo.git("add", "-A")
        return parse_unified_diff(self.repo.git("diff", "--cached", "--no-color", "-U3"))

    def test_modified_file_line_numbers(self):
        self.repo.write("app.py", "a = 1\nb = 2\nc = 3\n")
        self.repo.commit("base")
        self.repo.write("app.py", "a = 1\nb = 99\nc = 3\n")
        diffs = self.diff()
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0].path, "app.py")
        self.assertEqual(diffs[0].positions_added(), [2])
        self.assertEqual(diffs[0].line_text(2), "b = 99")

    def test_added_file(self):
        self.repo.write("a.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("new.py", "y = 2\n")
        diffs = self.diff()
        self.assertEqual(diffs[0].path, "new.py")
        self.assertTrue(diffs[0].is_new)
        self.assertEqual(diffs[0].positions_added(), [1])

    def test_deleted_file(self):
        self.repo.write("gone.py", "x = 1\n")
        self.repo.commit("base")
        import os

        os.unlink(os.path.join(self.repo.root, "gone.py"))
        diffs = self.diff()
        self.assertTrue(diffs[0].is_deleted)
        self.assertEqual(diffs[0].positions_added(), [])

    def test_binary_file(self):
        self.repo.write("a.py", "x = 1\n")
        self.repo.commit("base")
        with open("{0}/logo.png".format(self.repo.root), "wb") as handle:
            handle.write(b"\x89PNG\r\n\x1a\n" + bytes(range(256)))
        diffs = self.diff()
        binary = [d for d in diffs if d.path == "logo.png"][0]
        self.assertTrue(binary.is_binary)
        self.assertEqual(binary.positions_added(), [])

    def test_path_with_a_space(self):
        self.repo.write("a.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("two words.py", "y = 2\n")
        diffs = self.diff()
        self.assertIn("two words.py", [d.path for d in diffs])

    def test_several_hunks_in_one_file(self):
        lines = ["line{0} = {0}\n".format(n) for n in range(1, 41)]
        self.repo.write("big.py", "".join(lines))
        self.repo.commit("base")
        lines[2] = "line3 = 300\n"
        lines[35] = "line36 = 3600\n"
        self.repo.write("big.py", "".join(lines))
        diffs = self.diff()
        self.assertEqual(len(diffs[0].hunks), 2)
        self.assertEqual(diffs[0].positions_added(), [3, 36])

    def test_context_lines_count_as_touched_but_not_added(self):
        """Code that was already there can become wrong because of a line next to it."""
        self.repo.write("app.py", "a = 1\nb = 2\nc = 3\n")
        self.repo.commit("base")
        self.repo.write("app.py", "a = 1\nb = 99\nc = 3\n")
        diffs = self.diff()
        self.assertEqual(diffs[0].positions_added(), [2])
        self.assertEqual(sorted(diffs[0].positions_touched()), [1, 2, 3])

    def test_summary_counts(self):
        self.repo.write("a.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("a.py", "x = 1\ny = 2\n")
        self.repo.write("b.py", "z = 3\n")
        totals = summarise(self.diff())
        self.assertEqual(totals["files"], 2)
        self.assertEqual(totals["added_lines"], 2)
        self.assertEqual(totals["removed_lines"], 0)


class Robustness(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(parse_unified_diff(""), [])

    def test_text_that_is_not_a_diff(self):
        self.assertEqual(parse_unified_diff("hello\nworld\n"), [])

    def test_truncated_hunk_header_does_not_raise(self):
        text = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ bad header @@\n+x\n"
        parse_unified_diff(text)


class RenamesAndOddNames(RepoTestCase):
    def diff(self):
        self.repo.git("add", "-A")
        return parse_unified_diff(self.repo.git("diff", "--cached", "--no-color", "-U3"))

    def test_a_rename_keeps_both_names(self):
        self.repo.write("old.py", "a = 1\nb = 2\n")
        self.repo.commit("base")
        self.repo.git("mv", "old.py", "new.py")
        diff = self.diff()[0]
        self.assertEqual(diff.path, "new.py")
        self.assertEqual(diff.old_path, "old.py")

    def test_a_rename_is_reported_as_a_rename(self):
        self.repo.write("old.py", "a = 1\nb = 2\n")
        self.repo.commit("base")
        self.repo.git("mv", "old.py", "new.py")
        diff = self.diff()[0]
        self.assertEqual(diff.status, STATUS_RENAMED)
        self.assertTrue(diff.is_renamed)

    def test_a_pure_rename_adds_no_lines_to_review(self):
        self.repo.write("old.py", "a = 1\nb = 2\n")
        self.repo.commit("base")
        self.repo.git("mv", "old.py", "new.py")
        self.assertEqual(self.diff()[0].positions_added(), [])

    def test_a_name_git_quotes_is_read_back_as_the_real_name(self):
        # Git escapes bytes outside ASCII in the header. The path a finding
        # names must be the path on disk, not the escaped spelling.
        self.repo.write("a.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("caf\u00e9.py", "y = 2\n")
        paths = [d.path for d in self.diff()]
        self.assertIn("caf\u00e9.py", paths)

    def test_a_quoted_name_still_has_its_lines(self):
        self.repo.write("a.py", "x = 1\n")
        self.repo.commit("base")
        self.repo.write("caf\u00e9.py", "y = 2\n")
        diff = [d for d in self.diff() if d.path == "caf\u00e9.py"][0]
        self.assertEqual(diff.positions_added(), [1])

    def test_a_file_with_no_trailing_newline_parses(self):
        self.repo.write("a.py", "x = 1")
        self.repo.commit("base")
        self.repo.write("a.py", "x = 2")
        diff = self.diff()[0]
        self.assertEqual(diff.line_text(1), "x = 2")

    def test_the_no_newline_marker_is_not_counted_as_a_line(self):
        self.repo.write("a.py", "x = 1")
        self.repo.commit("base")
        self.repo.write("a.py", "x = 2")
        diff = self.diff()[0]
        self.assertEqual(diff.positions_added(), [1])
        self.assertEqual(diff.removed_line_count(), 1)


class WhatALineReportsAboutItself(unittest.TestCase):
    def line(self):
        text = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,1 @@\n-a = 1\n+a = 2\n"
        return parse_unified_diff(text)[0].hunks[0].lines

    def test_an_added_line_says_where_it_sits_in_the_new_file(self):
        added = [entry.as_dict() for entry in self.line() if entry.kind == "added"][0]
        self.assertEqual(added["new_line"], 1)
        self.assertEqual(added["text"], "a = 2")

    def test_an_added_line_has_no_old_position(self):
        added = [entry.as_dict() for entry in self.line() if entry.kind == "added"][0]
        self.assertIsNone(added["old_line"])

    def test_a_removed_line_has_no_new_position(self):
        removed = [entry.as_dict() for entry in self.line() if entry.kind == "removed"][0]
        self.assertEqual(removed["old_line"], 1)
        self.assertIsNone(removed["new_line"])


class AskingForALineTheDiffNeverTouched(unittest.TestCase):
    def test_an_untouched_line_has_no_text_rather_than_a_guess(self):
        text = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,1 @@\n+a = 2\n"
        self.assertIsNone(parse_unified_diff(text)[0].line_text(99))


class MalformedDiffText(unittest.TestCase):
    """Diff text is repository content, so it is untrusted input."""

    def test_a_line_that_is_not_part_of_a_hunk_ends_the_hunk(self):
        text = (
            "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
            "@@ -1,2 +1,2 @@\n+a = 2\nrubbish\n+b = 3\n"
        )
        diff = parse_unified_diff(text)[0]
        self.assertEqual(diff.positions_added(), [1])

    def test_a_header_with_no_b_prefix_still_names_a_file(self):
        text = "diff --git one.py two.py\n@@ -1,1 +1,1 @@\n+a = 2\n"
        diff = parse_unified_diff(text)[0]
        self.assertEqual(diff.path, "two.py")
        self.assertEqual(diff.old_path, "one.py")

    def test_a_header_naming_one_path_uses_it_for_both_sides(self):
        diff = parse_unified_diff("diff --git only.py\n@@ -1,1 +1,1 @@\n+a\n")[0]
        self.assertEqual(diff.path, "only.py")
        self.assertEqual(diff.old_path, "only.py")


class ANameThatIsNotUtf8(unittest.TestCase):
    """Git quotes bytes, and not every byte sequence is UTF-8."""

    def test_a_latin1_name_is_kept_as_it_was_rather_than_dropped(self):
        from jscr.vcs.diff import _unquote

        # \351 is a valid byte and a valid file name, but not valid UTF-8.
        self.assertEqual(_unquote('"caf\\351.py"'), "caf\u00e9.py")

    def test_the_parser_still_names_the_file(self):
        text = 'diff --git "a/caf\\351.py" "b/caf\\351.py"\n@@ -1,1 +1,1 @@\n+x\n'
        self.assertEqual(parse_unified_diff(text)[0].path, "caf\u00e9.py")


if __name__ == "__main__":
    unittest.main()
