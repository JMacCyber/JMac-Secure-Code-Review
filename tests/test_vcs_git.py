"""How git is invoked, and what is refused before git sees it.

git is the one external program JSCR runs by default. These tests run the
real git against a throwaway repository, because the point of the module is
what the real program does with the argument vector it is handed.
"""

from __future__ import annotations

import os
import stat
import unittest

from jscr.boundary.fs import RepositoryBoundary
from jscr.errors import GitError
from jscr.vcs.git import Git, GitRange, validate_revision

from .support import RepoTestCase


class GitCase(RepoTestCase):
    def git(self, **kwargs) -> Git:
        return Git(RepositoryBoundary(root=self.repo.root), **kwargs)

    def commit_a_file(self, name="app.py", content="x = 1\n", message="first"):
        self.repo.write(name, content)
        self.repo.commit(message)


class DescribingWhatIsUnderReview(unittest.TestCase):
    def test_the_working_tree_says_so(self):
        self.assertEqual(GitRange(worktree=True).describe(), "working tree")

    def test_staged_changes_say_so(self):
        self.assertEqual(GitRange(staged=True).describe(), "staged changes")

    def test_a_comparison_is_written_as_a_range(self):
        self.assertEqual(GitRange(base="main", head="topic").describe(), "main..topic")

    def test_one_commit_is_named_as_a_commit(self):
        self.assertEqual(GitRange(head="abc123").describe(), "commit abc123")

    def test_nothing_at_all_falls_back_to_the_working_tree(self):
        self.assertEqual(GitRange().describe(), "working tree")

    def test_the_working_tree_wins_over_staged(self):
        self.assertEqual(GitRange(staged=True, worktree=True).describe(), "working tree")


class ChoosingWhatToReview(unittest.TestCase):
    def test_a_commit_is_compared_against_its_parent(self):
        target = GitRange.from_args(commit="abc123")
        self.assertEqual((target.base, target.head), ("abc123^", "abc123"))

    def test_a_base_with_no_head_is_compared_against_head(self):
        target = GitRange.from_args(base="main")
        self.assertEqual((target.base, target.head), ("main", "HEAD"))

    def test_a_base_and_a_head_are_taken_as_given(self):
        target = GitRange.from_args(base="main", head="topic")
        self.assertEqual((target.base, target.head), ("main", "topic"))

    def test_staged_is_carried_through(self):
        self.assertTrue(GitRange.from_args(staged=True).staged)

    def test_the_working_tree_is_carried_through(self):
        self.assertTrue(GitRange.from_args(worktree=True).worktree)

    def test_no_argument_at_all_reviews_the_working_tree(self):
        self.assertTrue(GitRange.from_args().worktree)

    def test_a_commit_wins_over_a_base(self):
        self.assertEqual(GitRange.from_args(commit="abc123", base="main").base, "abc123^")


class ReviewingEveryFile(unittest.TestCase):
    def test_every_file_defaults_to_head(self):
        target = GitRange.from_args(every_file=True)
        self.assertTrue(target.every_file)
        self.assertEqual(target.head, "HEAD")
        self.assertIsNone(target.base)

    def test_every_file_keeps_a_head_it_was_given(self):
        self.assertEqual(GitRange.from_args(every_file=True, head="v1").head, "v1")

    def test_every_file_says_so(self):
        self.assertEqual(
            GitRange.from_args(every_file=True).describe(), "every tracked file at HEAD"
        )


class RefusingARevision(unittest.TestCase):
    def test_an_option_is_not_a_revision(self):
        with self.assertRaises(GitError):
            validate_revision("--upload-pack=/bin/sh")

    def test_an_empty_string_is_not_a_revision(self):
        with self.assertRaises(GitError):
            validate_revision("")

    def test_a_shell_metacharacter_is_not_a_revision(self):
        with self.assertRaises(GitError):
            validate_revision("HEAD; id > /tmp/proof")

    def test_a_command_substitution_is_not_a_revision(self):
        with self.assertRaises(GitError):
            validate_revision("$(id)")

    def test_a_space_is_not_a_revision(self):
        with self.assertRaises(GitError):
            validate_revision("HEAD HEAD")

    def test_a_string_longer_than_git_would_ever_produce_is_refused(self):
        with self.assertRaises(GitError):
            validate_revision("a" * 256)

    def test_the_shapes_git_actually_produces_are_accepted(self):
        for revision in ("HEAD", "HEAD^", "HEAD~2", "main", "origin/main", "abc123", "v1.0.0"):
            self.assertIsNone(validate_revision(revision))


class RunningGit(GitCase):
    def test_the_version_is_reported(self):
        self.assertIn("git version", self.git().version())

    def test_a_missing_binary_is_named_in_the_error(self):
        with self.assertRaises(GitError) as raised:
            self.git(binary="no-such-git-jscr").version()
        self.assertIn("no-such-git-jscr", str(raised.exception))

    @unittest.skipIf(os.name == "nt", "a /bin/sh stand-in is not runnable on Windows")
    def test_a_run_that_takes_too_long_is_stopped_and_reported(self):
        slow = os.path.join(self.repo.root, "slow-git")
        with open(slow, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nsleep 5\n")
        os.chmod(slow, os.stat(slow).st_mode | stat.S_IXUSR)
        with self.assertRaises(GitError) as raised:
            self.git(binary=slow, timeout=1).version()
        self.assertIn("timed out after 1s", str(raised.exception))

    def test_a_failing_subcommand_carries_what_git_said(self):
        with self.assertRaises(GitError) as raised:
            self.git().run(["cat-file", "-p", "0" * 40])
        self.assertIn("cat-file", str(raised.exception))

    def test_a_failure_with_no_message_still_reports_the_failure(self):
        # rev-parse --quiet fails silently, so there is nothing to quote.
        self.commit_a_file()
        with self.assertRaises(GitError) as raised:
            self.git().resolve("deadbee")
        self.assertIn("no output", str(raised.exception))

    def test_a_repository_is_recognised(self):
        self.assertTrue(self.git().is_repository())

    def test_a_git_that_cannot_run_is_not_reported_as_a_repository(self):
        self.assertFalse(self.git(binary="no-such-git-jscr").is_repository())


class TheEnvironmentGitGets(GitCase):
    def test_an_inherited_git_variable_cannot_redirect_the_repository(self):
        self.commit_a_file()
        os.environ["GIT_DIR"] = os.path.join(self.repo.root, "not-a-git-dir")
        self.addCleanup(os.environ.pop, "GIT_DIR", None)
        # If GIT_DIR were passed through, this would fail: the directory
        # does not exist.
        self.assertTrue(self.git().is_repository())

    def test_the_named_variables_are_set(self):
        environment = self.git()._environment()
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_ATTR_NOSYSTEM"], "1")

    def test_git_is_always_given_a_path(self):
        self.assertTrue(self.git()._environment()["PATH"])

    def test_a_variable_this_process_holds_does_not_reach_git(self):
        os.environ["JSCR_TEST_TOKEN"] = "must-not-travel"
        self.addCleanup(os.environ.pop, "JSCR_TEST_TOKEN", None)
        self.assertNotIn("JSCR_TEST_TOKEN", self.git()._environment())


class AskingAboutHistory(GitCase):
    def test_a_revision_resolves_to_a_full_object_id(self):
        self.commit_a_file()
        self.assertEqual(len(self.git().resolve("HEAD")), 40)

    def test_resolving_refuses_an_option_before_git_sees_it(self):
        with self.assertRaises(GitError):
            self.git().resolve("--output=/tmp/x")

    def test_the_head_commit_is_the_resolved_head(self):
        self.commit_a_file()
        client = self.git()
        self.assertEqual(client.head_commit(), client.resolve("HEAD"))

    def test_the_current_branch_is_named(self):
        self.commit_a_file()
        branch = self.repo.git("branch", "--show-current").strip()
        self.assertEqual(self.git().current_branch(), branch)

    def test_a_commit_message_is_read_back(self):
        self.commit_a_file(message="a message worth reading")
        self.assertEqual(self.git().commit_message("HEAD"), "a message worth reading")

    def test_a_commit_message_refuses_an_option(self):
        with self.assertRaises(GitError):
            self.git().commit_message("--all")

    def test_the_merge_base_of_two_branches_is_their_common_commit(self):
        self.commit_a_file()
        first = self.git().head_commit()
        self.repo.git("checkout", "-q", "-b", "topic")
        self.commit_a_file(name="b.py", message="second")
        self.assertEqual(self.git().merge_base(first, "HEAD"), first)

    def test_the_merge_base_refuses_an_option_in_either_place(self):
        with self.assertRaises(GitError):
            self.git().merge_base("--all", "HEAD")
        with self.assertRaises(GitError):
            self.git().merge_base("HEAD", "--all")

    def test_a_file_is_read_as_it_stood_at_a_revision(self):
        self.commit_a_file(content="first version\n")
        self.repo.write("app.py", "second version\n")
        self.repo.commit("second")
        # Windows checks the file out with CRLF, so compare the text, not
        # the line ending the platform chose.
        content = self.git().file_at("HEAD^", "app.py").replace("\r\n", "\n")
        self.assertEqual(content, "first version\n")

    def test_reading_a_file_refuses_an_option_as_the_revision(self):
        self.commit_a_file()
        with self.assertRaises(GitError):
            self.git().file_at("--all", "app.py")


class TakingTheDiff(GitCase):
    def test_the_working_tree_is_compared_against_head(self):
        self.commit_a_file(content="one\n")
        self.repo.write("app.py", "two\n")
        diff = self.git().diff(GitRange(worktree=True))
        self.assertIn("-one", diff)
        self.assertIn("+two", diff)

    def test_staged_changes_are_compared_against_head(self):
        self.commit_a_file(content="one\n")
        self.repo.write("app.py", "two\n")
        self.repo.git("add", "-A")
        self.assertIn("+two", self.git().diff(GitRange(staged=True)))

    def test_staged_ignores_a_change_that_is_not_staged_yet(self):
        self.commit_a_file(content="one\n")
        self.repo.write("app.py", "two\n")
        self.assertEqual(self.git().diff(GitRange(staged=True)), "")

    def test_a_range_is_compared_with_two_dots(self):
        self.commit_a_file(content="one\n")
        self.repo.write("app.py", "two\n")
        self.repo.commit("second")
        self.assertIn("+two", self.git().diff(GitRange(base="HEAD^", head="HEAD")))

    def test_a_range_with_no_base_falls_back_to_the_previous_commit(self):
        self.commit_a_file(content="one\n")
        self.repo.write("app.py", "two\n")
        self.repo.commit("second")
        self.assertIn("+two", self.git().diff(GitRange(head="HEAD")))

    def test_a_range_refuses_an_option_as_a_revision(self):
        with self.assertRaises(GitError):
            self.git().diff(GitRange(base="--output=/tmp/x", head="HEAD"))

    def test_the_context_line_count_is_passed_through(self):
        self.commit_a_file(content="a\nb\nc\nd\ne\nf\ng\n")
        self.repo.write("app.py", "a\nb\nc\nd\ne\nf\nCHANGED\n")
        narrow = self.git().diff(GitRange(worktree=True), context_lines=0)
        wide = self.git().diff(GitRange(worktree=True), context_lines=3)
        self.assertLess(len(narrow), len(wide))

    def test_the_changed_paths_are_listed_relative_to_the_repository(self):
        self.commit_a_file(name="src/app.py", content="one\n")
        self.repo.write("src/app.py", "two\n")
        self.assertEqual(self.git().changed_files(GitRange(worktree=True)), ["src/app.py"])

    def test_every_file_lists_the_whole_tree_on_a_first_commit(self):
        """A repository with one commit has no parent to diff against."""
        self.repo.write("a.py", "a = 1\n")
        self.repo.write("lib/b.py", "b = 2\n")
        self.repo.commit("only")
        self.assertEqual(
            sorted(self.git().changed_files(GitRange(head="HEAD", every_file=True))),
            ["a.py", "lib/b.py"],
        )

    def test_a_root_commit_is_its_whole_tree(self):
        """--commit on a first commit has no parent; it adds every file."""
        self.repo.write("a.py", "a = 1\n")
        self.repo.write("lib/b.py", "b = 2\n")
        self.repo.commit("only")
        self.assertEqual(
            sorted(self.git().changed_files(GitRange.from_args(commit="HEAD"))),
            ["a.py", "lib/b.py"],
        )

    def test_a_root_commit_is_named_as_a_first_commit(self):
        self.commit_a_file()
        target = self.git().settle(GitRange.from_args(commit="HEAD"))
        self.assertTrue(target.first_commit)
        self.assertIsNone(target.base)
        self.assertEqual(target.describe(), "commit HEAD (first commit, so every file it adds)")
        self.assertEqual(self.git().changed_files(target), ["app.py"])

    def test_a_commit_with_a_parent_keeps_its_range(self):
        self.commit_a_file(name="a.py")
        self.commit_a_file(name="b.py")
        target = GitRange.from_args(commit="HEAD")
        self.assertIs(self.git().settle(target), target)
        self.assertEqual(target.describe(), "HEAD^..HEAD")

    def test_a_commit_with_a_parent_still_diffs_against_it(self):
        self.commit_a_file(name="a.py", content="a = 1\n")
        self.commit_a_file(name="b.py", content="b = 2\n")
        self.assertEqual(self.git().changed_files(GitRange.from_args(commit="HEAD")), ["b.py"])

    def test_a_revision_that_does_not_exist_still_fails(self):
        self.commit_a_file()
        with self.assertRaises(GitError):
            self.git().diff(GitRange.from_args(commit="no-such-branch"))

    def test_every_file_ignores_edits_that_are_not_committed(self):
        self.commit_a_file(name="app.py", content="x = 1\n")
        self.repo.write("scratch.py", "y = 2\n")
        self.assertEqual(
            self.git().changed_files(GitRange(head="HEAD", every_file=True)), ["app.py"]
        )

    def test_the_empty_tree_matches_the_object_format(self):
        self.commit_a_file()
        self.assertEqual(self.git().empty_tree(), "4b825dc642cb6eb9a060e54bf8d69288fbee4904")

    def test_nothing_changed_means_no_paths(self):
        self.commit_a_file()
        self.assertEqual(self.git().changed_files(GitRange(worktree=True)), [])
