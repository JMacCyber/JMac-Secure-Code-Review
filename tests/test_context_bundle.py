"""Review bundles: what one review pass is allowed to see.

A bundle is built under a hard file and byte budget, and everything the
budget kept out is written down in the bundle itself. These tests are mostly
about that second part. A review that silently saw less than it should is
the failure worth testing for, because nothing downstream can tell.

Files are real, in a throwaway repository, read through the real boundary.
Two stand-in boundaries cover the refusal and the unreadable-file paths,
which cannot be produced reliably with a real file on every platform.
"""

from __future__ import annotations

import unittest

from jscr.boundary.fs import RepositoryBoundary
from jscr.context.bundle import (
    ROLE_CHANGED,
    ROLE_RELATED,
    Bundle,
    BundleFile,
    build_bundle,
    language_of,
)
from jscr.errors import BoundaryViolation
from jscr.vcs.diff import FileDiff

from .support import RepoTestCase


def diff_for(path, status="modified", is_binary=False):
    return FileDiff(path=path, status=status, is_binary=is_binary)


class _RefusingBoundary(object):
    """A boundary that refuses every read."""

    root = "/nowhere"

    def read_text(self, path, encoding="utf-8"):
        raise BoundaryViolation("fs.read", "{0} is outside the repository".format(path))

    def is_truncated(self, path):
        return False

    def walk(self):
        return iter(())


class _UnreadableBoundary(_RefusingBoundary):
    """A boundary where the file is inside the repository but will not open."""

    def read_text(self, path, encoding="utf-8"):
        raise OSError(13, "Permission denied")


class BundleCase(RepoTestCase):
    def boundary(self):
        return RepositoryBoundary(root=self.repo.root)

    def build(self, diffs, boundary=None, **kwargs):
        settings = {"expand_imports": False, "expand_tests": False, "expand_schemas": False}
        settings.update(kwargs)
        return build_bundle(boundary or self.boundary(), diffs, target="HEAD", **settings)


class WhatGoesIn(BundleCase):
    def test_a_changed_file_is_read_into_the_bundle(self):
        self.repo.write("app.py", "x = 1\n")
        bundle = self.build([diff_for("app.py")])
        self.assertEqual([f.path for f in bundle.changed_files], ["app.py"])

    def test_the_content_is_the_file_on_disk(self):
        self.repo.write("app.py", "x = 1\n")
        bundle = self.build([diff_for("app.py")])
        # Windows stores the newline it stores. The text is what is tested.
        content = bundle.changed_files[0].content.replace("\r\n", "\n")
        self.assertEqual(content, "x = 1\n")

    def test_the_reason_names_what_is_under_review(self):
        self.repo.write("app.py", "x = 1\n")
        bundle = self.build([diff_for("app.py")])
        self.assertEqual(bundle.changed_files[0].reason, "changed by HEAD")

    def test_the_diff_travels_with_the_file(self):
        self.repo.write("app.py", "x = 1\n")
        diff = diff_for("app.py")
        bundle = self.build([diff])
        self.assertIs(bundle.changed_files[0].diff, diff)

    def test_every_diff_is_kept_even_when_its_content_is_not(self):
        bundle = self.build([diff_for("gone.py", status="deleted")])
        self.assertEqual([d.path for d in bundle.diffs], ["gone.py"])


class WhatIsLeftOutAndSaidSo(BundleCase):
    def test_a_binary_file_is_omitted_with_the_reason(self):
        bundle = self.build([diff_for("logo.png", is_binary=True)])
        self.assertEqual(bundle.omitted, [{"path": "logo.png", "reason": "binary file"}])

    def test_a_binary_file_is_not_read(self):
        bundle = self.build([diff_for("logo.png", is_binary=True)])
        self.assertEqual(bundle.files, [])

    def test_a_deleted_file_is_omitted_with_the_reason(self):
        bundle = self.build([diff_for("gone.py", status="deleted")])
        self.assertEqual(bundle.omitted[0]["reason"], "file was deleted")

    def test_a_refused_read_is_recorded_as_a_refusal_not_an_omission(self):
        # The two lists are different questions: one is a budget, the
        # other is the boundary saying no.
        bundle = self.build([diff_for("../outside.py")], boundary=_RefusingBoundary())
        self.assertEqual(bundle.omitted, [])
        self.assertEqual(bundle.refusals[0]["path"], "../outside.py")

    def test_the_refusal_carries_the_boundarys_own_reason(self):
        bundle = self.build([diff_for("../outside.py")], boundary=_RefusingBoundary())
        self.assertIn("outside the repository", bundle.refusals[0]["reason"])

    def test_a_file_that_will_not_open_is_omitted_with_the_system_error(self):
        bundle = self.build([diff_for("locked.py")], boundary=_UnreadableBoundary())
        self.assertIn("Permission denied", bundle.omitted[0]["reason"])

    def test_a_file_that_will_not_open_is_not_a_refusal(self):
        bundle = self.build([diff_for("locked.py")], boundary=_UnreadableBoundary())
        self.assertEqual(bundle.refusals, [])


class TheBudgetOnChangedFiles(BundleCase):
    def write_files(self, count, content="x = 1\n"):
        names = []
        for number in range(count):
            name = "file{0}.py".format(number)
            self.repo.write(name, content)
            names.append(name)
        return names

    def test_the_file_budget_stops_the_content_not_the_diff(self):
        names = self.write_files(4)
        bundle = self.build([diff_for(n) for n in names], max_files=2)
        self.assertEqual(len(bundle.changed_files), 2)
        self.assertEqual(len(bundle.diffs), 4)

    def test_the_file_budget_says_why_in_the_bundle(self):
        names = self.write_files(3)
        bundle = self.build([diff_for(n) for n in names], max_files=1)
        self.assertIn("context.max_files", bundle.omitted[0]["reason"])

    def test_an_omitted_changed_file_is_told_its_hunks_are_still_there(self):
        names = self.write_files(2)
        bundle = self.build([diff_for(n) for n in names], max_files=1)
        self.assertIn("the diff still", bundle.omitted[0]["reason"])

    def test_the_byte_budget_stops_the_next_file(self):
        names = self.write_files(3, content="y" * 100)
        bundle = self.build([diff_for(n) for n in names], max_total_bytes=150)
        self.assertEqual(len(bundle.changed_files), 1)

    def test_the_first_changed_file_is_always_kept_however_large(self):
        # Otherwise a single oversized file produces a review of nothing.
        # The provider's own limit is what reports it instead.
        self.repo.write("huge.py", "z" * 5000)
        bundle = self.build([diff_for("huge.py")], max_total_bytes=10)
        self.assertEqual([f.path for f in bundle.changed_files], ["huge.py"])

    def test_the_first_file_is_kept_even_when_the_file_budget_is_zero(self):
        self.repo.write("app.py", "x = 1\n")
        bundle = self.build([diff_for("app.py")], max_files=0)
        self.assertEqual(len(bundle.changed_files), 1)


class RelatedContext(BundleCase):
    def setUpRelated(self):
        self.repo.write("app.py", "x = 1\n")
        self.repo.write("test_app.py", "import app\n")
        return [diff_for("app.py")]

    def test_a_related_file_is_added_when_the_budget_allows(self):
        diffs = self.setUpRelated()
        bundle = build_bundle(self.boundary(), diffs, target="HEAD", expand_tests=True)
        self.assertEqual([f.path for f in bundle.related_files], ["test_app.py"])

    def test_a_related_file_says_why_it_is_here(self):
        diffs = self.setUpRelated()
        bundle = build_bundle(self.boundary(), diffs, target="HEAD", expand_tests=True)
        self.assertEqual(bundle.related_files[0].reason, "related to a changed file")

    def test_related_context_is_dropped_first_when_the_file_budget_is_full(self):
        diffs = self.setUpRelated()
        bundle = build_bundle(self.boundary(), diffs, target="HEAD", expand_tests=True, max_files=1)
        self.assertEqual(bundle.related_files, [])
        self.assertEqual(len(bundle.changed_files), 1)

    def test_the_dropped_related_file_says_which_budget_stopped_it(self):
        diffs = self.setUpRelated()
        bundle = build_bundle(self.boundary(), diffs, target="HEAD", expand_tests=True, max_files=1)
        self.assertEqual(bundle.omitted[0]["reason"], "context.max_files budget reached")

    def test_a_related_file_over_the_byte_budget_is_omitted_with_its_own_reason(self):
        self.repo.write("app.py", "x = 1\n")
        self.repo.write("test_app.py", "q" * 4000)
        bundle = build_bundle(
            self.boundary(),
            [diff_for("app.py")],
            target="HEAD",
            expand_tests=True,
            max_total_bytes=100,
        )
        self.assertEqual(bundle.related_files, [])
        self.assertEqual(bundle.omitted[0]["reason"], "context.max_total_bytes budget reached")

    def test_a_refused_related_file_is_recorded_as_a_refusal(self):
        self.repo.write("app.py", "x = 1\n")
        self.repo.write("test_app.py", "import app\n")
        boundary = _RefusingRelatedBoundary(self.repo.root)
        bundle = build_bundle(boundary, [diff_for("app.py")], target="HEAD", expand_tests=True)
        self.assertEqual([r["path"] for r in bundle.refusals], ["test_app.py"])

    def test_a_related_file_that_will_not_open_is_passed_over_silently(self):
        # It is context, not the subject of the review, and the reviewer
        # was never told it existed.
        self.repo.write("app.py", "x = 1\n")
        self.repo.write("test_app.py", "import app\n")
        boundary = _UnreadableRelatedBoundary(self.repo.root)
        bundle = build_bundle(boundary, [diff_for("app.py")], target="HEAD", expand_tests=True)
        self.assertEqual(bundle.related_files, [])
        self.assertEqual(bundle.omitted, [])


class _RefusingRelatedBoundary(RepositoryBoundary):
    """Reads changed files, refuses everything else."""

    def read_text(self, candidate, encoding="utf-8"):
        if candidate != "app.py":
            raise BoundaryViolation("fs.read", "{0} is not permitted".format(candidate))
        return RepositoryBoundary.read_text(self, candidate, encoding)


class _UnreadableRelatedBoundary(RepositoryBoundary):
    """Reads changed files; every other file fails to open."""

    def read_text(self, candidate, encoding="utf-8"):
        if candidate != "app.py":
            raise OSError(13, "Permission denied")
        return RepositoryBoundary.read_text(self, candidate, encoding)


class WhatTheBundleReportsAboutItself(unittest.TestCase):
    def bundle(self):
        bundle = Bundle(target="HEAD", root="/repo")
        bundle.add(BundleFile(path="app.py", role=ROLE_CHANGED, content="x = 1\n"))
        bundle.add(BundleFile(path="test_app.py", role=ROLE_RELATED, content="y = 2\n"))
        return bundle

    def test_total_bytes_counts_the_content_it_holds(self):
        self.assertEqual(self.bundle().total_bytes(), 12)

    def test_size_is_measured_in_bytes_not_characters(self):
        item = BundleFile(path="a.py", role=ROLE_CHANGED, content="é")
        self.assertEqual(item.size(), 2)

    def test_the_two_roles_are_reported_separately(self):
        bundle = self.bundle()
        self.assertEqual(len(bundle.changed_files), 1)
        self.assertEqual(len(bundle.related_files), 1)

    def test_the_same_bundle_twice_has_the_same_digest(self):
        self.assertEqual(self.bundle().digest(), self.bundle().digest())

    def test_different_content_changes_the_digest(self):
        other = self.bundle()
        other.files[0].content = "x = 2\n"
        self.assertNotEqual(self.bundle().digest(), other.digest())

    def test_a_different_target_changes_the_digest(self):
        other = Bundle(target="main", root="/repo")
        self.assertNotEqual(Bundle(target="HEAD", root="/repo").digest(), other.digest())

    def test_diff_for_finds_the_diff_of_a_path(self):
        bundle = self.bundle()
        bundle.diffs = [diff_for("app.py")]
        self.assertEqual(bundle.diff_for("app.py").path, "app.py")

    def test_diff_for_a_path_with_no_diff_is_none(self):
        self.assertIsNone(self.bundle().diff_for("nothing.py"))

    def test_as_dict_reports_the_omitted_and_the_refused(self):
        bundle = self.bundle()
        bundle.omit("big.py", "budget")
        bundle.refuse("outside.py", "not permitted")
        report = bundle.as_dict()
        self.assertEqual(report["omitted"], [{"path": "big.py", "reason": "budget"}])
        self.assertEqual(report["refusals"], [{"path": "outside.py", "reason": "not permitted"}])

    def test_as_dict_reports_bytes_and_a_digest(self):
        report = self.bundle().as_dict()
        self.assertEqual(report["bytes"], 12)
        self.assertEqual(len(report["digest"]), 16)

    def test_a_file_entry_carries_its_role_and_size_but_not_its_content(self):
        entry = self.bundle().as_dict()["files"][0]
        self.assertEqual(
            entry,
            {"path": "app.py", "role": "changed", "bytes": 6, "truncated": False, "reason": ""},
        )


class FencingALanguage(unittest.TestCase):
    def test_a_known_suffix_names_its_language(self):
        self.assertEqual(language_of("app/models.py"), "python")

    def test_the_suffix_is_matched_whatever_the_case(self):
        self.assertEqual(language_of("Main.PY"), "python")

    def test_an_unknown_suffix_names_nothing_rather_than_guessing(self):
        self.assertEqual(language_of("notes.xyz"), "")

    def test_a_file_with_no_suffix_names_nothing(self):
        self.assertEqual(language_of("Makefile"), "")


if __name__ == "__main__":
    unittest.main()
