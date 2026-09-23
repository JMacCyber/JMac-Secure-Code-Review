"""The repository boundary, attacked.

Every test here is a real technique. The boundary is the thing standing
between "review this repository" and "read anything on this machine", so it
is tested the way an attacker would probe it, not the way a happy path
would exercise it.
"""

from __future__ import annotations

import os
import unittest

from jscr.boundary.fs import RepositoryBoundary
from jscr.errors import BoundaryViolation

from ..support import RepoTestCase


class PathEscape(RepoTestCase):
    def setUp(self):
        super().setUp()
        self.repo.write("app.py", "x = 1\n")
        self.repo.write("sub/nested.py", "y = 2\n")
        self.boundary = RepositoryBoundary(self.repo.root)

    def denied(self, path):
        with self.assertRaises(BoundaryViolation, msg=path):
            self.boundary.resolve(path)

    # -- traversal ------------------------------------------------------
    def test_parent_traversal(self):
        self.denied("../../etc/passwd")

    def test_traversal_through_a_real_directory(self):
        self.denied("sub/../../../../etc/passwd")

    def test_absolute_path(self):
        self.denied("/etc/passwd")

    def test_absolute_path_inside_a_sibling_with_a_shared_prefix(self):
        """/repo-evil starts with /repo but is not inside it.

        This is the bug that a startswith() containment check ships with.
        """
        sibling = self.repo.root + "-evil"
        os.makedirs(sibling, exist_ok=True)
        self.addCleanup(os.rmdir, sibling)
        self.denied(sibling)

    def test_embedded_null_byte(self):
        self.denied("app.py\x00.txt")

    def test_deep_traversal(self):
        self.denied("/".join([".."] * 40) + "/etc/passwd")

    # -- symlinks -------------------------------------------------------
    def test_symlink_pointing_outside(self):
        os.symlink("/etc/passwd", os.path.join(self.repo.root, "escape"))
        self.denied("escape")

    def test_symlinked_directory_pointing_outside(self):
        os.symlink("/etc", os.path.join(self.repo.root, "etc-link"))
        self.denied("etc-link/passwd")

    def test_symlink_inside_the_repository_is_refused_by_default(self):
        """Even a link that stays inside is refused unless follow_symlinks is on.

        The link itself is the thing under review. Reading through it means
        reviewing content that is not at the path the diff names.
        """
        os.symlink(os.path.join(self.repo.root, "app.py"), os.path.join(self.repo.root, "inside"))
        self.denied("inside")

    def test_the_refusal_names_what_the_caller_asked_for(self):
        os.symlink(os.path.join(self.repo.root, "app.py"), os.path.join(self.repo.root, "inside"))
        with self.assertRaises(BoundaryViolation) as caught:
            self.boundary.resolve("inside")
        self.assertIn("inside", str(caught.exception))

    def test_symlink_inside_is_allowed_when_configured(self):
        os.symlink(os.path.join(self.repo.root, "app.py"), os.path.join(self.repo.root, "inside"))
        permissive = RepositoryBoundary(self.repo.root, follow_symlinks=True)
        self.assertTrue(permissive.resolve("inside").endswith("app.py"))

    def test_symlink_outside_is_still_refused_when_following_is_on(self):
        """follow_symlinks relaxes one rule. It does not open the boundary."""
        os.symlink("/etc/passwd", os.path.join(self.repo.root, "escape"))
        permissive = RepositoryBoundary(self.repo.root, follow_symlinks=True)
        with self.assertRaises(BoundaryViolation):
            permissive.resolve("escape")

    # -- what is allowed ------------------------------------------------
    def test_ordinary_file_resolves(self):
        self.assertTrue(self.boundary.resolve("app.py").endswith("app.py"))

    def test_nested_file_resolves(self):
        self.assertTrue(self.boundary.resolve("sub/nested.py").endswith("nested.py"))

    def test_normalised_path_that_stays_inside_resolves(self):
        self.assertTrue(self.boundary.resolve("sub/../app.py").endswith("app.py"))

    def test_contains_agrees_with_resolve(self):
        self.assertTrue(self.boundary.contains("app.py"))
        self.assertFalse(self.boundary.contains("../../etc/passwd"))

    # -- reading --------------------------------------------------------
    def test_oversized_file_is_truncated_not_refused(self):
        self.repo.write("big.py", "a" * 5000)
        small = RepositoryBoundary(self.repo.root, max_file_bytes=100)
        self.assertEqual(len(small.read_bytes("big.py")), 100)
        self.assertTrue(small.is_truncated("big.py"))

    def test_walk_stays_inside(self):
        os.symlink("/etc", os.path.join(self.repo.root, "etc-link"))
        for path in self.boundary.walk():
            self.assertTrue(self.boundary.contains(path), path)


if __name__ == "__main__":
    unittest.main()
