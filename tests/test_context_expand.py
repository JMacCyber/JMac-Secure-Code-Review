"""Context expansion: which files a reviewer gets besides the diff.

Expansion is a fixed set of rules over names and import statements. So
these tests state the rules as examples: what resolves, what does not, and
what order the caller receives. Nothing here runs a model or a network.

Each test builds real files in a throwaway repository and reads them
through the real boundary, because the resolution rules work on the paths
the boundary actually reports.
"""

from __future__ import annotations

import unittest

from jscr.boundary.fs import RepositoryBoundary
from jscr.context.expand import (
    _callers_for,
    _is_test,
    _resolve_import,
    _schemas_for,
    _tests_for,
    related_paths,
)
from jscr.errors import BoundaryViolation

from .support import RepoTestCase


class UnreadableBoundary(object):
    """A boundary that refuses every read, to exercise the give-up paths."""

    def __init__(self, error: Exception) -> None:
        self.error = error

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        raise self.error


class ResolvingPythonImports(unittest.TestCase):
    def resolve(self, target, importer, known):
        return _resolve_import(target, importer, ".py", set(known))

    def test_an_absolute_module_maps_to_a_file(self):
        self.assertEqual(
            self.resolve("app.models", "app/views.py", ["app/models.py"]), "app/models.py"
        )

    def test_a_package_maps_to_its_init(self):
        self.assertEqual(
            self.resolve("app.models", "app/views.py", ["app/models/__init__.py"]),
            "app/models/__init__.py",
        )

    def test_a_single_dot_import_stays_in_the_directory(self):
        self.assertEqual(
            self.resolve(".models", "app/views.py", ["app/models.py"]), "app/models.py"
        )

    def test_a_double_dot_import_climbs_one_level(self):
        self.assertEqual(
            self.resolve("..shared", "app/web/views.py", ["app/shared.py"]), "app/shared.py"
        )

    def test_a_third_party_package_resolves_to_nothing(self):
        self.assertIsNone(self.resolve("requests", "app/views.py", ["app/models.py"]))


class ResolvingJavascriptImports(unittest.TestCase):
    def resolve(self, target, importer, known):
        return _resolve_import(target, importer, ".ts", set(known))

    def test_a_relative_import_gains_an_extension(self):
        self.assertEqual(self.resolve("./cart", "src/app.ts", ["src/cart.ts"]), "src/cart.ts")

    def test_the_extension_order_prefers_typescript(self):
        known = ["src/cart.js", "src/cart.ts"]
        self.assertEqual(self.resolve("./cart", "src/app.ts", known), "src/cart.ts")

    def test_a_directory_import_finds_its_index(self):
        self.assertEqual(
            self.resolve("../lib", "src/app/main.ts", ["src/lib/index.ts"]), "src/lib/index.ts"
        )

    def test_a_relative_import_of_a_missing_file_resolves_to_nothing(self):
        self.assertIsNone(self.resolve("./missing", "src/app.ts", ["src/cart.ts"]))

    def test_a_package_name_resolves_to_nothing(self):
        self.assertIsNone(self.resolve("react", "src/app.ts", ["src/cart.ts"]))


class ResolvingOtherLanguages(unittest.TestCase):
    def test_a_go_import_path_maps_to_a_directory_file(self):
        self.assertEqual(
            _resolve_import("internal/store", "main.go", ".go", {"internal/store.go"}),
            "internal/store.go",
        )

    def test_a_java_package_becomes_a_path(self):
        self.assertEqual(
            _resolve_import("com.app.Cart", "Main.java", ".java", {"com/app/Cart.java"}),
            "com/app/Cart.java",
        )

    def test_a_rust_use_path_becomes_a_path(self):
        self.assertEqual(
            _resolve_import("crate::store", "main.rs", ".rs", {"crate/store.rs"}),
            "crate/store.rs",
        )

    def test_the_last_segment_is_tried_when_the_full_path_misses(self):
        self.assertEqual(
            _resolve_import("github.com/x/y/store", "main.go", ".go", {"internal/store.go"}),
            "internal/store.go",
        )

    def test_an_unknown_target_resolves_to_nothing(self):
        self.assertIsNone(_resolve_import("fmt", "main.go", ".go", {"internal/store.go"}))


class NamingATest(unittest.TestCase):
    def test_a_directory_called_tests_marks_the_file(self):
        self.assertTrue(_is_test("tests/support.py"))

    def test_a_spec_directory_marks_the_file(self):
        self.assertTrue(_is_test("spec/cart.rb"))

    def test_a_test_prefix_marks_the_file(self):
        self.assertTrue(_is_test("app/test_cart.py"))

    def test_a_dot_spec_suffix_marks_the_file(self):
        self.assertTrue(_is_test("src/cart.spec.ts"))

    def test_ordinary_source_is_not_a_test(self):
        self.assertFalse(_is_test("src/cart.ts"))

    def test_the_word_latest_in_a_path_is_not_a_test(self):
        self.assertFalse(_is_test("src/latest.py"))


class FindingTestsForAFile(unittest.TestCase):
    def test_a_matching_test_file_is_found(self):
        known = ["src/cart.py", "tests/test_cart.py", "tests/test_orders.py"]
        self.assertEqual(_tests_for("src/cart.py", known), ["tests/test_cart.py"])

    def test_a_changed_test_file_gets_no_tests_of_its_own(self):
        self.assertEqual(_tests_for("tests/test_cart.py", ["tests/test_cart.py"]), [])

    def test_a_file_with_no_matching_test_gets_nothing(self):
        self.assertEqual(_tests_for("src/cart.py", ["tests/test_orders.py"]), [])

    def test_the_match_ignores_case(self):
        self.assertEqual(_tests_for("src/Cart.js", ["spec/cart.spec.js"]), ["spec/cart.spec.js"])


class FindingSchemasNearAFile(unittest.TestCase):
    def test_a_manifest_in_the_same_directory_is_found(self):
        self.assertEqual(
            _schemas_for("api/handler.py", ["api/openapi.yaml"]),
            ["api/openapi.yaml"],
        )

    def test_a_manifest_at_the_repository_root_is_found(self):
        self.assertEqual(_schemas_for("api/handler.py", ["pyproject.toml"]), ["pyproject.toml"])

    def test_a_manifest_in_a_parent_directory_is_found(self):
        self.assertEqual(
            _schemas_for("api/v1/handler.py", ["api/package.json"]), ["api/package.json"]
        )

    def test_a_manifest_in_an_unrelated_directory_is_ignored(self):
        self.assertEqual(_schemas_for("api/handler.py", ["web/package.json"]), [])

    def test_a_file_that_is_not_a_manifest_is_ignored(self):
        self.assertEqual(_schemas_for("api/handler.py", ["api/notes.md"]), [])


class FindingCallers(RepoTestCase):
    def boundary(self):
        return RepositoryBoundary(self.repo.root)

    def test_a_file_naming_the_changed_module_is_a_caller(self):
        self.repo.write("cart.py", "VALUE = 1\n")
        self.repo.write("checkout.py", "import cart\n")
        known = ["cart.py", "checkout.py"]
        self.assertEqual(_callers_for(self.boundary(), ["cart.py"], known), ["checkout.py"])

    def test_the_changed_file_is_not_its_own_caller(self):
        self.repo.write("cart.py", "cart = 1\n")
        self.assertEqual(_callers_for(self.boundary(), ["cart.py"], ["cart.py"]), [])

    def test_a_short_stem_is_refused_because_it_would_match_everything(self):
        self.repo.write("db.py", "X = 1\n")
        self.repo.write("app.py", "import db\n")
        self.assertEqual(_callers_for(self.boundary(), ["db.py"], ["db.py", "app.py"]), [])

    def test_a_generic_stem_is_refused_for_the_same_reason(self):
        self.repo.write("utils.py", "X = 1\n")
        self.repo.write("app.py", "import utils\n")
        self.assertEqual(_callers_for(self.boundary(), ["utils.py"], ["utils.py", "app.py"]), [])

    def test_a_non_source_file_is_never_searched(self):
        self.repo.write("cart.py", "X = 1\n")
        self.repo.write("notes.md", "cart is changing\n")
        known = ["cart.py", "notes.md"]
        self.assertEqual(_callers_for(self.boundary(), ["cart.py"], known), [])

    def test_the_search_stops_at_twenty_five_hits(self):
        self.repo.write("cart.py", "X = 1\n")
        known = ["cart.py"]
        for number in range(40):
            name = "caller{0:02d}.py".format(number)
            self.repo.write(name, "import cart\n")
            known.append(name)
        self.assertEqual(len(_callers_for(self.boundary(), ["cart.py"], known)), 25)

    def test_an_unreadable_candidate_is_left_out_rather_than_raising(self):
        refusing = UnreadableBoundary(BoundaryViolation("fs.read", "refused"))
        self.assertEqual(_callers_for(refusing, ["cart.py"], ["checkout.py"]), [])

    def test_a_file_that_is_not_text_is_left_out(self):
        refusing = UnreadableBoundary(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"))
        self.assertEqual(_callers_for(refusing, ["cart.py"], ["checkout.py"]), [])


class ExpandingAChange(RepoTestCase):
    def setUp(self):
        RepoTestCase.setUp(self)
        self.repo.write("pyproject.toml", "[project]\nname = 'x'\n")
        self.repo.write("app/models.py", "VALUE = 1\n")
        self.repo.write("app/views.py", "from .models import VALUE\n")
        self.repo.write("app/checkout.py", "import views\n")
        self.repo.write("tests/test_views.py", "VALUE = 1\n")
        self.boundary = RepositoryBoundary(self.repo.root)

    def expand(self, **flags):
        return related_paths(self.boundary, ["app/views.py"], **flags)

    def test_imports_tests_and_schemas_all_come_back(self):
        found = self.expand()
        self.assertIn("app/models.py", found)
        self.assertIn("tests/test_views.py", found)
        self.assertIn("pyproject.toml", found)

    def test_the_order_is_imports_then_tests_then_schemas(self):
        found = self.expand()
        self.assertLess(found.index("app/models.py"), found.index("tests/test_views.py"))
        self.assertLess(found.index("tests/test_views.py"), found.index("pyproject.toml"))

    def test_callers_are_off_unless_asked_for(self):
        self.assertNotIn("app/checkout.py", self.expand())

    def test_callers_arrive_when_asked_for(self):
        self.assertIn("app/checkout.py", self.expand(expand_callers=True))

    def test_each_switch_turns_its_group_off(self):
        found = self.expand(expand_imports=False, expand_tests=False, expand_schemas=False)
        self.assertEqual(found, [])

    def test_the_changed_file_is_never_returned(self):
        self.assertNotIn("app/views.py", self.expand())

    def test_a_path_is_returned_once_however_many_rules_find_it(self):
        found = related_paths(self.boundary, ["app/views.py", "app/models.py"])
        self.assertEqual(found.count("pyproject.toml"), 1)

    def test_two_changed_files_importing_one_module_return_it_once(self):
        self.repo.write("app/orders.py", "from .models import VALUE\n")
        found = related_paths(self.boundary, ["app/views.py", "app/orders.py"])
        self.assertEqual(found.count("app/models.py"), 1)

    def test_a_supplied_index_replaces_the_walk(self):
        index = ["app/views.py", "app/models.py"]
        found = related_paths(self.boundary, ["app/views.py"], index=index)
        self.assertEqual(found, ["app/models.py"])

    def test_a_candidate_outside_the_index_is_dropped(self):
        index = ["app/views.py", "tests/test_views.py"]
        found = related_paths(self.boundary, ["app/views.py"], index=index)
        self.assertEqual(found, ["tests/test_views.py"])

    def test_a_changed_file_that_is_not_in_the_index_yields_no_imports(self):
        found = related_paths(self.boundary, ["gone.py"], index=["app/models.py"])
        self.assertEqual(found, [])


class WhenAChangedFileCannotBeRead(RepoTestCase):
    def test_expansion_gives_up_on_that_file_rather_than_failing(self):
        refusing = UnreadableBoundary(BoundaryViolation("fs.read", "refused"))
        found = related_paths(refusing, ["app/views.py"], index=["app/views.py", "app/models.py"])
        self.assertEqual(found, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
