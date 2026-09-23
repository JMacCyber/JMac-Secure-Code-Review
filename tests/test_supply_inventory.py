"""The dependency inventory, read from manifests and nothing else.

The inventory never resolves a version or asks a registry anything, so
these tests hand the reader a dictionary of file text and check what comes
back. A field a manifest does not carry must come back empty: an empty
licence means "not declared here", and a test that accepted a guess there
would undo the point of the module.
"""

from __future__ import annotations

import json
import unittest

from jscr.supply.inventory import (
    CARGO,
    GO,
    NPM,
    PYPI,
    Package,
    manifest_paths,
    read_inventory,
)


def reader_for(files):
    """A reader over a dictionary. A missing path raises, as a boundary would."""

    def read(path):
        if path not in files:
            raise OSError("no such file: {0}".format(path))
        return files[path]

    return read


def inventory(files):
    return read_inventory(reader_for(files), sorted(files))


def by_name(packages):
    return {p.name: p for p in packages}


class DescribingOnePackage(unittest.TestCase):
    def test_the_key_joins_ecosystem_name_and_version(self):
        self.assertEqual(Package(NPM, "left-pad", "1.3.0").key, "npm:left-pad@1.3.0")

    def test_a_missing_version_is_named_rather_than_left_blank(self):
        self.assertEqual(Package(PYPI, "flask").key, "pypi:flask@unspecified")

    def test_the_dictionary_carries_every_field(self):
        row = Package(GO, "example.com/x", "v1.0.0", "MIT", "runtime", "registry", "go.mod")
        self.assertEqual(
            row.as_dict(),
            {
                "ecosystem": "go",
                "name": "example.com/x",
                "version": "v1.0.0",
                "licence": "MIT",
                "scope": "runtime",
                "source": "registry",
                "declared_in": "go.mod",
            },
        )

    def test_the_defaults_are_runtime_and_registry(self):
        row = Package(NPM, "left-pad")
        self.assertEqual(row.scope, "runtime")
        self.assertEqual(row.source, "registry")
        self.assertEqual(row.licence, "")


class ChoosingManifests(unittest.TestCase):
    def test_every_known_manifest_name_is_picked_up(self):
        paths = [
            "package.json",
            "package-lock.json",
            "requirements.txt",
            "pyproject.toml",
            "go.mod",
            "Cargo.toml",
        ]
        self.assertEqual(manifest_paths(paths), sorted(paths))

    def test_a_requirements_variant_counts(self):
        self.assertEqual(manifest_paths(["requirements-dev.txt"]), ["requirements-dev.txt"])

    def test_a_manifest_inside_node_modules_is_ignored(self):
        self.assertEqual(manifest_paths(["node_modules/left-pad/package.json"]), [])

    def test_a_manifest_inside_vendor_is_ignored(self):
        self.assertEqual(manifest_paths(["src/vendor/x/go.mod"]), [])

    def test_a_windows_path_is_read_the_same_way(self):
        self.assertEqual(manifest_paths([r"app\package.json"]), [r"app\package.json"])

    def test_an_ordinary_source_file_is_not_a_manifest(self):
        self.assertEqual(manifest_paths(["src/app.py", "README.md"]), [])

    def test_the_result_is_sorted(self):
        self.assertEqual(manifest_paths(["go.mod", "Cargo.toml"]), ["Cargo.toml", "go.mod"])


class ReadingNpmManifests(unittest.TestCase):
    def manifest(self, data):
        return inventory({"package.json": json.dumps(data)})

    def test_runtime_and_development_are_told_apart(self):
        found = by_name(
            self.manifest(
                {"dependencies": {"left-pad": "^1.3.0"}, "devDependencies": {"jest": "29"}}
            )
        )
        self.assertEqual(found["left-pad"].scope, "runtime")
        self.assertEqual(found["jest"].scope, "development")

    def test_optional_dependencies_get_their_own_scope(self):
        found = by_name(self.manifest({"optionalDependencies": {"fsevents": "2"}}))
        self.assertEqual(found["fsevents"].scope, "optional")

    def test_peer_dependencies_count_as_runtime(self):
        found = by_name(self.manifest({"peerDependencies": {"react": "18"}}))
        self.assertEqual(found["react"].scope, "runtime")

    def test_the_declared_range_is_kept_as_written(self):
        found = by_name(self.manifest({"dependencies": {"left-pad": "^1.3.0"}}))
        self.assertEqual(found["left-pad"].version, "^1.3.0")

    def test_a_git_dependency_is_marked_as_not_from_the_registry(self):
        found = by_name(self.manifest({"dependencies": {"x": "git+https://host/x.git"}}))
        self.assertEqual(found["x"].source, "git-https")

    def test_a_tarball_dependency_is_marked_as_a_url(self):
        found = by_name(self.manifest({"dependencies": {"x": "./vendor/x.tgz"}}))
        self.assertEqual(found["x"].source, "url")

    def test_a_file_dependency_is_marked_as_a_file(self):
        found = by_name(self.manifest({"dependencies": {"x": "file:../x"}}))
        self.assertEqual(found["x"].source, "file")

    def test_a_manifest_that_is_not_an_object_yields_nothing(self):
        self.assertEqual(inventory({"package.json": "[1, 2]"}), [])

    def test_malformed_json_yields_nothing_rather_than_raising(self):
        self.assertEqual(inventory({"package.json": "{oh no"}), [])

    def test_a_dependency_block_that_is_not_an_object_is_skipped(self):
        self.assertEqual(inventory({"package.json": json.dumps({"dependencies": []})}), [])

    def test_a_manifest_the_reader_refuses_yields_nothing(self):
        self.assertEqual(read_inventory(reader_for({}), ["package.json"]), [])


class ReadingNpmLockfiles(unittest.TestCase):
    def lock(self, data):
        return inventory({"package-lock.json": json.dumps(data)})

    def test_the_resolved_version_and_licence_are_read(self):
        found = by_name(
            self.lock(
                {
                    "packages": {
                        "node_modules/left-pad": {"version": "1.3.0", "license": "WTFPL"},
                    }
                }
            )
        )
        self.assertEqual(found["left-pad"].version, "1.3.0")
        self.assertEqual(found["left-pad"].licence, "WTFPL")

    def test_the_name_is_taken_from_the_entry_when_it_carries_one(self):
        found = self.lock({"packages": {"node_modules/a": {"name": "@scope/a", "version": "1"}}})
        self.assertEqual(found[0].name, "@scope/a")

    def test_the_root_entry_is_skipped(self):
        found = self.lock({"packages": {"": {"name": "root", "version": "1"}}})
        self.assertEqual(found, [])

    def test_a_dev_entry_is_scoped_as_development(self):
        found = self.lock({"packages": {"node_modules/jest": {"version": "29", "dev": True}}})
        self.assertEqual(found[0].scope, "development")

    def test_an_entry_that_is_not_an_object_is_skipped(self):
        self.assertEqual(self.lock({"packages": {"node_modules/a": "1.0.0"}}), [])

    def test_the_old_lockfile_layout_is_still_read(self):
        found = by_name(self.lock({"dependencies": {"left-pad": {"version": "1.3.0"}}}))
        self.assertEqual(found["left-pad"].version, "1.3.0")

    def test_an_old_layout_dev_entry_is_scoped_as_development(self):
        found = self.lock({"dependencies": {"jest": {"version": "29", "dev": True}}})
        self.assertEqual(found[0].scope, "development")

    def test_an_old_layout_entry_that_is_not_an_object_is_skipped(self):
        self.assertEqual(self.lock({"dependencies": {"left-pad": "1.3.0"}}), [])

    def test_malformed_lockfile_json_yields_nothing_rather_than_raising(self):
        self.assertEqual(inventory({"package-lock.json": "{oh no"}), [])

    def test_a_lockfile_with_neither_section_yields_nothing(self):
        self.assertEqual(self.lock({"lockfileVersion": 3}), [])


class ReadingRequirements(unittest.TestCase):
    def requirements(self, text):
        return inventory({"requirements.txt": text})

    def test_a_pinned_version_is_read(self):
        found = self.requirements("flask==3.0.0\n")
        self.assertEqual(
            (found[0].ecosystem, found[0].name, found[0].version), (PYPI, "flask", "==3.0.0")
        )

    def test_a_range_operator_is_kept(self):
        self.assertEqual(self.requirements("flask>=2.0\n")[0].version, ">=2.0")

    def test_a_package_with_no_version_comes_back_unversioned(self):
        self.assertEqual(self.requirements("flask\n")[0].version, "")

    def test_extras_are_stripped_from_the_name(self):
        found = self.requirements("celery[redis]==5.3\n")
        self.assertEqual((found[0].name, found[0].version), ("celery", "==5.3"))

    def test_a_marker_is_not_taken_for_a_version(self):
        self.assertEqual(
            self.requirements('flask==3.0.0; python_version < "3.10"\n')[0].version, "==3.0.0"
        )

    def test_comments_and_blank_lines_are_skipped(self):
        self.assertEqual(self.requirements("# a comment\n\nflask\n")[0].name, "flask")

    def test_an_include_line_is_skipped(self):
        self.assertEqual(self.requirements("-r other.txt\n--index-url https://x/\n"), [])

    def test_a_line_that_is_not_a_requirement_is_skipped(self):
        self.assertEqual(self.requirements("%%% not a package\n"), [])

    def test_a_file_the_reader_refuses_yields_nothing(self):
        self.assertEqual(read_inventory(reader_for({}), ["requirements.txt"]), [])


class ReadingPyproject(unittest.TestCase):
    def pyproject(self, text):
        return inventory({"pyproject.toml": text})

    def test_dependencies_are_read_from_the_array(self):
        found = by_name(
            self.pyproject('[project]\nname = "app"\ndependencies = ["flask>=2.0", "click"]\n')
        )
        self.assertEqual(found["flask"].version, ">=2.0")
        self.assertEqual(found["click"].version, "")

    def test_an_array_spanning_several_lines_is_read_whole(self):
        text = '[project]\nname = "app"\ndependencies = [\n  "flask>=2.0",\n  "click",\n]\n'
        self.assertEqual(len(self.pyproject(text)), 2)

    def test_single_quoted_entries_are_read_too(self):
        self.assertEqual(self.pyproject("dependencies = ['flask>=2.0']\n")[0].name, "flask")

    def test_a_project_with_no_dependencies_reports_itself_and_its_licence(self):
        found = self.pyproject('[project]\nname = "app"\nlicense = "Apache-2.0"\n')
        self.assertEqual(
            (found[0].name, found[0].licence, found[0].scope), ("app", "Apache-2.0", "self")
        )

    def test_a_licence_table_is_reduced_to_its_text(self):
        found = self.pyproject('[project]\nname = "app"\nlicense = {text = "MIT"}\n')
        self.assertEqual(found[0].licence, "MIT")

    def test_an_unnamed_project_gets_a_placeholder_name(self):
        self.assertEqual(self.pyproject('[project]\nlicense = "MIT"\n')[0].name, "this-project")

    def test_a_comment_is_not_read_as_a_key(self):
        found = self.pyproject('[project]\nname = "app"  # the name\nlicense = "MIT"\n')
        self.assertEqual(found[0].name, "app")

    def test_a_file_with_neither_licence_nor_dependencies_yields_nothing(self):
        self.assertEqual(self.pyproject("[build-system]\nrequires = []\n"), [])

    def test_a_file_the_reader_refuses_yields_nothing(self):
        self.assertEqual(read_inventory(reader_for({}), ["pyproject.toml"]), [])


class ReadingGoModules(unittest.TestCase):
    def gomod(self, text):
        return inventory({"go.mod": text})

    def test_a_required_module_is_read(self):
        found = self.gomod("module example.com/app\n\nrequire example.com/x v1.2.3\n")
        self.assertEqual(
            (found[0].ecosystem, found[0].name, found[0].version), (GO, "example.com/x", "v1.2.3")
        )

    def test_a_module_inside_a_require_block_is_read(self):
        found = self.gomod("require (\n\texample.com/x v1.2.3\n)\n")
        self.assertEqual(found[0].name, "example.com/x")

    def test_an_indirect_module_is_scoped_as_development(self):
        found = self.gomod("\texample.com/x v1.2.3 // indirect\n")
        self.assertEqual(found[0].scope, "development")

    def test_the_module_line_is_not_a_dependency(self):
        self.assertEqual(self.gomod("module example.com/app\n"), [])

    def test_a_comment_line_is_skipped(self):
        self.assertEqual(self.gomod("// example.com/x v1.2.3\n"), [])

    def test_a_file_the_reader_refuses_yields_nothing(self):
        self.assertEqual(read_inventory(reader_for({}), ["go.mod"]), [])


class ReadingCargoManifests(unittest.TestCase):
    def cargo(self, text):
        return inventory({"Cargo.toml": text})

    def test_a_dependency_and_its_version_are_read(self):
        found = self.cargo('[dependencies]\nserde = "1.0"\n')
        self.assertEqual(
            (found[0].ecosystem, found[0].name, found[0].version), (CARGO, "serde", "1.0")
        )

    def test_a_dev_dependency_is_scoped_as_development(self):
        self.assertEqual(
            self.cargo('[dev-dependencies]\ncriterion = "0.5"\n')[0].scope, "development"
        )

    def test_a_build_dependency_is_scoped_as_development(self):
        self.assertEqual(self.cargo('[build-dependencies]\ncc = "1.0"\n')[0].scope, "development")

    def test_a_table_valued_dependency_is_left_unversioned(self):
        found = self.cargo('[dependencies]\nserde = { version = "1.0", features = ["derive"] }\n')
        self.assertEqual((found[0].name, found[0].version), ("serde", ""))

    def test_keys_outside_a_dependency_table_are_ignored(self):
        self.assertEqual(self.cargo('[package]\nname = "app"\n'), [])

    def test_a_file_the_reader_refuses_yields_nothing(self):
        self.assertEqual(read_inventory(reader_for({}), ["Cargo.toml"]), [])


class MergingWhatEveryManifestSaid(unittest.TestCase):
    def test_the_same_package_from_two_files_appears_once(self):
        files = {
            "package.json": json.dumps({"dependencies": {"left-pad": "1.3.0"}}),
            "package-lock.json": json.dumps(
                {"packages": {"node_modules/left-pad": {"version": "1.3.0"}}}
            ),
        }
        self.assertEqual(len(inventory(files)), 1)

    def test_the_row_carrying_a_licence_wins(self):
        files = {
            "package.json": json.dumps({"dependencies": {"left-pad": "1.3.0"}}),
            "package-lock.json": json.dumps(
                {"packages": {"node_modules/left-pad": {"version": "1.3.0", "license": "WTFPL"}}}
            ),
        }
        self.assertEqual(inventory(files)[0].licence, "WTFPL")

    def test_two_versions_of_one_package_stay_separate(self):
        files = {
            "package-lock.json": json.dumps(
                {
                    "packages": {
                        "node_modules/a/node_modules/left-pad": {
                            "name": "left-pad",
                            "version": "1.2.0",
                        },
                        "node_modules/left-pad": {"version": "1.3.0"},
                    }
                }
            )
        }
        self.assertEqual([p.version for p in inventory(files)], ["1.2.0", "1.3.0"])

    def test_the_result_is_ordered_by_ecosystem_then_name(self):
        files = {
            "package.json": json.dumps({"dependencies": {"zod": "3"}}),
            "requirements.txt": "flask\n",
            "go.mod": "require example.com/x v1.0.0\n",
        }
        self.assertEqual([p.ecosystem for p in inventory(files)], [GO, NPM, PYPI])

    def test_a_repository_with_no_manifests_yields_nothing(self):
        self.assertEqual(inventory({"src/app.py": "x = 1\n"}), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
