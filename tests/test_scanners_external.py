"""How the external wrappers invoke their programs.

These tests do not need semgrep or gitleaks installed. They check the
argument list and the parsing, which is where both wrappers were wrong: one
asked semgrep for a rule set it downloads, the other called a gitleaks
subcommand that no longer exists and asked for a report on a stream the
program refuses to write to.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from typing import List

from jscr.boundary.fs import RepositoryBoundary
from jscr.config import Config
from jscr.scanners.external import (
    BUNDLED_SEMGREP_RULES,
    ExternalScanner,
    GitleaksScanner,
    SemgrepScanner,
    TrivyScanner,
    _confidence,
    _discard,
    _first_cwe,
    _json,
    _package_lines,
    _read_report,
    _relative,
    _report_path,
    _secret_free_evidence,
    _short_check_id,
    _source_line,
)

from .support import RepoTestCase


class SemgrepCommand(RepoTestCase):
    def boundary(self):
        return RepositoryBoundary(self.repo.root)

    def test_the_bundled_rule_file_is_used_by_default(self):
        argv = SemgrepScanner(Config.defaults()).command(self.boundary(), [])
        self.assertIn("--config={0}".format(BUNDLED_SEMGREP_RULES), argv)
        self.assertTrue(os.path.exists(BUNDLED_SEMGREP_RULES))

    def test_no_argument_asks_semgrep_to_download_rules(self):
        argv = SemgrepScanner(Config.defaults()).command(self.boundary(), [])
        self.assertNotIn("--config=auto", argv)
        self.assertIn("--metrics=off", argv)

    def test_a_repository_rule_file_wins_over_the_bundled_one(self):
        self.repo.write(".semgrep.yml", "rules: []\n")
        argv = SemgrepScanner(Config.defaults()).command(self.boundary(), [])
        self.assertIn("--config=.semgrep.yml", argv)

    def test_configuration_wins_over_both(self):
        self.repo.write(".semgrep.yml", "rules: []\n")
        config = Config.defaults()
        config.override("scanners.semgrep_config", "/rules/house.yml")
        argv = SemgrepScanner(config).command(self.boundary(), [])
        self.assertIn("--config=/rules/house.yml", argv)

    def test_a_local_rule_keeps_its_own_name(self):
        long_id = "Users.someone.jscr.src.rules.jscr-py-yaml-load"
        self.assertEqual(_short_check_id(long_id), "jscr-py-yaml-load")

    def test_a_registry_rule_id_is_left_alone(self):
        registry = "python.lang.security.audit.dangerous-subprocess-use"
        self.assertEqual(_short_check_id(registry), registry)


class GitleaksCommand(RepoTestCase):
    def test_the_working_tree_is_scanned_and_the_report_goes_to_a_file(self):
        boundary = RepositoryBoundary(self.repo.root)
        argv = GitleaksScanner(Config.defaults()).command(boundary, [], "/tmp/report.json")
        self.assertEqual(argv[1], "dir")
        self.assertIn("--report-path=/tmp/report.json", argv)
        self.assertNotIn("--report-path=/dev/stdout", argv)

    def test_a_report_is_read_into_findings(self):
        boundary = RepositoryBoundary(self.repo.root)
        payload = json.dumps(
            [
                {
                    "File": os.path.join(self.repo.root, "app.py"),
                    "StartLine": 12,
                    "RuleID": "generic-api-key",
                    "Description": "a value that looks like a key",
                    "Match": "REDACTED",
                }
            ]
        )
        findings = GitleaksScanner(Config.defaults()).parse(payload, boundary)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "app.py")
        self.assertEqual(findings[0].line, 12)


class EvidenceIsTheFilesOwnText(RepoTestCase):
    """Both wrappers used to quote a string the file does not contain.

    semgrep returns ``requires login`` in place of the matched line when it
    is not signed in, gitleaks returns ``REDACTED``. Anchoring then rejects
    the finding, so a real match is discarded as unverifiable.
    """

    def test_semgrep_evidence_comes_from_the_file_not_from_semgrep(self):
        self.repo.write("app.js", "const a = 1;\nconst f = new Function(body);\n")
        boundary = RepositoryBoundary(self.repo.root)
        payload = json.dumps(
            {
                "results": [
                    {
                        "path": os.path.join(self.repo.root, "app.js"),
                        "start": {"line": 2},
                        "end": {"line": 2},
                        "check_id": "jscr-js-new-function",
                        "extra": {
                            "message": "new Function compiles a string into code",
                            "severity": "ERROR",
                            "lines": "requires login",
                        },
                    }
                ]
            }
        )
        findings = SemgrepScanner(Config.defaults()).parse(payload, boundary)
        self.assertEqual(findings[0].evidence, "const f = new Function(body);")

    def test_gitleaks_evidence_is_the_name_never_the_value(self):
        value = "xoxb-" + "1234567890" + "-" + "0987654321" + "-" + ("a" * 24)
        self.repo.write("conf.py", 'TOKEN = "{0}"\n'.format(value))
        boundary = RepositoryBoundary(self.repo.root)
        payload = json.dumps(
            [
                {
                    "File": os.path.join(self.repo.root, "conf.py"),
                    "StartLine": 1,
                    "RuleID": "slack-bot-token",
                    "Match": "REDACTED",
                }
            ]
        )
        findings = GitleaksScanner(Config.defaults()).parse(payload, boundary)
        self.assertEqual(findings[0].evidence, "TOKEN =")
        self.assertNotIn(value, findings[0].evidence)

    def test_a_line_with_nowhere_safe_to_cut_is_not_quoted(self):
        self.assertEqual(_secret_free_evidence("xoxb-" + ("a" * 30)), "")

    def test_the_match_column_is_a_ceiling_on_the_cut(self):
        # The value comes first and a colon follows it, so cutting at the
        # colon would quote the value. The column stops that.
        line = "AKIA" + ("Q" * 16) + ":name"
        self.assertEqual(_secret_free_evidence(line, 1), "")

    def test_an_unreadable_file_leaves_the_evidence_empty(self):
        boundary = RepositoryBoundary(self.repo.root)
        payload = json.dumps(
            [{"File": "gone.py", "StartLine": 3, "RuleID": "generic-api-key", "Match": "REDACTED"}]
        )
        findings = GitleaksScanner(Config.defaults()).parse(payload, boundary)
        self.assertEqual(findings[0].evidence, "")


class TrivyIsGivenALine(RepoTestCase):
    """trivy reports a package, not a position.

    Its JSON for a lockfile carries no line at all, so every dependency
    finding used to arrive at line 0 and be rejected as unanchorable. The
    wrapper finds where the lockfile names the package.
    """

    def test_a_vulnerable_package_is_anchored_to_its_lockfile_entry(self):
        self.repo.write(
            "package-lock.json",
            "{\n"
            '  "packages": {\n'
            '    "": { "dependencies": { "fast-uri": "^3.0.1" } },\n'
            '    "node_modules/fast-uri": { "version": "3.1.5" }\n'
            "  }\n}\n",
        )
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "package-lock.json",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-0000-1",
                                "PkgName": "fast-uri",
                                "InstalledVersion": "3.1.5",
                                "Severity": "HIGH",
                                "FixedVersion": "3.1.6",
                            }
                        ],
                    }
                ]
            }
        )
        boundary = RepositoryBoundary(self.repo.root)
        findings = TrivyScanner(Config.defaults()).parse(payload, boundary)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 4)
        self.assertIn("node_modules/fast-uri", findings[0].evidence)

    def test_a_package_the_file_never_names_falls_back_to_line_one(self):
        self.repo.write("package-lock.json", '{\n  "packages": {}\n}\n')
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "package-lock.json",
                        "Vulnerabilities": [{"VulnerabilityID": "CVE-0000-2", "PkgName": "gone"}],
                    }
                ]
            }
        )
        boundary = RepositoryBoundary(self.repo.root)
        findings = TrivyScanner(Config.defaults()).parse(payload, boundary)
        self.assertEqual(findings[0].line, 1)
        self.assertEqual(findings[0].evidence, "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class Completed(object):
    """Stands in for ``subprocess.CompletedProcess``."""

    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeScanner(ExternalScanner):
    """An external scanner whose program is replaced by a canned answer.

    The wrappers are tested without semgrep, gitleaks or trivy on the
    machine, because a test that skips when a program is absent proves
    nothing on the machine that matters.
    """

    name = "fake"
    binary = "fake-scanner"

    def __init__(self, answer=None, present=True, config=None):
        ExternalScanner.__init__(self, config)
        self.answer = answer if answer is not None else Completed()
        self.present = present
        self.calls = []

    def installed(self):
        return self.present

    def command(self, boundary, paths, report_path=None):
        return [self.binary, "--json", report_path or "."]

    def parse(self, stdout, boundary) -> List:
        self.parsed = stdout
        return ["finding"] if stdout.strip() else []

    def version(self):
        return "fake 1.0"

    def _run(self, argv, cwd, timeout, extra_environment=None):  # noqa: D102
        self.calls.append((list(argv), cwd, timeout, extra_environment))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


class RunningAScanner(RepoTestCase):
    def boundary(self):
        return RepositoryBoundary(self.repo.root)

    def test_a_missing_program_is_reported_not_treated_as_clean(self):
        result = FakeScanner(present=False).scan(self.boundary(), [])
        self.assertFalse(result.ran)
        self.assertIn("not installed", result.error)
        self.assertEqual(result.findings, [])

    def test_a_successful_run_returns_its_findings(self):
        scanner = FakeScanner(Completed(stdout=b'{"results": []}'))
        result = scanner.scan(self.boundary(), [])
        self.assertTrue(result.ran)
        self.assertEqual(result.findings, ["finding"])
        self.assertEqual(result.version, "fake 1.0")
        self.assertGreaterEqual(result.duration_seconds, 0)

    def test_the_program_runs_at_the_repository_root(self):
        scanner = FakeScanner()
        scanner.scan(self.boundary(), [])
        self.assertEqual(scanner.calls[0][1], self.boundary().root)

    def test_the_timeout_is_passed_to_the_program(self):
        scanner = FakeScanner()
        scanner.scan(self.boundary(), [], timeout=7)
        self.assertEqual(scanner.calls[0][2], 7)

    def test_a_timeout_is_reported_rather_than_swallowed(self):
        scanner = FakeScanner(subprocess.TimeoutExpired(["fake-scanner"], 5))
        result = scanner.scan(self.boundary(), [], timeout=5)
        self.assertFalse(result.ran)
        self.assertEqual(result.error, "timed out after 5s")

    def test_an_os_error_is_reported_rather_than_swallowed(self):
        result = FakeScanner(OSError("permission denied")).scan(self.boundary(), [])
        self.assertFalse(result.ran)
        self.assertIn("permission denied", result.error)

    def test_output_that_cannot_be_parsed_is_reported(self):
        class Refusing(FakeScanner):
            def parse(self, stdout, boundary):
                raise ValueError("not json")

        result = Refusing(Completed(stdout=b"x")).scan(self.boundary(), [])
        self.assertFalse(result.ran)
        self.assertIn("could not read output", result.error)

    def test_a_failing_return_code_carries_the_error_output(self):
        scanner = FakeScanner(Completed(returncode=2, stderr=b"config is broken"))
        self.assertEqual(scanner.scan(self.boundary(), []).error, "config is broken")

    def test_a_return_code_of_one_means_it_found_something(self):
        scanner = FakeScanner(Completed(returncode=1, stdout=b"x", stderr=b"noise"))
        result = scanner.scan(self.boundary(), [])
        self.assertTrue(result.ran)
        self.assertEqual(result.error, "")

    def test_error_output_is_truncated(self):
        scanner = FakeScanner(Completed(returncode=2, stderr=b"x" * 900))
        self.assertEqual(len(scanner.scan(self.boundary(), []).error), 400)


class ReadingAReportFile(RepoTestCase):
    """Some programs write their report to a file rather than to stdout."""

    def boundary(self):
        return RepositoryBoundary(self.repo.root)

    def scanner(self, report_text):
        class Filed(FakeScanner):
            report_file = True

            def _run(inner, argv, cwd, timeout, extra_environment=None):
                inner.calls.append((list(argv), cwd, timeout, extra_environment))
                with open(argv[-1], "w", encoding="utf-8") as handle:
                    handle.write(report_text)
                return Completed()

        return Filed()

    def test_the_report_is_read_from_the_file_not_from_stdout(self):
        scanner = self.scanner('[{"RuleID": "x"}]')
        result = scanner.scan(self.boundary(), [])
        self.assertTrue(result.ran)
        self.assertEqual(scanner.parsed, '[{"RuleID": "x"}]')

    def test_the_report_file_is_removed_once_it_has_been_read(self):
        scanner = self.scanner("[]")
        scanner.scan(self.boundary(), [])
        self.assertFalse(os.path.exists(scanner.calls[0][0][-1]))

    def test_the_report_file_is_removed_after_a_timeout_too(self):
        class Timing(FakeScanner):
            report_file = True

            def _run(inner, argv, cwd, timeout, extra_environment=None):
                inner.calls.append((list(argv), cwd, timeout, extra_environment))
                raise subprocess.TimeoutExpired(argv, timeout)

        scanner = Timing()
        scanner.scan(self.boundary(), [], timeout=1)
        self.assertFalse(os.path.exists(scanner.calls[0][0][-1]))


class TheEnvironmentAProgramGets(unittest.TestCase):
    """``_run`` hands the child a small, named set of variables."""

    def environment_seen_by_a_child(self, extra=None):
        argv = [sys.executable, "-c", "import json, os; print(json.dumps(dict(os.environ)))"]
        completed = ExternalScanner._run(argv, cwd=os.getcwd(), timeout=30, extra_environment=extra)
        return json.loads(completed.stdout.decode("utf-8"))

    def test_a_variable_this_process_holds_does_not_reach_the_child(self):
        os.environ["JSCR_TEST_TOKEN"] = "must-not-travel"
        self.addCleanup(os.environ.pop, "JSCR_TEST_TOKEN", None)
        self.assertNotIn("JSCR_TEST_TOKEN", self.environment_seen_by_a_child())

    def test_only_the_named_variables_are_passed_through(self):
        seen = self.environment_seen_by_a_child()
        allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TZ", "SYSTEMROOT", "TMPDIR"}
        # macOS adds these two itself when it starts the process. They are not
        # ours to pass or withhold, and they carry no secret.
        allowed |= {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}
        extra = set(seen) - allowed
        self.assertEqual(extra, set(), "unexpected variables: {0}".format(extra))

    def test_the_child_is_always_given_a_path(self):
        self.assertTrue(self.environment_seen_by_a_child().get("PATH"))

    def test_a_wrapper_can_add_its_own_variable(self):
        seen = self.environment_seen_by_a_child({"DOCKER_CONFIG": "/tmp/empty"})
        self.assertEqual(seen.get("DOCKER_CONFIG"), "/tmp/empty")

    def test_the_command_is_a_list_and_never_a_shell_string(self):
        completed = ExternalScanner._run(
            [sys.executable, "-c", "print('ok')"], cwd=os.getcwd(), timeout=30
        )
        self.assertEqual(completed.stdout.decode("utf-8").strip(), "ok")
        self.assertEqual(completed.returncode, 0)


class TheBaseClass(RepoTestCase):
    def test_a_wrapper_must_supply_its_own_command(self):
        with self.assertRaises(NotImplementedError):
            ExternalScanner().command(RepositoryBoundary(self.repo.root), [])

    def test_a_wrapper_must_supply_its_own_parser(self):
        with self.assertRaises(NotImplementedError):
            ExternalScanner().parse("{}", RepositoryBoundary(self.repo.root))

    def test_a_setting_falls_back_to_its_default_without_a_config(self):
        self.assertEqual(ExternalScanner().setting("scanners.semgrep_config", "none"), "none")

    def test_a_setting_is_read_from_the_config_when_there_is_one(self):
        scanner = ExternalScanner(Config.defaults())
        self.assertEqual(scanner.setting("scanners.semgrep_config", "none"), "")

    def test_most_wrappers_add_nothing_to_the_environment(self):
        self.assertEqual(ExternalScanner().environment(), {})

    def test_the_version_is_empty_when_the_program_is_absent(self):
        scanner = ExternalScanner()
        scanner.binary = "no-such-program-jscr"
        self.assertEqual(scanner.version(), "")

    def test_the_version_is_the_first_line_the_program_printed(self):
        class Versioned(ExternalScanner):
            binary = "fake"

            @staticmethod
            def _run(argv, cwd, timeout, extra_environment=None):
                return Completed(stdout=b"fake 2.1\nbuilt from source\n")

        self.assertEqual(Versioned().version(), "fake 2.1")

    def test_a_program_that_prints_nothing_has_no_version(self):
        class Silent(ExternalScanner):
            binary = "fake"

            @staticmethod
            def _run(argv, cwd, timeout, extra_environment=None):
                return Completed(stdout=b"")

        self.assertEqual(Silent().version(), "")

    def test_installed_asks_the_path_for_the_binary(self):
        scanner = ExternalScanner()
        scanner.binary = "no-such-program-jscr"
        self.assertFalse(scanner.installed())


class TrivyGetsAnEmptyDockerConfig(unittest.TestCase):
    """A stale credential helper in the real config makes trivy exit 1."""

    def test_the_directory_is_new_and_empty(self):
        directory = TrivyScanner().environment()["DOCKER_CONFIG"]
        self.addCleanup(os.rmdir, directory)
        self.assertTrue(os.path.isdir(directory))
        self.assertEqual(os.listdir(directory), [])

    def test_the_command_scans_the_filesystem_offline(self):
        argv = TrivyScanner().command(None, [])
        self.assertIn("--offline-scan", argv)
        self.assertIn("filesystem", argv)


class TrivyMisconfigurations(RepoTestCase):
    def test_a_misconfiguration_becomes_a_finding(self):
        payload = json.dumps(
            {
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Misconfigurations": [
                            {
                                "ID": "DS002",
                                "Title": "Image runs as root",
                                "Description": "Specify a user",
                                "Severity": "HIGH",
                                "Resolution": "Add a USER instruction",
                                "CauseMetadata": {"StartLine": 3},
                            }
                        ],
                    }
                ]
            }
        )
        self.repo.write("Dockerfile", "FROM x\nRUN y\nCMD z\n")
        boundary = RepositoryBoundary(self.repo.root)
        finding = TrivyScanner(Config.defaults()).parse(payload, boundary)[0]
        self.assertEqual((finding.line, finding.rule_id), (3, "DS002"))
        self.assertEqual(finding.recommendation, "Add a USER instruction")


class FindingWhereAPackageIsNamed(RepoTestCase):
    def boundary(self):
        return RepositoryBoundary(self.repo.root)

    def test_an_empty_path_gives_an_empty_index(self):
        self.assertEqual(_package_lines(self.boundary(), ""), {})

    def test_a_file_that_cannot_be_read_gives_an_empty_index(self):
        self.assertEqual(_package_lines(self.boundary(), "gone.json"), {})

    def test_the_installed_entry_is_preferred_over_the_declared_range(self):
        self.repo.write(
            "package-lock.json",
            '{\n  "packages": {\n    "": { "dependencies": { "left-pad": "^1.0.0" } },\n'
            '    "node_modules/left-pad": { "version": "1.3.0" }\n  }\n}\n',
        )
        index = _package_lines(self.boundary(), "package-lock.json")
        self.assertEqual(index["left-pad"][0], 4)

    def test_the_declared_range_does_not_displace_the_installed_entry(self):
        self.repo.write(
            "package-lock.json",
            '{\n  "packages": {\n    "node_modules/left-pad": { "version": "1.3.0" },\n'
            '    "": { "dependencies": { "left-pad": "^1.0.0" } }\n  }\n}\n',
        )
        index = _package_lines(self.boundary(), "package-lock.json")
        self.assertEqual(index["left-pad"][0], 3)


class ReadingASourceLine(RepoTestCase):
    def boundary(self):
        return RepositoryBoundary(self.repo.root)

    def test_the_line_is_the_files_own_text(self):
        self.repo.write("a.py", "one\ntwo\nthree\n")
        self.assertEqual(_source_line(self.boundary(), "a.py", 2), "two")

    def test_a_line_past_the_end_of_the_file_is_empty(self):
        self.repo.write("a.py", "one\n")
        self.assertEqual(_source_line(self.boundary(), "a.py", 9), "")

    def test_a_line_number_of_zero_is_empty(self):
        self.repo.write("a.py", "one\n")
        self.assertEqual(_source_line(self.boundary(), "a.py", 0), "")

    def test_no_path_is_empty(self):
        self.assertEqual(_source_line(self.boundary(), "", 1), "")


class TheReportFileHelpers(unittest.TestCase):
    def test_a_report_path_is_created_and_can_be_read_back(self):
        path = _report_path()
        self.addCleanup(_discard, path)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("[]")
        self.assertEqual(_read_report(path), "[]")

    def test_reading_a_missing_report_gives_an_empty_string(self):
        self.assertEqual(_read_report("/no/such/jscr-report.json"), "")

    def test_discarding_removes_the_file(self):
        path = _report_path()
        _discard(path)
        self.assertFalse(os.path.exists(path))

    def test_discarding_nothing_is_not_an_error(self):
        self.assertIsNone(_discard(None))

    def test_discarding_a_missing_file_is_not_an_error(self):
        self.assertIsNone(_discard("/no/such/jscr-report.json"))


class ReadingScannerJson(unittest.TestCase):
    def test_empty_output_is_an_empty_object(self):
        self.assertEqual(_json(""), {})

    def test_empty_output_is_an_empty_list_when_a_list_is_expected(self):
        self.assertEqual(_json("", default_list=True), [])

    def test_valid_json_is_returned(self):
        self.assertEqual(_json('{"a": 1}'), {"a": 1})

    def test_malformed_json_raises_so_the_run_is_reported_not_silent(self):
        with self.assertRaises(ValueError):
            _json("{oh no")


class MakingAPathRelative(RepoTestCase):
    def boundary(self):
        return RepositoryBoundary(self.repo.root)

    def test_a_path_inside_the_repository_comes_back_relative(self):
        self.repo.write("app/main.py", "x = 1\n")
        absolute = os.path.join(self.repo.root, "app/main.py")
        self.assertEqual(_relative(absolute, self.boundary()), "app/main.py")

    def test_a_path_outside_the_repository_is_not_made_to_look_inside_it(self):
        # The boundary refuses to resolve it, so the fallback drops the
        # leading separator rather than claiming a path in the repository.
        self.assertEqual(_relative("/etc/hosts", self.boundary()), "etc/hosts")

    def test_an_empty_path_stays_empty(self):
        self.assertEqual(_relative("", self.boundary()), "")


class ReadingMetadata(unittest.TestCase):
    def test_the_first_cwe_of_a_list_is_taken(self):
        self.assertEqual(_first_cwe(["CWE-79", "CWE-80"]), "CWE-79")

    def test_a_single_cwe_string_is_taken_as_it_is(self):
        self.assertEqual(_first_cwe("CWE-89"), "CWE-89")

    def test_a_missing_cwe_is_empty(self):
        self.assertEqual(_first_cwe(None), "")

    def test_an_empty_list_is_empty(self):
        self.assertEqual(_first_cwe([]), "")

    def test_the_named_confidence_levels_map_to_numbers(self):
        self.assertEqual(_confidence("HIGH", 0.75), 0.9)
        self.assertEqual(_confidence("medium", 0.75), 0.7)
        self.assertEqual(_confidence("Low", 0.75), 0.5)

    def test_an_unknown_level_falls_back(self):
        self.assertEqual(_confidence("SEVERE", 0.75), 0.75)

    def test_a_level_that_is_not_a_string_falls_back(self):
        self.assertEqual(_confidence(None, 0.6), 0.6)
