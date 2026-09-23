"""The command line, including the exit codes CI depends on."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from jscr.cli import EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK, EXIT_UNUSABLE, main
from jscr.config import CONFIG_FILENAME

from .support import RepoTestCase

VULNERABLE = 'import os\n\n\ndef go(name):\n    os.system("echo " + name)\n'


class Cli(RepoTestCase):
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


class ExitCodes(Cli):
    def test_findings_exit_one(self):
        self.stage_a_vulnerability()
        code, _out, _err = self.run_cli("review", "--repo", self.repo.root, "--staged")
        self.assertEqual(code, EXIT_FINDINGS)

    def test_all_finds_a_defect_that_is_already_committed(self):
        """Nothing is staged, so only --all can see it."""
        self.repo.write("app.py", VULNERABLE)
        self.repo.commit("only")
        code, _out, _err = self.run_cli("review", "--repo", self.repo.root, "--staged")
        self.assertEqual(code, EXIT_OK)
        code, out, _err = self.run_cli("review", "--repo", self.repo.root, "--all")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("every tracked file at HEAD", out)

    def test_commit_reviews_a_first_commit(self):
        """A root commit has no parent; --commit still reviews what it adds."""
        self.repo.write("app.py", VULNERABLE)
        self.repo.commit("only")
        code, out, err = self.run_cli("review", "--repo", self.repo.root, "--commit", "HEAD")
        self.assertEqual(code, EXIT_FINDINGS, err)
        self.assertIn("commit HEAD (first commit", out)
        self.assertNotIn("HEAD^", out)

    def test_all_refuses_to_be_mixed_with_another_target(self):
        self.stage_a_vulnerability()
        code, _out, err = self.run_cli("review", "--repo", self.repo.root, "--all", "--staged")
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("--all", err)

    def test_a_high_bar_can_pass(self):
        self.stage_a_vulnerability()
        code, _out, _err = self.run_cli(
            "review", "--repo", self.repo.root, "--staged", "--fail-on", "Critical"
        )
        self.assertEqual(code, EXIT_OK)

    def test_an_incomplete_review_is_not_reported_as_clean(self):
        """A pipeline must never read 'the model was unreachable' as 'no issues'."""
        self.stage_a_vulnerability()
        code, _out, _err = self.run_cli(
            "review",
            "--repo",
            self.repo.root,
            "--staged",
            "--fail-on",
            "Critical",
            "--set",
            "provider.name=anthropic",
        )
        self.assertEqual(code, EXIT_INCOMPLETE)

    def test_a_bad_setting_is_unusable_not_a_clean_run(self):
        code, _out, err = self.run_cli(
            "review", "--repo", self.repo.root, "--staged", "--set", "egres.enabled=true"
        )
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("unknown setting", err)

    def test_no_subcommand_prints_help(self):
        code, out, _err = self.run_cli()
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("jscr", out)


class Formats(Cli):
    def test_json_output_parses(self):
        self.stage_a_vulnerability()
        _code, out, _err = self.run_cli(
            "review", "--repo", self.repo.root, "--staged", "--format", "json"
        )
        self.assertIn("findings", json.loads(out))

    def test_sarif_output_parses(self):
        self.stage_a_vulnerability()
        _code, out, _err = self.run_cli(
            "review", "--repo", self.repo.root, "--staged", "--format", "sarif"
        )
        self.assertEqual(json.loads(out)["version"], "2.1.0")

    def test_output_to_a_file(self):
        self.stage_a_vulnerability()
        path = os.path.join(self.repo.root, "report.json")
        self.run_cli(
            "review", "--repo", self.repo.root, "--staged", "--format", "json", "--output", path
        )
        with open(path, encoding="utf-8") as handle:
            self.assertIn("findings", json.load(handle))


class OtherCommands(Cli):
    def test_init_writes_a_closed_configuration(self):
        code, out, _err = self.run_cli("init", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Egress is closed", out)
        with open(os.path.join(self.repo.root, CONFIG_FILENAME), encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertFalse(data["egress"]["enabled"])

    def test_init_refuses_to_overwrite_without_force(self):
        self.run_cli("init", "--repo", self.repo.root)
        code, _out, err = self.run_cli("init", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("--force", err)

    def test_config_prints_one_key(self):
        _code, out, _err = self.run_cli("config", "--repo", self.repo.root, "egress.enabled")
        self.assertEqual(json.loads(out), False)

    def test_config_rejects_an_unknown_key(self):
        code, _out, _err = self.run_cli("config", "--repo", self.repo.root, "egress.enable")
        self.assertEqual(code, EXIT_UNUSABLE)

    def test_policy_reports_the_closed_defaults(self):
        _code, out, _err = self.run_cli("policy", "--repo", self.repo.root)
        self.assertIn("deny", out)
        self.assertIn("net.connect", out)

    def test_policy_json(self):
        _code, out, _err = self.run_cli("policy", "--repo", self.repo.root, "--json")
        rows = json.loads(out)
        actions = {row["action"]: row["allowed"] for row in rows}
        self.assertFalse(actions["net.connect"])

    def test_doctor_states_that_nothing_is_sent(self):
        _code, out, _err = self.run_cli("doctor", "--repo", self.repo.root)
        self.assertIn("sends no usage data", out)
        self.assertIn("Telemetry", out)


if __name__ == "__main__":
    unittest.main()


class TheSbomCommand(Cli):
    def declare_a_dependency(self):
        self.repo.write("package.json", json.dumps({"name": "app", "dependencies": {"left": "1"}}))

    def test_it_writes_a_cyclonedx_document_to_stdout(self):
        self.declare_a_dependency()
        code, out, _err = self.run_cli("sbom", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["bomFormat"], "CycloneDX")

    def test_a_declared_dependency_is_a_component(self):
        self.declare_a_dependency()
        _code, out, _err = self.run_cli("sbom", "--repo", self.repo.root)
        names = [c.get("name") for c in json.loads(out)["components"]]
        self.assertIn("left", names)

    def test_the_root_component_can_be_named(self):
        self.declare_a_dependency()
        _code, out, _err = self.run_cli("sbom", "--repo", self.repo.root, "--project", "given-name")
        self.assertEqual(json.loads(out)["metadata"]["component"]["name"], "given-name")

    def test_the_root_component_version_can_be_given(self):
        self.declare_a_dependency()
        _code, out, _err = self.run_cli(
            "sbom", "--repo", self.repo.root, "--project-version", "2.1.0"
        )
        self.assertEqual(json.loads(out)["metadata"]["component"]["version"], "2.1.0")

    def test_an_output_path_is_written_instead_of_stdout(self):
        self.declare_a_dependency()
        path = os.path.join(self.repo.root, "sbom.json")
        code, out, err = self.run_cli("sbom", "--repo", self.repo.root, "--output", path)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "")
        self.assertIn("wrote", err)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["bomFormat"], "CycloneDX")

    def test_declaring_nothing_is_reported_but_is_not_a_failure(self):
        # A repository can genuinely declare no dependencies. The
        # difference is on stderr so a pipeline can tell the two apart.
        code, out, err = self.run_cli("sbom", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["components"], [])
        self.assertIn("no dependency manifest", err)


class TheConfigCommand(Cli):
    def test_with_no_key_it_prints_the_whole_configuration(self):
        code, out, _err = self.run_cli("config", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("provider", json.loads(out))

    def test_a_named_configuration_file_is_read(self):
        path = os.path.join(self.repo.root, "elsewhere.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "provider": {"model": "from-the-named-file"}}, handle)
        _code, out, _err = self.run_cli("config", "--repo", self.repo.root, "--config", path)
        self.assertEqual(json.loads(out)["provider"]["model"], "from-the-named-file")

    def test_a_set_without_an_equals_sign_is_refused(self):
        code, _out, err = self.run_cli("config", "--repo", self.repo.root, "--set", "provider.name")
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("key=value", err)


class TheDoctorCommand(Cli):
    def test_it_says_whether_the_key_variable_is_set(self):
        os.environ["JSCR_DOCTOR_TEST_KEY"] = "present"
        self.addCleanup(os.environ.pop, "JSCR_DOCTOR_TEST_KEY", None)
        _code, out, _err = self.run_cli(
            "doctor",
            "--repo",
            self.repo.root,
            "--set",
            "provider.api_key_env=JSCR_DOCTOR_TEST_KEY",
        )
        self.assertIn("JSCR_DOCTOR_TEST_KEY (set)", out)

    def test_a_variable_that_is_not_set_is_reported_as_not_set(self):
        os.environ.pop("JSCR_DOCTOR_MISSING_KEY", None)
        _code, out, _err = self.run_cli(
            "doctor",
            "--repo",
            self.repo.root,
            "--set",
            "provider.api_key_env=JSCR_DOCTOR_MISSING_KEY",
        )
        self.assertIn("NOT set", out)

    def test_the_key_itself_is_never_printed(self):
        os.environ["JSCR_DOCTOR_TEST_KEY"] = "a-secret-value"
        self.addCleanup(os.environ.pop, "JSCR_DOCTOR_TEST_KEY", None)
        _code, out, _err = self.run_cli(
            "doctor",
            "--repo",
            self.repo.root,
            "--set",
            "provider.api_key_env=JSCR_DOCTOR_TEST_KEY",
        )
        self.assertNotIn("a-secret-value", out)

    def test_git_being_unusable_is_reported_rather_than_crashing(self):
        from jscr import cli as cli_module
        from jscr.errors import JscrError

        def refuse(_boundary):
            raise JscrError("git executable not found")

        real = cli_module.Git
        cli_module.Git = refuse
        self.addCleanup(setattr, cli_module, "Git", real)
        code, out, _err = self.run_cli("doctor", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("unavailable: git executable not found", out)


class HowFailuresLeaveTheProcess(Cli):
    def test_a_policy_refusal_exits_unusable_and_says_denied(self):
        from jscr import cli as cli_module
        from jscr.errors import PolicyDenied

        def refuse(_args):
            raise PolicyDenied("provider.use", "provider 'x' is not a provider JSCR knows")

        real = cli_module.cmd_config
        cli_module.cmd_config = refuse
        self.addCleanup(setattr, cli_module, "cmd_config", real)
        code, _out, err = self.run_cli("config", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("denied:", err)

    def test_a_provider_that_cannot_be_built_does_not_fall_back_to_another(self):
        # The review still runs deterministically, and the report says the
        # AI pass did not happen rather than quietly using something else.
        self.stage_a_vulnerability()
        path = os.path.join(self.repo.root, "report.json")
        self.run_cli(
            "review",
            "--repo",
            self.repo.root,
            "--staged",
            "--set",
            "provider.name=not-a-provider",
            "--format",
            "json",
            "--output",
            path,
        )
        with open(path, encoding="utf-8") as handle:
            report = json.load(handle)
        self.assertIsNone(report["provider"]["used"])
        self.assertTrue(any("provider unavailable" in e for e in report["errors"]))

    def test_an_interruption_is_reported_rather_than_a_traceback(self):
        from jscr import cli as cli_module

        def interrupt(_args):
            raise KeyboardInterrupt

        real = cli_module.cmd_config
        cli_module.cmd_config = interrupt
        self.addCleanup(setattr, cli_module, "cmd_config", real)
        code, _out, err = self.run_cli("config", "--repo", self.repo.root)
        self.assertEqual(code, EXIT_UNUSABLE)
        self.assertIn("interrupted", err)


class TheProvenanceLog(Cli):
    def log(self, run, output_path):
        from jscr.cli import _log_provenance

        class _Result(object):
            pass

        result = _Result()
        result.run = run
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            _log_provenance(output_path, result)
        return err.getvalue()

    def test_a_run_that_recorded_nothing_writes_no_line(self):
        report = os.path.join(self.repo.root, "report.json")
        self.assertEqual(self.log({}, report), "")
        self.assertFalse(os.path.exists(os.path.join(self.repo.root, "provenance.jsonl")))

    def test_a_run_is_appended_beside_the_report(self):
        report = os.path.join(self.repo.root, "report.json")
        with open(report, "w", encoding="utf-8") as handle:
            handle.write("{}")
        err = self.log({"started": "now"}, report)
        self.assertIn("provenance appended", err)
        with open(os.path.join(self.repo.root, "provenance.jsonl"), encoding="utf-8") as handle:
            self.assertEqual(json.loads(handle.readline())["report"], report)

    def test_a_log_that_cannot_be_written_is_reported_and_never_fails_the_review(self):
        # The review already happened; losing the log entry must not
        # change its outcome.
        directory = os.path.join(self.repo.root, "not-a-directory")
        with open(directory, "w", encoding="utf-8") as handle:
            handle.write("a file where the directory would be")
        err = self.log({"started": "now"}, os.path.join(directory, "report.json"))
        self.assertIn("provenance log not written", err)
