"""The Claude CLI provider.

No test here starts the real CLI. Each one replaces ``subprocess.run`` and
checks the argument list JSCR builds and the envelope it reads back, which
is the part JSCR is responsible for.
"""

from __future__ import annotations

import json
import unittest

from jscr.config import Config
from jscr.errors import ProviderError
from jscr.providers import claude_cli
from jscr.providers.claude_cli import ClaudeCliProvider


class _Completed(object):
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _envelope(**overrides):
    body = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": '{"findings": []}',
        "stop_reason": "end_turn",
        "session_id": "s-1",
        "total_cost_usd": 0.5,
        "usage": {
            "input_tokens": 10,
            "cache_creation_input_tokens": 200,
            "cache_read_input_tokens": 30,
            "output_tokens": 7,
        },
    }
    body.update(overrides)
    return json.dumps(body).encode("utf-8")


class _Recorder(object):
    """Stands in for subprocess.run and remembers how it was called."""

    def __init__(self, completed):
        self.completed = completed
        self.argv = None
        self.kwargs = None

    def __call__(self, argv, **kwargs):
        self.argv = list(argv)
        self.kwargs = kwargs
        return self.completed


def _provider(**settings):
    values = {"provider": {"model": "claude-opus-5"}}
    values["provider"].update(settings)
    return ClaudeCliProvider(Config(values))


class TheCommandJscrBuilds(unittest.TestCase):
    def setUp(self):
        self.real = claude_cli.subprocess.run
        self.recorder = _Recorder(_Completed(stdout=_envelope()))
        claude_cli.subprocess.run = self.recorder

    def tearDown(self):
        claude_cli.subprocess.run = self.real

    def test_it_asks_for_the_json_envelope_and_names_the_model(self):
        _provider().complete("be careful", "review this")
        self.assertIn("--print", self.recorder.argv)
        self.assertEqual(
            ["--output-format", "json"],
            self.recorder.argv[2:4],
        )
        self.assertIn("--model", self.recorder.argv)
        self.assertIn("claude-opus-5", self.recorder.argv)

    def test_the_child_gets_no_mcp_servers_and_no_tools(self):
        _provider().complete("s", "u")
        self.assertIn("--strict-mcp-config", self.recorder.argv)
        self.assertIn("--disallowed-tools", self.recorder.argv)
        for tool in ("Bash", "Read", "WebFetch", "Task"):
            self.assertIn(tool, self.recorder.argv)

    def test_the_prompt_goes_on_stdin_never_on_the_command_line(self):
        _provider().complete("system text", "the whole bundle")
        self.assertEqual(b"the whole bundle", self.recorder.kwargs["input"])
        self.assertNotIn("the whole bundle", self.recorder.argv)

    def test_the_system_prompt_replaces_the_cli_own(self):
        # Appending left the CLI's conversational prompt in place, and the
        # model answered in prose where the reviewer prompt asked for JSON.
        _provider().complete("system text", "u")
        self.assertIn("--system-prompt", self.recorder.argv)
        self.assertNotIn("--append-system-prompt", self.recorder.argv)
        self.assertIn("system text", self.recorder.argv)

    def test_a_schema_is_passed_to_the_cli_as_a_constraint(self):
        schema = {"type": "object", "properties": {"findings": {"type": "array"}}}
        _provider().complete("s", "u", json_schema=schema)
        self.assertIn("--json-schema", self.recorder.argv)
        sent = self.recorder.argv[self.recorder.argv.index("--json-schema") + 1]
        self.assertEqual(schema, json.loads(sent))

    def test_no_schema_flag_when_the_caller_asks_for_no_shape(self):
        _provider().complete("s", "u")
        self.assertNotIn("--json-schema", self.recorder.argv)

    def test_it_never_runs_a_shell_and_never_starts_in_the_repository(self):
        _provider().complete("s", "u")
        self.assertIs(False, self.recorder.kwargs["shell"])
        self.assertIn("jscr-claude-cli-", self.recorder.kwargs["cwd"])

    def test_the_binary_is_configurable(self):
        _provider(cli_binary="/opt/claude").complete("s", "u")
        self.assertEqual("/opt/claude", self.recorder.argv[0])


class WhatItReadsBack(unittest.TestCase):
    def setUp(self):
        self.real = claude_cli.subprocess.run

    def tearDown(self):
        claude_cli.subprocess.run = self.real

    def _answer(self, completed):
        claude_cli.subprocess.run = _Recorder(completed)
        return _provider().complete("s", "u")

    def test_cached_input_is_counted_as_input(self):
        completion = self._answer(_Completed(stdout=_envelope()))
        # 10 fresh + 200 cache creation + 30 cache read.
        self.assertEqual(240, completion.input_tokens)
        self.assertEqual(7, completion.output_tokens)

    def test_the_result_text_is_the_completion(self):
        completion = self._answer(_Completed(stdout=_envelope()))
        self.assertEqual('{"findings": []}', completion.text)
        self.assertEqual("claude-opus-5", completion.model)

    def test_a_finished_answer_survives_a_non_zero_exit(self):
        # The CLI's own teardown can fail after the answer is produced.
        # Throwing it away would cost a second run and report nothing true.
        completed = _Completed(returncode=1, stdout=_envelope(), stderr=b"SessionEnd hook failed")
        self.assertEqual('{"findings": []}', self._answer(completed).text)

    def test_an_error_envelope_is_an_error_whatever_the_exit_code_says(self):
        completed = _Completed(
            returncode=0,
            stdout=_envelope(is_error=True, result="Not logged in"),
        )
        with self.assertRaises(ProviderError) as caught:
            self._answer(completed)
        self.assertIn("Not logged in", str(caught.exception))

    def test_output_that_is_not_the_promised_envelope_is_an_error(self):
        completed = _Completed(returncode=1, stdout=b"command not found", stderr=b"boom")
        with self.assertRaises(ProviderError) as caught:
            self._answer(completed)
        self.assertIn("boom", str(caught.exception))

    def test_an_empty_result_is_an_error_not_an_empty_finding_set(self):
        completed = _Completed(stdout=_envelope(result="   "))
        with self.assertRaises(ProviderError):
            self._answer(completed)

    def test_a_missing_binary_says_which_setting_names_it(self):
        def missing(argv, **kwargs):
            raise OSError()

        class _NotFound(Exception):
            pass

        def raiser(argv, **kwargs):
            raise FileNotFoundError()

        claude_cli.subprocess.run = raiser
        with self.assertRaises(ProviderError) as caught:
            _provider().complete("s", "u")
        self.assertIn("provider.cli_binary", str(caught.exception))
        del missing, _NotFound


class WhatItTellsTheOperator(unittest.TestCase):
    def test_describe_admits_the_allowlist_is_not_enforced(self):
        described = _provider().describe()
        self.assertIs(False, described["egress_allowlist_enforced"])
        self.assertIn("no API key", described["credential"])

    def test_it_reports_itself_as_opening_no_socket(self):
        self.assertIs(False, ClaudeCliProvider.requires_network)


if __name__ == "__main__":
    unittest.main()
