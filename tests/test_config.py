"""The configuration schema is closed, and that is a security control."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from jscr.config import CONFIG_FILENAME, Config, config_keys, default_config_json
from jscr.errors import ConfigError

from .support import config


class DefaultsAreClosed(unittest.TestCase):
    def test_egress_is_off_by_default(self):
        self.assertFalse(Config.defaults().get("egress.enabled"))

    def test_no_hosts_allowed_by_default(self):
        self.assertEqual(Config.defaults().get("egress.allow_hosts"), [])

    def test_private_addresses_refused_by_default(self):
        self.assertFalse(Config.defaults().get("egress.allow_private_addresses"))

    def test_redirects_refused_by_default(self):
        self.assertFalse(Config.defaults().get("egress.allow_redirects"))

    def test_repository_code_is_not_executed_by_default(self):
        self.assertFalse(Config.defaults().get("execution.allow_repository_code"))
        self.assertFalse(Config.defaults().get("execution.allow_repository_hooks"))

    def test_symlinks_are_not_followed_by_default(self):
        self.assertFalse(Config.defaults().get("repository.follow_symlinks"))

    def test_no_tools_allowed_by_default(self):
        self.assertEqual(Config.defaults().get("tools.allow"), [])

    def test_telemetry_and_updates_are_off_by_default(self):
        self.assertFalse(Config.defaults().get("telemetry.enabled"))
        self.assertFalse(Config.defaults().get("update.check"))

    def test_every_external_scanner_is_off_by_default(self):
        for name in ("semgrep", "gitleaks", "trivy"):
            self.assertFalse(Config.defaults().get("scanners.{0}".format(name)), name)

    def test_provider_is_null_by_default(self):
        self.assertEqual(Config.defaults().get("provider.name"), "null")

    def test_the_written_default_file_is_the_closed_one(self):
        data = json.loads(default_config_json())
        self.assertFalse(data["egress"]["enabled"])
        self.assertEqual(data["provider"]["name"], "null")


class UnknownKeysAreRefused(unittest.TestCase):
    """A misspelled security setting must fail, never be quietly ignored.

    The failure mode this prevents: an operator writes "egres" and believes
    they opened egress, or believes they closed it. Either way the file no
    longer describes what the tool does.
    """

    def _load(self, payload):
        handle, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        self.addCleanup(os.unlink, path)
        return Config.load(path)

    def test_misspelled_section_is_an_error(self):
        with self.assertRaises(ConfigError) as caught:
            self._load({"egres": {"enabled": True}})
        self.assertIn("egres", str(caught.exception))

    def test_misspelled_key_is_an_error(self):
        with self.assertRaises(ConfigError):
            self._load({"egress": {"enable": True}})

    def test_unknown_scanner_is_an_error(self):
        with self.assertRaises(ConfigError):
            self._load({"scanners": {"not_a_scanner": True}})

    def test_invalid_json_is_an_error_not_a_silent_default(self):
        handle, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            fh.write("{ not json")
        self.addCleanup(os.unlink, path)
        with self.assertRaises(ConfigError):
            Config.load(path)

    def test_a_named_missing_file_is_an_error(self):
        with self.assertRaises(ConfigError):
            Config.load(os.path.join(tempfile.gettempdir(), "no-such-jscr.json"))

    def test_override_refuses_unknown_keys_too(self):
        cfg = Config.defaults()
        with self.assertRaises(ConfigError):
            cfg.override("egres.enabled", True)


class Validation(unittest.TestCase):
    def test_egress_on_with_no_hosts_is_refused(self):
        with self.assertRaises(ConfigError):
            config(egress__enabled=True)

    def test_egress_on_with_a_host_is_accepted(self):
        cfg = Config.defaults()
        cfg.override("egress.allow_hosts", ["api.example.com"])
        cfg.override("egress.enabled", True)
        self.assertTrue(cfg.get("egress.enabled"))


class Keys(unittest.TestCase):
    def test_key_list_is_stable(self):
        keys = config_keys()
        self.assertIn("egress.enabled", keys)
        self.assertIn("provider.api_key_env", keys)
        self.assertEqual(len(keys), len(set(keys)))

    def test_filename(self):
        self.assertEqual(CONFIG_FILENAME, ".jscr.json")
