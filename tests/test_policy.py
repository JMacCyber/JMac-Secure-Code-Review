"""The policy layer is the only thing that decides what is possible."""

from __future__ import annotations

import unittest

from jscr.config import Config
from jscr.errors import PolicyDenied
from jscr.policy import (
    EXEC_RUN,
    FS_READ,
    NET_CONNECT,
    PERSIST_WRITE,
    PROVIDER_USE,
    TELEMETRY_SEND,
    TOOL_CALL,
    UPDATE_CHECK,
    Policy,
)

from .support import config


class ShippedDefaultsDenyEverything(unittest.TestCase):
    """With no configuration, the only thing permitted is reading the repository."""

    def setUp(self):
        self.policy = Policy(Config.defaults())

    def test_reading_the_repository_is_allowed(self):
        self.assertTrue(self.policy.allows(FS_READ, "app.py"))

    def test_network_is_denied(self):
        self.assertFalse(self.policy.allows(NET_CONNECT, "api.example.com:443"))

    def test_execution_is_denied(self):
        self.assertFalse(self.policy.allows(EXEC_RUN, "npm test"))

    def test_tools_are_denied(self):
        self.assertFalse(self.policy.allows(TOOL_CALL, "anything"))

    def test_persistence_beyond_metadata_is_denied(self):
        self.assertFalse(self.policy.allows(PERSIST_WRITE, "source code"))

    def test_telemetry_is_denied(self):
        self.assertFalse(self.policy.allows(TELEMETRY_SEND, "usage"))

    def test_update_checks_are_denied(self):
        self.assertFalse(self.policy.allows(UPDATE_CHECK, "releases"))

    def test_every_scanner_is_denied_until_switched_on(self):
        for name in ("semgrep", "gitleaks", "trivy"):
            self.assertFalse(self.policy.allows(EXEC_RUN, name), name)


class RunningAScannerIsNotRunningRepositoryCode(unittest.TestCase):
    """Two different questions share one action, and get different answers."""

    def test_an_enabled_scanner_is_allowed(self):
        policy = Policy(config(scanners__semgrep=True))
        self.assertTrue(policy.allows(EXEC_RUN, "semgrep"))

    def test_enabling_a_scanner_does_not_permit_repository_code(self):
        policy = Policy(config(scanners__semgrep=True))
        self.assertFalse(policy.allows(EXEC_RUN, "npm test"))

    def test_allowing_repository_code_does_not_enable_a_disabled_scanner(self):
        policy = Policy(config(execution__allow_repository_code=True))
        self.assertFalse(policy.allows(EXEC_RUN, "semgrep"))


class NetworkRules(unittest.TestCase):
    def policy(self, hosts, **extra):
        cfg = Config.defaults()
        cfg.override("egress.allow_hosts", hosts)
        cfg.override("egress.enabled", True)
        for key, value in extra.items():
            cfg.override(key.replace("__", "."), value)
        return Policy(cfg)

    def test_a_listed_host_is_allowed(self):
        self.assertTrue(self.policy(["api.example.com"]).allows(NET_CONNECT, "api.example.com:443"))

    def test_an_unlisted_host_is_denied(self):
        self.assertFalse(self.policy(["api.example.com"]).allows(NET_CONNECT, "evil.test:443"))

    def test_a_wildcard_covers_one_label(self):
        policy = self.policy(["*.example.com"])
        self.assertTrue(policy.allows(NET_CONNECT, "api.example.com:443"))
        self.assertFalse(policy.allows(NET_CONNECT, "example.com:443"))

    def test_a_bare_star_allows_nothing(self):
        self.assertFalse(self.policy(["*"]).allows(NET_CONNECT, "anything.test:443"))

    def test_an_unlisted_port_is_denied(self):
        self.assertFalse(
            self.policy(["api.example.com"]).allows(NET_CONNECT, "api.example.com:8080")
        )

    def test_host_matching_is_case_insensitive(self):
        self.assertTrue(self.policy(["api.example.com"]).allows(NET_CONNECT, "API.Example.COM:443"))


class ProviderRules(unittest.TestCase):
    def test_the_null_provider_needs_nothing(self):
        self.assertTrue(Policy(Config.defaults()).allows(PROVIDER_USE, "null"))

    def test_a_network_provider_is_denied_while_egress_is_closed(self):
        policy = Policy(config(provider__name="anthropic"))
        decision = policy.check(PROVIDER_USE, "anthropic")
        self.assertFalse(decision.allowed)
        self.assertIn("egress", decision.reason)

    def test_an_unknown_provider_is_denied_rather_than_guessed(self):
        policy = Policy(config(provider__name="something-else"))
        self.assertFalse(policy.allows(PROVIDER_USE, "something-else"))


class TheAuditTrail(unittest.TestCase):
    def test_every_decision_is_recorded(self):
        policy = Policy(Config.defaults())
        policy.allows(NET_CONNECT, "a.test:443")
        policy.allows(FS_READ, "app.py")
        self.assertEqual(policy.summary()["decisions"], 2)

    def test_denials_are_reported_with_their_reason(self):
        policy = Policy(Config.defaults())
        policy.allows(NET_CONNECT, "a.test:443")
        denials = policy.summary()["denied"]
        self.assertEqual(len(denials), 1)
        self.assertIn("egress.enabled is false", denials[0]["reason"])

    def test_require_raises_rather_than_returning_false(self):
        with self.assertRaises(PolicyDenied):
            Policy(Config.defaults()).require(NET_CONNECT, "a.test:443")

    def test_explain_answers_before_anything_runs(self):
        rows = Policy(Config.defaults()).explain()
        actions = {row["action"]: row["allowed"] for row in rows}
        self.assertTrue(actions[FS_READ])
        self.assertFalse(actions[NET_CONNECT])
        self.assertFalse(actions[TELEMETRY_SEND])
        for row in rows:
            self.assertTrue(row["reason"], row["action"])

    def test_an_unknown_action_is_denied_not_allowed(self):
        policy = Policy(Config.defaults())
        self.assertFalse(policy.allows("some.future.action", "x"))


if __name__ == "__main__":
    unittest.main()
