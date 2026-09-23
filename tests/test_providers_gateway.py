"""The provider gateway.

The gateway has one job and one rule: build the provider configuration
names, and never a different one. These tests are mostly about the refusals,
because a silent fallback is the failure this module exists to prevent.

No provider built here is ever asked to complete anything, so nothing here
reaches the network.
"""

from __future__ import annotations

import os
import unittest

from jscr.egress.guard import EgressGuard
from jscr.errors import PolicyDenied, ProviderError
from jscr.policy import Policy
from jscr.providers.anthropic import AnthropicProvider
from jscr.providers.claude_cli import ClaudeCliProvider
from jscr.providers.gateway import Gateway
from jscr.providers.null import NullProvider
from jscr.providers.openai_compatible import OpenAICompatibleProvider

from .support import config, fake_model_key

HOST = "models.example.com"
ENDPOINT = "https://" + HOST + "/v1/chat/completions"
KEY_VARIABLE = "JSCR_TEST_PROVIDER_KEY"


class GatewayCase(unittest.TestCase):
    def gateway(self, **overrides):
        # Order matters: the config validates on every override, so the
        # host is named before egress is switched on.
        settings = {
            "egress__allow_hosts": [HOST, "api.anthropic.com"],
            "egress__allow_ports": [443],
        }
        settings.update(overrides)
        cfg = config(**settings)
        return Gateway(Policy(cfg), EgressGuard(Policy(cfg)))

    def networked(self, **overrides):
        """A gateway with egress on and a key in the environment."""
        self.set_key(fake_model_key())
        settings = {
            "egress__enabled": True,
            "provider__api_key_env": KEY_VARIABLE,
            "provider__model": "a-model",
        }
        settings.update(overrides)
        return self.gateway(**settings)

    def set_key(self, value):
        os.environ[KEY_VARIABLE] = value
        self.addCleanup(os.environ.pop, KEY_VARIABLE, None)


class WhichProviderItBuilds(GatewayCase):
    def test_the_default_is_the_null_provider(self):
        self.assertIsInstance(self.gateway().build(), NullProvider)

    def test_a_provider_that_needs_no_network_is_built_without_egress(self):
        # The null provider takes no key, no model and no endpoint, so it
        # returns before any of that is read.
        gateway = self.gateway(provider__name="null")
        self.assertIsInstance(gateway.build(), NullProvider)

    def test_the_anthropic_provider_is_built_by_name(self):
        gateway = self.networked(provider__name="anthropic")
        self.assertIsInstance(gateway.build(), AnthropicProvider)

    def test_the_openai_compatible_provider_is_built_by_name(self):
        gateway = self.networked(provider__name="openai_compatible", provider__endpoint=ENDPOINT)
        self.assertIsInstance(gateway.build(), OpenAICompatibleProvider)

    def test_the_configured_model_reaches_the_provider(self):
        gateway = self.networked(provider__name="anthropic", provider__model="a-model")
        self.assertEqual(gateway.build().model, "a-model")

    def test_the_configured_endpoint_reaches_the_provider(self):
        gateway = self.networked(provider__name="openai_compatible", provider__endpoint=ENDPOINT)
        self.assertEqual(gateway.build().endpoint, ENDPOINT)

    def test_the_guard_reaches_the_provider(self):
        gateway = self.networked(provider__name="anthropic")
        self.assertIs(gateway.build().guard, gateway.guard)

    def test_an_unknown_name_is_refused_rather_than_guessed(self):
        # The policy layer refuses first, which is the stricter of the two
        # refusals and the one that should fire.
        with self.assertRaises(PolicyDenied):
            self.gateway(provider__name="gpt-whatever").build()

    def test_an_empty_name_is_refused(self):
        with self.assertRaises(PolicyDenied):
            self.gateway(provider__name="").build()


class WhatItRefusesToBuild(GatewayCase):
    def test_a_networked_provider_needs_egress_switched_on(self):
        with self.assertRaises((ProviderError, PolicyDenied)):
            self.gateway(provider__name="anthropic").build()

    def test_the_egress_refusal_says_what_to_switch_on(self):
        with self.assertRaises(Exception) as caught:
            self.gateway(provider__name="anthropic").build()
        self.assertIn("egress", str(caught.exception))

    def test_the_cli_provider_needs_egress_even_though_it_opens_no_socket(self):
        # It starts a program that reaches the network, so the same
        # declaration is required.
        gateway = self.gateway(provider__name="claude_cli", provider__allow_cli=True)
        with self.assertRaises(Exception) as caught:
            gateway.build()
        self.assertIn("egress", str(caught.exception))

    def test_the_cli_provider_needs_its_own_switch_as_well(self):
        gateway = self.gateway(
            egress__enabled=True, provider__name="claude_cli", provider__allow_cli=False
        )
        with self.assertRaises(PolicyDenied):
            gateway.build()

    def test_the_cli_provider_is_built_when_both_switches_are_on(self):
        gateway = self.gateway(
            egress__enabled=True, provider__name="claude_cli", provider__allow_cli=True
        )
        self.assertIsInstance(gateway.build(), ClaudeCliProvider)

    def test_the_cli_provider_is_built_without_reading_a_key(self):
        # It signs in on its own; JSCR never handles a credential for it.
        gateway = self.gateway(
            egress__enabled=True,
            provider__name="claude_cli",
            provider__allow_cli=True,
            provider__api_key_env="",
        )
        self.assertIsInstance(gateway.build(), ClaudeCliProvider)


class WhereTheKeyComesFrom(GatewayCase):
    def test_the_variable_must_be_named(self):
        gateway = self.networked(provider__name="anthropic", provider__api_key_env="")
        with self.assertRaises(ProviderError) as caught:
            gateway.build()
        self.assertIn("provider.api_key_env", str(caught.exception))

    def test_an_empty_variable_is_an_error_not_an_anonymous_request(self):
        gateway = self.networked(provider__name="anthropic")
        self.set_key("")
        with self.assertRaises(ProviderError) as caught:
            gateway.build()
        self.assertIn(KEY_VARIABLE, str(caught.exception))

    def test_a_variable_that_is_not_set_at_all_is_the_same_error(self):
        os.environ.pop(KEY_VARIABLE, None)
        gateway = self.gateway(
            egress__enabled=True,
            provider__name="anthropic",
            provider__api_key_env=KEY_VARIABLE,
            provider__model="a-model",
        )
        with self.assertRaises(ProviderError):
            gateway.build()

    def test_the_named_variable_is_the_only_one_read(self):
        # Not a default variable name, not a file, not a keychain.
        os.environ["ANTHROPIC_API_KEY"] = fake_model_key()
        self.addCleanup(os.environ.pop, "ANTHROPIC_API_KEY", None)
        os.environ.pop(KEY_VARIABLE, None)
        gateway = self.gateway(
            egress__enabled=True,
            provider__name="anthropic",
            provider__api_key_env=KEY_VARIABLE,
            provider__model="a-model",
        )
        with self.assertRaises(ProviderError):
            gateway.build()

    def test_a_variable_name_with_spaces_around_it_is_still_read(self):
        self.set_key(fake_model_key())
        gateway = self.gateway(
            egress__enabled=True,
            provider__name="anthropic",
            provider__api_key_env="  " + KEY_VARIABLE + "  ",
            provider__model="a-model",
        )
        self.assertIsInstance(gateway.build(), AnthropicProvider)


class WhatItSaysAboutItself(GatewayCase):
    def test_describe_names_the_configured_provider(self):
        gateway = self.gateway(provider__name="null")
        self.assertEqual(gateway.describe()["configured"], "null")

    def test_describe_names_the_configured_model(self):
        gateway = self.networked(provider__name="anthropic", provider__model="a-model")
        self.assertEqual(gateway.describe()["model"], "a-model")

    def test_describe_states_that_there_is_no_fallback(self):
        # Written down rather than implied, because the absence of a
        # fallback is the design.
        self.assertEqual(self.gateway().describe()["fallback"], "none")


class TheSecondGateInsideTheGateway(GatewayCase):
    """The gateway does not trust the policy table to match its registry.

    In normal use the policy refuses these three cases first, so the
    gateway's own checks never fire. They are here because the two tables
    are written in different files and can drift apart; if they ever do,
    the gateway still refuses rather than building something nobody
    approved. A permissive policy stand-in is the only way to ask the
    gateway that question on its own.
    """

    def gateway_with_a_policy_that_allows_everything(self, **overrides):
        gateway = self.gateway(**overrides)
        gateway.policy = _AllowEverything(gateway.config)
        return gateway

    def gateway_naming(self, name):
        """A gateway whose settings name a provider the config would reject."""
        gateway = self.gateway_with_a_policy_that_allows_everything(provider__name="null")
        gateway.config = _Settings({"provider.name": name})
        return gateway

    def test_a_name_the_registry_does_not_hold_is_still_refused(self):
        with self.assertRaises(ProviderError) as caught:
            self.gateway_naming("not-a-provider").build()
        self.assertIn("unknown provider", str(caught.exception))

    def test_the_unknown_name_error_lists_what_is_known(self):
        with self.assertRaises(ProviderError) as caught:
            self.gateway_naming("not-a-provider").build()
        self.assertIn("anthropic", str(caught.exception))

    def test_the_cli_provider_is_refused_when_egress_is_off(self):
        gateway = self.gateway_with_a_policy_that_allows_everything(
            provider__name="claude_cli", provider__allow_cli=True
        )
        with self.assertRaises(ProviderError) as caught:
            gateway.build()
        self.assertIn("egress.enabled", str(caught.exception))

    def test_a_networked_provider_is_refused_when_egress_is_off(self):
        gateway = self.gateway_with_a_policy_that_allows_everything(provider__name="anthropic")
        with self.assertRaises(ProviderError) as caught:
            gateway.build()
        self.assertIn("egress.enabled", str(caught.exception))


class _Settings(object):
    """Settings the real Config would refuse to hold, so the gateway can be asked."""

    def __init__(self, values):
        self.values = values

    def get(self, key, default=None):
        return self.values.get(key, default)


class _AllowEverything(object):
    """A policy that permits anything. Used only to reach the gateway's own checks."""

    def __init__(self, config):
        self.config = config

    def require(self, action, subject=""):
        return None


if __name__ == "__main__":
    unittest.main()
