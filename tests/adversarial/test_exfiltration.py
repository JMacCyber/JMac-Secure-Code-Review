"""The egress guard, attacked.

The threat is a review tool that can be talked into sending source code, or
a credential, somewhere the operator did not approve. Every test here is a
way that has actually been done to somebody: an allowlist that a lookalike
host slips past, a name that resolves to the cloud metadata service, a
redirect to a second destination, a name that answers with one good address
and one bad one.

DNS is stubbed. These tests must pass on a machine with no network, because
a test that silently skips when offline is not a control.
"""

from __future__ import annotations

import socket
import unittest

from jscr.egress import guard as guard_module
from jscr.egress.guard import EgressGuard
from jscr.errors import EgressDenied, PolicyDenied
from jscr.policy import Policy

from ..support import config


def _answers(*addresses):
    """Build getaddrinfo-shaped results without touching the network."""
    rows = []
    for address in addresses:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
        rows.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
    return rows


class StubbedDNS(unittest.TestCase):
    def setUp(self):
        self.answers = {}
        original = guard_module.socket.getaddrinfo

        def fake(host, port, *args, **kwargs):
            if host in self.answers:
                return _answers(*self.answers[host])
            raise socket.gaierror("no such host in this test: {0}".format(host))

        guard_module.socket.getaddrinfo = fake
        self.addCleanup(setattr, guard_module.socket, "getaddrinfo", original)

    def guard(self, **overrides):
        settings = {
            "egress__allow_hosts": ["api.example.com"],
            "egress__enabled": True,
        }
        settings.update(overrides)
        hosts = settings.pop("egress__allow_hosts")
        cfg = config()
        cfg.override("egress.allow_hosts", hosts)
        for key, value in settings.items():
            cfg.override(key.replace("__", "."), value)
        return EgressGuard(Policy(cfg))


class ClosedByDefault(StubbedDNS):
    def test_nothing_goes_out_with_the_shipped_configuration(self):
        guard = EgressGuard(Policy(config()))
        with self.assertRaises(PolicyDenied):
            guard.authorise("https", "api.example.com", 443)


class AllowlistIsHonoured(StubbedDNS):
    def test_a_listed_host_is_allowed(self):
        self.answers["api.example.com"] = ["93.184.216.34"]
        destination = self.guard().authorise("https", "api.example.com", 443)
        self.assertEqual(destination.host, "api.example.com")
        self.assertEqual(destination.address, "93.184.216.34")

    def test_an_unlisted_host_is_refused(self):
        self.answers["evil.example.net"] = ["93.184.216.34"]
        with self.assertRaises(PolicyDenied):
            self.guard().authorise("https", "evil.example.net", 443)

    def test_a_lookalike_suffix_is_refused(self):
        """api.example.com.attacker.test must not pass an api.example.com rule."""
        host = "api.example.com.attacker.test"
        self.answers[host] = ["93.184.216.34"]
        with self.assertRaises(PolicyDenied):
            self.guard().authorise("https", host, 443)

    def test_a_lookalike_prefix_is_refused(self):
        host = "notapi.example.com"
        self.answers[host] = ["93.184.216.34"]
        with self.assertRaises(PolicyDenied):
            self.guard().authorise("https", host, 443)

    def test_a_wildcard_rule_matches_one_label_only(self):
        guard = self.guard(egress__allow_hosts=["*.example.com"])
        self.answers["api.example.com"] = ["93.184.216.34"]
        self.assertTrue(guard.authorise("https", "api.example.com", 443))

    def test_a_bare_star_is_not_an_allowlist(self):
        """An allowlist that allows everything is not an allowlist."""
        guard = self.guard(egress__allow_hosts=["*"])
        self.answers["evil.example.net"] = ["93.184.216.34"]
        with self.assertRaises(PolicyDenied):
            guard.authorise("https", "evil.example.net", 443)

    def test_an_unlisted_port_is_refused(self):
        self.answers["api.example.com"] = ["93.184.216.34"]
        with self.assertRaises(PolicyDenied):
            self.guard().authorise("https", "api.example.com", 8080)


class AddressesAreChecked(StubbedDNS):
    """The allowlist is a name check. Names are controlled by whoever runs DNS."""

    def test_cloud_metadata_address_is_refused(self):
        self.answers["api.example.com"] = ["169.254.169.254"]
        with self.assertRaises(EgressDenied) as caught:
            self.guard().authorise("https", "api.example.com", 443)
        self.assertIn("link-local", str(caught.exception))

    def test_loopback_is_refused(self):
        self.answers["api.example.com"] = ["127.0.0.1"]
        with self.assertRaises(EgressDenied):
            self.guard().authorise("https", "api.example.com", 443)

    def test_ipv6_loopback_is_refused(self):
        self.answers["api.example.com"] = ["::1"]
        with self.assertRaises(EgressDenied):
            self.guard().authorise("https", "api.example.com", 443)

    def test_private_range_is_refused(self):
        for address in ("10.0.0.5", "192.168.1.1", "172.16.0.1"):
            self.answers["api.example.com"] = [address]
            with self.assertRaises(EgressDenied, msg=address):
                self.guard().authorise("https", "api.example.com", 443)

    def test_ipv6_unique_local_is_refused(self):
        self.answers["api.example.com"] = ["fd00::1"]
        with self.assertRaises(EgressDenied):
            self.guard().authorise("https", "api.example.com", 443)

    def test_ipv4_mapped_ipv6_loopback_is_refused(self):
        """::ffff:127.0.0.1 is loopback wearing an IPv6 costume."""
        self.answers["api.example.com"] = ["::ffff:127.0.0.1"]
        with self.assertRaises(EgressDenied):
            self.guard().authorise("https", "api.example.com", 443)

    def test_one_bad_address_among_good_ones_refuses_the_whole_name(self):
        """A DNS rebinding attempt answers with both. Taking the good one is the bug."""
        self.answers["api.example.com"] = ["93.184.216.34", "127.0.0.1"]
        with self.assertRaises(EgressDenied):
            self.guard().authorise("https", "api.example.com", 443)

    def test_private_addresses_are_allowed_when_explicitly_configured(self):
        """Local models are a real use case, and require saying so."""
        guard = self.guard(
            egress__allow_hosts=["localhost"],
            egress__allow_ports=[11434],
            egress__allow_private_addresses=True,
        )
        self.answers["localhost"] = ["127.0.0.1"]
        destination = guard.authorise("http", "localhost", 11434)
        self.assertEqual(destination.address, "127.0.0.1")


class SchemesAndNames(StubbedDNS):
    def test_plain_http_is_refused_to_a_public_host(self):
        self.answers["api.example.com"] = ["93.184.216.34"]
        with self.assertRaises(EgressDenied):
            self.guard().authorise("http", "api.example.com", 443)

    def test_non_http_schemes_are_refused(self):
        for scheme in ("file", "ftp", "gopher", "data", "ws"):
            with self.assertRaises(EgressDenied, msg=scheme):
                self.guard().authorise(scheme, "api.example.com", 443)

    def test_a_name_that_does_not_resolve_is_refused_not_retried(self):
        with self.assertRaises(EgressDenied):
            self.guard().authorise("https", "api.example.com", 443)


if __name__ == "__main__":
    unittest.main()
