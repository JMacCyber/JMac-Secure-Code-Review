"""The outbound HTTP client, exercised without opening a socket.

Every test here replaces ``_open`` with a fake connection, or calls a pure
function. Nothing in this file talks to a network, so the suite stays
runnable on a machine with no route out.

The host used throughout is a literal public IP address. That keeps the
guard's own resolver step out of the way: an address needs no DNS answer,
so these tests measure the client and not the name server.
"""

from __future__ import annotations

import socket
import ssl
import unittest

from jscr.egress import http as http_module
from jscr.egress.guard import Destination, EgressGuard
from jscr.errors import EgressDenied, ProviderError
from jscr.policy import Policy

from .support import config

HOST = "93.184.216.34"
URL = "https://" + HOST + "/v1/messages"


def guard_for(**overrides) -> EgressGuard:
    """A guard that permits exactly one destination."""
    # Order matters: the config validates on every override, and enabling
    # egress before naming a host is itself a refusal.
    settings = {
        "egress__allow_hosts": [HOST],
        "egress__allow_ports": [443],
        "egress__enabled": True,
    }
    settings.update(overrides)
    return EgressGuard(Policy(config(**settings)))


class FakeRaw(object):
    """Stands in for ``http.client.HTTPResponse``."""

    def __init__(self, status=200, headers=None, body=b"{}"):
        self.status = status
        self._headers = headers if headers is not None else [("Content-Type", "application/json")]
        self._body = body
        self.read_limit = None

    def getheaders(self):
        return self._headers

    def read(self, amount=None):
        self.read_limit = amount
        return self._body


class FakeConnection(object):
    """Records what the client asked for, and answers with a canned response."""

    def __init__(self, raw=None, raises=None):
        self.raw = raw if raw is not None else FakeRaw()
        self.raises = raises
        self.closed = False
        self.method = None
        self.path = None
        self.body = None
        self.headers = None

    def request(self, method, path, body=None, headers=None):
        self.method = method
        self.path = path
        self.body = body
        self.headers = headers
        if self.raises is not None:
            raise self.raises

    def getresponse(self):
        return self.raw

    def close(self):
        self.closed = True


class UsingAFakeConnection(unittest.TestCase):
    """Installs the fake in place of ``_open`` for the length of one test."""

    def use(self, connection):
        real_open = http_module._open
        self.opened = []

        def fake_open(destination, timeout):
            self.opened.append((destination, timeout))
            return connection

        http_module._open = fake_open
        self.addCleanup(setattr, http_module, "_open", real_open)
        return connection


class SplittingAUrl(unittest.TestCase):
    def test_an_https_url_defaults_to_port_443(self):
        self.assertEqual(
            http_module.split_url("https://example.test/v1"),
            ("https", "example.test", 443, "/v1"),
        )

    def test_an_http_url_defaults_to_port_80(self):
        self.assertEqual(http_module.split_url("http://example.test")[2], 80)

    def test_an_explicit_port_wins(self):
        self.assertEqual(http_module.split_url("https://example.test:8443/x")[2], 8443)

    def test_an_empty_path_becomes_a_slash(self):
        self.assertEqual(http_module.split_url("https://example.test")[3], "/")

    def test_a_query_string_is_kept(self):
        self.assertEqual(http_module.split_url("https://example.test/s?q=1&r=2")[3], "/s?q=1&r=2")

    def test_the_host_is_lower_cased(self):
        self.assertEqual(http_module.split_url("https://Example.TEST/x")[1], "example.test")

    def test_a_relative_url_is_refused(self):
        with self.assertRaises(EgressDenied):
            http_module.split_url("/v1/messages")

    def test_credentials_in_the_url_are_refused(self):
        with self.assertRaises(EgressDenied) as caught:
            http_module.split_url("https://user:pass@example.test/x")
        self.assertIn("credentials", str(caught.exception))


class ParsingAResponse(unittest.TestCase):
    def test_json_is_parsed_when_the_content_type_says_so(self):
        response = http_module.HttpResponse(
            200, {"content-type": "application/json"}, b'{"ok": true}'
        )
        self.assertEqual(response.json, {"ok": True})

    def test_a_charset_suffix_does_not_stop_the_parse(self):
        response = http_module.HttpResponse(
            200, {"content-type": "Application/JSON; charset=utf-8"}, b"[1, 2]"
        )
        self.assertEqual(response.json, [1, 2])

    def test_html_is_left_unparsed(self):
        response = http_module.HttpResponse(200, {"content-type": "text/html"}, b"<html></html>")
        self.assertIsNone(response.json)

    def test_an_empty_body_is_left_unparsed(self):
        response = http_module.HttpResponse(204, {"content-type": "application/json"}, b"")
        self.assertIsNone(response.json)

    def test_malformed_json_is_none_rather_than_an_exception(self):
        response = http_module.HttpResponse(200, {"content-type": "application/json"}, b"{oh no")
        self.assertIsNone(response.json)

    def test_a_missing_content_type_is_left_unparsed(self):
        self.assertIsNone(http_module.HttpResponse(200, {}, b'{"ok": true}').json)


class PostingJson(UsingAFakeConnection):
    def test_the_payload_is_serialised_by_the_client(self):
        connection = self.use(FakeConnection())
        http_module.post_json(guard_for(), URL, {"model": "m", "n": 1})
        self.assertEqual(connection.body, b'{"model": "m", "n": 1}')

    def test_the_method_and_path_come_from_the_url(self):
        connection = self.use(FakeConnection())
        http_module.post_json(guard_for(), URL, {})
        self.assertEqual(connection.method, "POST")
        self.assertEqual(connection.path, "/v1/messages")

    def test_the_standard_headers_are_set(self):
        connection = self.use(FakeConnection())
        http_module.post_json(guard_for(), URL, {})
        self.assertEqual(connection.headers["content-type"], "application/json")
        self.assertEqual(connection.headers["accept"], "application/json")
        self.assertEqual(connection.headers["connection"], "close")
        self.assertEqual(connection.headers["content-length"], str(len(connection.body)))
        self.assertTrue(connection.headers["user-agent"].startswith("jscr/"))

    def test_caller_headers_are_lower_cased(self):
        connection = self.use(FakeConnection())
        http_module.post_json(guard_for(), URL, {}, headers={"X-Api-Version": "2026-09-20"})
        self.assertEqual(connection.headers["x-api-version"], "2026-09-20")

    def test_the_response_is_returned_parsed(self):
        self.use(FakeConnection(FakeRaw(body=b'{"ok": true}')))
        response = http_module.post_json(guard_for(), URL, {})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.json, {"ok": True})
        self.assertEqual(response.headers["content-type"], "application/json")

    def test_the_read_is_capped(self):
        raw = FakeRaw()
        self.use(FakeConnection(raw))
        http_module.post_json(guard_for(), URL, {})
        self.assertEqual(raw.read_limit, http_module._MAX_RESPONSE_BYTES)

    def test_the_timeout_comes_from_the_config_by_default(self):
        self.use(FakeConnection())
        http_module.post_json(guard_for(egress__timeout_seconds=12), URL, {})
        self.assertEqual(self.opened[0][1], 12.0)

    def test_an_explicit_timeout_wins(self):
        self.use(FakeConnection())
        http_module.post_json(guard_for(egress__timeout_seconds=12), URL, {}, timeout=3)
        self.assertEqual(self.opened[0][1], 3.0)

    def test_the_connection_is_made_to_the_validated_address(self):
        self.use(FakeConnection())
        http_module.post_json(guard_for(), URL, {})
        destination = self.opened[0][0]
        self.assertEqual(destination.address, HOST)
        self.assertEqual(destination.port, 443)
        self.assertEqual(destination.scheme, "https")

    def test_a_host_off_the_allowlist_never_reaches_the_client(self):
        self.use(FakeConnection())
        with self.assertRaises(Exception):
            http_module.post_json(guard_for(), "https://198.51.100.9/v1", {})
        self.assertEqual(self.opened, [])


class WhenTheConnectionFails(UsingAFakeConnection):
    def test_a_tls_error_becomes_a_provider_error(self):
        self.use(FakeConnection(raises=ssl.SSLError("handshake")))
        with self.assertRaises(ProviderError) as caught:
            http_module.post_json(guard_for(), URL, {})
        self.assertIn("TLS failure", str(caught.exception))

    def test_a_timeout_becomes_a_provider_error_naming_the_limit(self):
        self.use(FakeConnection(raises=socket.timeout()))
        with self.assertRaises(ProviderError) as caught:
            http_module.post_json(guard_for(), URL, {}, timeout=5)
        self.assertIn("did not answer within 5.0s", str(caught.exception))

    def test_any_other_os_error_becomes_a_provider_error(self):
        self.use(FakeConnection(raises=OSError("network is down")))
        with self.assertRaises(ProviderError) as caught:
            http_module.post_json(guard_for(), URL, {})
        self.assertIn("cannot reach", str(caught.exception))

    def test_the_connection_is_closed_even_after_a_failure(self):
        connection = self.use(FakeConnection(raises=OSError("network is down")))
        with self.assertRaises(ProviderError):
            http_module.post_json(guard_for(), URL, {})
        self.assertTrue(connection.closed)

    def test_the_connection_is_closed_after_a_success(self):
        connection = self.use(FakeConnection())
        http_module.post_json(guard_for(), URL, {})
        self.assertTrue(connection.closed)


class WhenTheServerRedirects(UsingAFakeConnection):
    def redirect(self, status):
        return FakeConnection(
            FakeRaw(status=status, headers=[("Location", "https://elsewhere.test/x")], body=b"")
        )

    def test_every_redirect_status_is_refused_by_default(self):
        for status in (301, 302, 303, 307, 308):
            self.use(self.redirect(status))
            with self.assertRaises(EgressDenied):
                http_module.post_json(guard_for(), URL, {})

    def test_the_refusal_names_the_destination(self):
        self.use(self.redirect(302))
        with self.assertRaises(EgressDenied) as caught:
            http_module.post_json(guard_for(), URL, {})
        self.assertIn("elsewhere.test", str(caught.exception))

    def test_a_redirect_is_returned_when_the_setting_allows_it(self):
        self.use(self.redirect(302))
        response = http_module.post_json(guard_for(egress__allow_redirects=True), URL, {})
        self.assertEqual(response.status, 302)

    def test_an_ordinary_error_status_is_returned_not_raised(self):
        self.use(FakeConnection(FakeRaw(status=500, body=b"")))
        self.assertEqual(http_module.post_json(guard_for(), URL, {}).status, 500)


class OpeningAConnection(unittest.TestCase):
    """``_open`` builds the connection object. It does not connect."""

    def test_https_gets_a_verifying_tls_context(self):
        connection = http_module._open(Destination(HOST, 443, HOST, socket.AF_INET, "https"), 10)
        self.assertIsInstance(connection, http_module._PinnedHTTPSConnection)
        self.assertTrue(connection._context.check_hostname)
        self.assertEqual(connection._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(connection._context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_https_keeps_the_hostname_for_sni_and_the_address_for_the_socket(self):
        destination = Destination("example.test", 443, HOST, socket.AF_INET, "https")
        connection = http_module._open(destination, 10)
        self.assertEqual(connection.host, "example.test")
        self.assertEqual(connection._destination.address, HOST)

    def test_http_gets_a_plain_connection(self):
        destination = Destination("127.0.0.1", 8080, "127.0.0.1", socket.AF_INET, "http")
        connection = http_module._open(destination, 10)
        self.assertIsInstance(connection, http_module._PinnedHTTPConnection)
        self.assertEqual(connection.port, 8080)
        self.assertEqual(connection._destination.address, "127.0.0.1")


class TheUserAgent(unittest.TestCase):
    def test_it_names_the_tool_and_its_version(self):
        agent = http_module._user_agent()
        self.assertTrue(agent.startswith("jscr/"))
        self.assertGreater(len(agent), len("jscr/"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
