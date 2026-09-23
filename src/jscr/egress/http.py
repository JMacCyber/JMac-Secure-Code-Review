"""The only outbound HTTP client in JSCR.

No other module imports ``urllib``, ``http.client``, ``requests`` or a socket.
A grep for those names is a meaningful review of this codebase, and CI runs
exactly that grep.

The client is small on purpose:

* it connects to the IP address the guard validated, not to the name, so the
  address cannot change between the check and the connection;
* TLS still verifies the certificate against the hostname, via SNI, so
  pinning the address does not weaken authentication;
* redirects are not followed unless ``egress.allow_redirects`` is on, because
  a redirect is a destination nobody put on the allowlist;
* only JSON is sent and only JSON is read back.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from ..errors import EgressDenied, ProviderError
from .guard import Destination, EgressGuard

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class HttpResponse(object):
    """A response, already parsed."""

    __slots__ = ("status", "headers", "body", "json")

    def __init__(self, status: int, headers: Dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.json: Optional[Any] = None
        content_type = headers.get("content-type", "")
        if "json" in content_type.lower() and body:
            try:
                self.json = json.loads(body.decode("utf-8", errors="replace"))
            except ValueError:
                self.json = None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<HttpResponse {0} {1} bytes>".format(self.status, len(self.body))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    # Declared because HTTPSConnection sets it without declaring it, and the
    # TLS context is the part of this class that matters most.
    _context: ssl.SSLContext

    """Connect to a fixed address while presenting the real hostname to TLS."""

    def __init__(self, destination: Destination, timeout: float, context: ssl.SSLContext) -> None:
        http.client.HTTPSConnection.__init__(
            self,
            destination.host,
            destination.port,
            timeout=timeout,
            context=context,
        )
        self._destination = destination

    def connect(self) -> None:  # pragma: no cover - exercised by integration tests
        raw = socket.create_connection(
            (self._destination.address, self._destination.port), self.timeout
        )
        self.sock = self._context.wrap_socket(raw, server_hostname=self._destination.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP to a fixed address. Only reachable for local endpoints."""

    def __init__(self, destination: Destination, timeout: float) -> None:
        http.client.HTTPConnection.__init__(
            self, destination.host, destination.port, timeout=timeout
        )
        self._destination = destination

    def connect(self) -> None:  # pragma: no cover - exercised by integration tests
        self.sock = socket.create_connection(
            (self._destination.address, self._destination.port), self.timeout
        )


def post_json(
    guard: EgressGuard,
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
) -> HttpResponse:
    """POST JSON to ``url`` through the guard, or raise.

    ``payload`` is serialised here. Callers hand over data, never a string
    they built themselves, so no caller can smuggle anything past the
    redaction step that ran on that data.
    """
    scheme, host, port, path = split_url(url)
    destination = guard.authorise(scheme, host, port)
    timeout = float(timeout or guard.config.get("egress.timeout_seconds", 30))

    body = json.dumps(payload).encode("utf-8")
    request_headers = {
        "content-type": "application/json",
        "accept": "application/json",
        "content-length": str(len(body)),
        "user-agent": _user_agent(),
        "connection": "close",
    }
    for key, value in (headers or {}).items():
        request_headers[key.lower()] = value

    connection = _open(destination, timeout)
    try:
        connection.request("POST", path, body=body, headers=request_headers)
        raw = connection.getresponse()
        received = raw.read(_MAX_RESPONSE_BYTES)
        response = HttpResponse(
            raw.status,
            {k.lower(): v for k, v in raw.getheaders()},
            received,
        )
    except ssl.SSLError as exc:
        raise ProviderError("TLS failure contacting {0}: {1}".format(host, exc)) from exc
    except (socket.timeout, TimeoutError):
        raise ProviderError("{0} did not answer within {1}s".format(host, timeout)) from None
    except OSError as exc:
        raise ProviderError("cannot reach {0}: {1}".format(host, exc)) from exc
    finally:
        connection.close()

    if response.status in (301, 302, 303, 307, 308):
        if not guard.config.get("egress.allow_redirects", False):
            location = response.headers.get("location", "(none)")
            raise EgressDenied(
                "egress",
                "{0} redirected to {1}; redirects are not followed because the "
                "destination is not on the allowlist".format(host, location),
            )
    return response


def split_url(url: str) -> Tuple[str, str, int, str]:
    """Split a URL, refusing anything with credentials or a missing host."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise EgressDenied("egress", "{0!r} is not an absolute URL".format(url))
    if parts.username or parts.password:
        raise EgressDenied("egress", "credentials in a URL are not accepted")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path = "{0}?{1}".format(path, parts.query)
    return parts.scheme.lower(), parts.hostname.lower(), port, path


def _open(destination: Destination, timeout: float):
    if destination.scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return _PinnedHTTPSConnection(destination, timeout, context)
    return _PinnedHTTPConnection(destination, timeout)


def _user_agent() -> str:
    from .. import __version__

    return "jscr/{0}".format(__version__)
