"""Deny-by-default network egress.

JSCR makes no network connection unless three separate things are true:

1. ``egress.enabled`` is on;
2. the host is named in ``egress.allow_hosts`` and the port in
   ``egress.allow_ports`` (the policy layer decides this);
3. every IP address the host resolves to passes the address checks here.

The third check matters because the first two operate on a name. A name
resolving to ``169.254.169.254`` reaches a cloud metadata service; a name
resolving to ``127.0.0.1`` reaches whatever else is on the machine. So the
guard resolves the name once, validates every address it got, and hands the
caller a :class:`Destination` carrying the chosen address. The connection is
then made to that address, not to the name — which also closes the window
between the check and the connect in which DNS could answer differently.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, List, Optional, Tuple, Union

from ..errors import EgressDenied
from ..policy import NET_CONNECT, Policy

# The concrete address classes, not ipaddress._BaseAddress: the private
# base does not declare is_loopback and friends, and those checks are the
# whole job of this module.
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class Destination(object):
    """A validated place to connect to."""

    __slots__ = ("host", "port", "address", "family", "scheme")

    def __init__(
        self, host: str, port: int, address: str, family: int, scheme: str = "https"
    ) -> None:
        self.host = host
        self.port = port
        self.address = address
        self.family = family
        self.scheme = scheme

    def as_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "address": self.address,
            "scheme": self.scheme,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Destination {0}:{1} via {2}>".format(self.host, self.port, self.address)


class EgressGuard(object):
    """The single gate every outbound connection passes through."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.config = policy.config
        self.allow_private = bool(self.config.get("egress.allow_private_addresses", False))
        self._connections: List[Dict[str, Any]] = []

    @property
    def connections(self) -> Tuple[Dict[str, Any], ...]:
        """Every destination approved during this run, for the audit trail."""
        return tuple(self._connections)

    def authorise(self, scheme: str, host: str, port: Optional[int] = None) -> Destination:
        """Validate a destination or refuse it."""
        scheme = (scheme or "").lower()
        if scheme not in ("https", "http"):
            raise EgressDenied("egress", "scheme {0!r} is not supported".format(scheme))
        if scheme == "http" and not self.allow_private:
            # Plain HTTP is only sensible for a local model server, and that
            # requires the private-address allowance to be on anyway.
            raise EgressDenied(
                "egress",
                "http:// is refused; use https, or set egress.allow_private_addresses "
                "for a local endpoint",
            )
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            raise EgressDenied("egress", "no host given")
        port = int(port or (443 if scheme == "https" else 80))

        # Policy decides the name. This raises PolicyDenied on refusal, and
        # the decision is recorded in the run's audit trail either way.
        self.policy.require(NET_CONNECT, "{0}:{1}".format(host, port))

        address, family = self._resolve(host, port)
        destination = Destination(host, port, address, family, scheme)
        self._connections.append(destination.as_dict())
        return destination

    def _resolve(self, host: str, port: int) -> Tuple[str, int]:
        """Resolve a name and refuse it unless every answer is acceptable.

        Every address is checked, not just the one chosen. A name answering
        with one public and one loopback address is refused outright: which
        one a later connection would pick is not something to leave to
        resolver ordering.
        """
        literal = _as_ip(host)
        if literal is not None:
            self._check_address(literal, host)
            family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
            return str(literal), family
        try:
            answers = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise EgressDenied("egress", "cannot resolve {0!r}: {1}".format(host, exc)) from exc
        if not answers:
            raise EgressDenied("egress", "{0!r} resolved to nothing".format(host))
        chosen: Optional[Tuple[str, int]] = None
        for family, _socktype, _proto, _canon, sockaddr in answers:
            address = _as_ip(str(sockaddr[0]))
            if address is None:  # pragma: no cover - resolver returned a name
                raise EgressDenied("egress", "{0!r} resolved to a non-address".format(host))
            self._check_address(address, host)
            if chosen is None:
                chosen = (str(address), family)
        assert chosen is not None
        return chosen

    def _check_address(self, address: IPAddress, host: str) -> None:
        if self.allow_private:
            return
        why = _why_refused(address)
        if why is not None:
            raise EgressDenied(
                "egress",
                "{0} resolves to {1}, which is {2}; set "
                "egress.allow_private_addresses only if that is intended".format(
                    host, address, why
                ),
            )


def _as_ip(text: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None


def _why_refused(address: IPAddress) -> Optional[str]:
    """Name the reason an address is off limits, or return None."""
    if address.is_loopback:
        return "the loopback interface"
    if address.is_link_local:
        # Covers 169.254.0.0/16, which is where cloud metadata services live.
        return "link-local (cloud metadata lives here)"
    if address.is_private:
        return "a private network"
    if address.is_reserved:
        return "reserved"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "the unspecified address"
    if getattr(address, "ipv4_mapped", None) is not None:
        return "an IPv4-mapped IPv6 address"
    if getattr(address, "sixtofour", None) is not None:
        return "a 6to4 address"
    return None
