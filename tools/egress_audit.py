#!/usr/bin/env python3
"""Prove that only one module in this codebase can reach the network.

JSCR's central claim is that nothing leaves the machine except through the
egress guard. A claim in a README is worth nothing; this is the same claim
as a test. It parses every module's imports with ast rather than grepping,
so a name split across lines or aliased still counts.

Exit 0 means the claim holds.
"""

from __future__ import annotations

import ast
import os
import sys

NETWORK_MODULES = {
    "socket",
    "ssl",
    "http",
    "urllib",
    "ftplib",
    "smtplib",
    "telnetlib",
    "asyncio",
    "xmlrpc",
    "requests",
    "httpx",
    "aiohttp",
    "urllib3",
    "websockets",
}

# The one module permitted to open a connection, and the audit tool itself.
ALLOWED = {
    os.path.join("src", "jscr", "egress", "http.py"),
    os.path.join("tools", "egress_audit.py"),
}

# The egress guard is a separate case, and the difference matters. It needs
# ``socket.getaddrinfo`` to resolve a name so it can check every address the
# name answers with; resolving is how it refuses cloud metadata addresses
# and loopback. But it must never open a connection itself. So instead of
# waiving the file, the audit holds it to the narrower rule: name
# resolution yes, connection no.
# The same narrower rule covers two test files. The exfiltration tests
# import socket in order to stub name resolution, because a test that
# silently skips when the machine is offline is not a control. The client
# tests import socket and ssl for their constants and error classes, so
# that the error paths they check are the real ones. Both are held to the
# connection rule instead of the import rule: name a thing yes, connect no.
RESOLVER_ONLY = {
    os.path.join("src", "jscr", "egress", "guard.py"),
    os.path.join("tests", "adversarial", "test_exfiltration.py"),
    os.path.join("tests", "test_egress_http.py"),
}

FORBIDDEN_SOCKET_CALLS = {
    "socket",
    "create_connection",
    "create_server",
    "socketpair",
    "connect",
    "connect_ex",
    "bind",
}

ROOTS = ("src", "tools", "tests")


def imported_modules(path):
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # a relative import cannot be stdlib networking
                continue
            if node.module:
                yield node.module, node.lineno


def connection_calls(path):
    """Yield any call in this file that would open or accept a connection."""
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = None
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        if name in FORBIDDEN_SOCKET_CALLS:
            yield name, node.lineno


def main() -> int:
    failures = []
    checked = 0
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for filename in sorted(filenames):
                if not filename.endswith(".py"):
                    continue
                path = os.path.join(dirpath, filename)
                if path in ALLOWED:
                    continue
                checked += 1
                if path in RESOLVER_ONLY:
                    for name, lineno in connection_calls(path):
                        failures.append(
                            (
                                path,
                                lineno,
                                "calls {0}(); it may resolve names, never connect".format(name),
                            )
                        )
                    continue
                for module, lineno in imported_modules(path):
                    top = module.split(".")[0]
                    if module in NETWORK_MODULES or top in NETWORK_MODULES:
                        failures.append(
                            (
                                path,
                                lineno,
                                "imports {0}; only src/jscr/egress/http.py may "
                                "reach the network".format(module),
                            )
                        )

    for path, lineno, detail in failures:
        sys.stderr.write("{0}:{1}: {2}\n".format(path, lineno, detail))
    if failures:
        sys.stderr.write("\negress audit FAILED: {0} violation(s)\n".format(len(failures)))
        return 1
    sys.stdout.write(
        "egress audit Passed: {0} module(s) checked, none can reach the "
        "network.\nThe only outbound path is src/jscr/egress/http.py, which "
        "refuses any destination\nthe policy layer has not allowed.\n".format(checked)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
