"""Telemetry: there is none.

This module exists so that the absence is a checkable fact rather than a
claim in a README. `jscr doctor` calls `status()` and prints what it says.
CI asserts that this file contains no network import, and that no other
module sends anything anywhere except `egress/http.py`, which only ever
talks to the provider endpoint the operator configured.

If telemetry is ever added it will be here, it will be off by default, it
will say exactly what it sends, and it will be visible in this docstring.
Today it sends nothing, because nothing here can.
"""

from __future__ import annotations

from typing import Any, Dict

ENABLED = False


def status() -> Dict[str, Any]:
    return {
        "enabled": ENABLED,
        "endpoint": None,
        "events": [],
        "note": "JSCR sends no usage data. The only outbound connection JSCR "
        "can make is to the model provider endpoint named in your "
        "configuration, and only when egress.enabled is true.",
    }


def record(event: str, **fields: Any) -> None:
    """Accepts an event and drops it.

    Call sites exist so that adding telemetry later would be a change to
    this function rather than a change scattered across the codebase. It
    returns None and does nothing else.
    """
    return None
