"""The null provider.

It returns an empty finding set without touching the network. It exists so
that the whole pipeline — boundary, diff, context, redaction, deterministic
scanners, verification, reporting — can be run and tested end to end with no
credential, no egress and no cost, and so that the default configuration of
JSCR does something useful rather than erroring.

With the null provider selected, ``jscr review`` is a deterministic scanner.
That is a real mode of operation, not a stub.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .base import Completion, Provider


class NullProvider(Provider):
    name = "null"
    requires_network = False

    def complete(
        self,
        system: str,
        user: str,
        max_output_tokens: int = 4096,
        temperature: float = 0.0,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> Completion:
        del system, user, max_output_tokens, temperature, json_schema
        return Completion(
            text=json.dumps({"findings": []}),
            model="null",
            stop_reason="null_provider",
        )
