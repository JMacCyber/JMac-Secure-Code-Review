"""The JSON report.

This is the whole result, including what was refused and what was rejected.
A report that shows only the findings hides the two things a reader most
needs in order to trust it: what the tool was not allowed to do, and what it
decided not to tell you.
"""

from __future__ import annotations

import json
from typing import Any


def render_json(result: Any, indent: int = 2) -> str:
    return json.dumps(result.as_dict(), indent=indent, sort_keys=False, default=str)
