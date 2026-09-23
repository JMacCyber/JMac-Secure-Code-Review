"""Classifying a licence identifier.

A licence is not a bug, so this never decides on its own that something is
wrong. It puts an identifier into a category, and the category is what a
policy can act on. The obligations named below are the ordinary reading of
each licence family; they are not legal advice, and the report says so.
"""

from __future__ import annotations

import re
from typing import Dict, Tuple

CATEGORY_PERMISSIVE = "permissive"
CATEGORY_WEAK_COPYLEFT = "weak-copyleft"
CATEGORY_STRONG_COPYLEFT = "strong-copyleft"
CATEGORY_NETWORK_COPYLEFT = "network-copyleft"
CATEGORY_SOURCE_AVAILABLE = "source-available"
CATEGORY_PUBLIC_DOMAIN = "public-domain"
CATEGORY_UNKNOWN = "unknown"

#: SPDX identifier prefix -> (category, what it asks of you).
_TABLE: Dict[str, Tuple[str, str]] = {
    "MIT": (CATEGORY_PERMISSIVE, "Keep the copyright notice."),
    "ISC": (CATEGORY_PERMISSIVE, "Keep the copyright notice."),
    "BSD": (CATEGORY_PERMISSIVE, "Keep the copyright notice and the disclaimer."),
    "APACHE": (
        CATEGORY_PERMISSIVE,
        "Keep the notice, state your changes, and respect the patent grant.",
    ),
    "PYTHON": (CATEGORY_PERMISSIVE, "Keep the notice."),
    "ZLIB": (CATEGORY_PERMISSIVE, "Keep the notice."),
    "UNLICENSE": (CATEGORY_PUBLIC_DOMAIN, "No obligation."),
    "CC0": (CATEGORY_PUBLIC_DOMAIN, "No obligation."),
    "0BSD": (CATEGORY_PUBLIC_DOMAIN, "No obligation."),
    "MPL": (
        CATEGORY_WEAK_COPYLEFT,
        "Changes to the licensed files must be published under the same licence. "
        "Your own files are unaffected.",
    ),
    "LGPL": (
        CATEGORY_WEAK_COPYLEFT,
        "Dynamic linking is fine. Changes to the library itself must be published.",
    ),
    "EPL": (CATEGORY_WEAK_COPYLEFT, "Changes to the licensed files must be published."),
    "CDDL": (CATEGORY_WEAK_COPYLEFT, "Changes to the licensed files must be published."),
    "GPL": (
        CATEGORY_STRONG_COPYLEFT,
        "Distributing a work that includes this generally requires publishing that "
        "whole work's source under the GPL.",
    ),
    "AGPL": (
        CATEGORY_NETWORK_COPYLEFT,
        "Letting users reach it over a network counts as distribution, so a hosted "
        "service built on this generally has to publish its source.",
    ),
    "SSPL": (
        CATEGORY_NETWORK_COPYLEFT,
        "Offering it as a service requires publishing the service's whole stack.",
    ),
    "BUSL": (
        CATEGORY_SOURCE_AVAILABLE,
        "Not an open-source licence. Production use is restricted until the change date.",
    ),
    "BUSINESS SOURCE": (CATEGORY_SOURCE_AVAILABLE, "Not an open-source licence."),
    "ELASTIC": (CATEGORY_SOURCE_AVAILABLE, "Not an open-source licence."),
    "COMMONS CLAUSE": (CATEGORY_SOURCE_AVAILABLE, "Selling the software is forbidden."),
    "PROPRIETARY": (CATEGORY_SOURCE_AVAILABLE, "Whatever the contract says."),
    "UNLICENSED": (CATEGORY_UNKNOWN, "The package declares no licence at all."),
}

_SPLIT = re.compile(r"\s+(?:OR|AND|WITH)\s+|[()]|,", re.IGNORECASE)


def classify(identifier: str) -> Tuple[str, str]:
    """Return ``(category, obligation)`` for a licence string.

    An expression such as ``MIT OR GPL-3.0`` is reduced to its most permissive
    branch, because the person using it may pick that branch.
    """
    text = (identifier or "").strip()
    if not text:
        return CATEGORY_UNKNOWN, "No licence identifier was found."

    best: Tuple[int, str, str] = (99, CATEGORY_UNKNOWN, "No match for this identifier.")
    order = [
        CATEGORY_PUBLIC_DOMAIN,
        CATEGORY_PERMISSIVE,
        CATEGORY_WEAK_COPYLEFT,
        CATEGORY_STRONG_COPYLEFT,
        CATEGORY_NETWORK_COPYLEFT,
        CATEGORY_SOURCE_AVAILABLE,
        CATEGORY_UNKNOWN,
    ]
    for part in _SPLIT.split(text):
        token = part.strip().upper()
        if not token:
            continue
        for prefix, (category, obligation) in _TABLE.items():
            # AGPL must beat GPL, so the longest matching prefix wins.
            if token.startswith(prefix):
                rank = order.index(category)
                longer = len(prefix)
                current_rank, _, _ = best
                if rank < current_rank or (rank == current_rank and longer > 0):
                    best = (rank, category, obligation)
                break
    return best[1], best[2]
