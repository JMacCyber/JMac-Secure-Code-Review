"""Reading what a repository depends on, and what licences come with it."""

from .inventory import Package, read_inventory
from .licences import CATEGORY_NETWORK_COPYLEFT, CATEGORY_UNKNOWN, classify

__all__ = [
    "Package",
    "read_inventory",
    "classify",
    "CATEGORY_UNKNOWN",
    "CATEGORY_NETWORK_COPYLEFT",
]
