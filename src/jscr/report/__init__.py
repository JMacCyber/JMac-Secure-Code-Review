"""Output formats.

Reporters read a finished ReviewResult and write text. They make no
decisions, read no configuration beyond what they are handed, and never
touch the network or the filesystem outside the stream they are given.
"""

from .html import render_html
from .json_out import render_json
from .sarif import render_sarif
from .text import render_text

FORMATS = ("text", "json", "sarif", "html")

__all__ = ["render_html", "render_json", "render_sarif", "render_text", "FORMATS"]
