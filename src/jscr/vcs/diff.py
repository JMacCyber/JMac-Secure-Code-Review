"""Unified diff parsing.

Findings are reported against lines a reviewer can point at, so the parser
keeps both sides of the mapping: for every added line it records the new-file
line number, and for every removed line the old-file line number. A finding
anchored to a line that the diff did not touch is a finding in the wrong
place, and :meth:`FileDiff.positions_added` is what the reviewer checks it
against.

The parser is deliberately strict and stateless. Diff text is repository
content, therefore untrusted input.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Tuple

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")

ADDED = "added"
REMOVED = "removed"
CONTEXT = "context"

STATUS_ADDED = "added"
STATUS_DELETED = "deleted"
STATUS_MODIFIED = "modified"
STATUS_RENAMED = "renamed"


class Line(object):
    """One line inside a hunk, with its position on each side."""

    __slots__ = ("kind", "text", "old_line", "new_line")

    def __init__(
        self, kind: str, text: str, old_line: Optional[int], new_line: Optional[int]
    ) -> None:
        self.kind = kind
        self.text = text
        self.old_line = old_line
        self.new_line = new_line

    def as_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "text": self.text,
            "old_line": self.old_line,
            "new_line": self.new_line,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Line {0} new={1} {2!r}>".format(self.kind, self.new_line, self.text[:40])


class Hunk(object):
    """One ``@@`` block."""

    __slots__ = ("old_start", "old_count", "new_start", "new_count", "heading", "lines")

    def __init__(
        self,
        old_start: int,
        old_count: int,
        new_start: int,
        new_count: int,
        heading: str = "",
    ) -> None:
        self.old_start = old_start
        self.old_count = old_count
        self.new_start = new_start
        self.new_count = new_count
        self.heading = heading
        self.lines: List[Line] = []

    def header(self) -> str:
        return "@@ -{0},{1} +{2},{3} @@{4}".format(
            self.old_start, self.old_count, self.new_start, self.new_count, self.heading
        )

    def render(self) -> str:
        marker = {ADDED: "+", REMOVED: "-", CONTEXT: " "}
        body = "".join(marker[line.kind] + line.text + "\n" for line in self.lines)
        return self.header() + "\n" + body


class FileDiff(object):
    """Every hunk for one file, plus how the file changed."""

    __slots__ = ("path", "old_path", "status", "hunks", "is_binary")

    def __init__(
        self,
        path: str,
        old_path: Optional[str] = None,
        status: str = STATUS_MODIFIED,
        is_binary: bool = False,
    ) -> None:
        self.path = path
        self.old_path = old_path
        self.status = status
        self.is_binary = is_binary
        self.hunks: List[Hunk] = []

    # -- positions ------------------------------------------------------
    @property
    def is_new(self) -> bool:
        return self.status == STATUS_ADDED

    @property
    def is_deleted(self) -> bool:
        """A deleted file has no new-file lines, so it has nothing to review.

        It is still reported in the summary: removing a file is a change a
        reviewer may need to see, even though there is no line to anchor a
        finding to.
        """
        return self.status == STATUS_DELETED

    @property
    def is_renamed(self) -> bool:
        return self.status == STATUS_RENAMED

    def positions_added(self) -> List[int]:
        """New-file line numbers this diff adds or changes."""
        return [
            line.new_line
            for h in self.hunks
            for line in h.lines
            if line.kind == ADDED and line.new_line
        ]

    def positions_touched(self) -> List[int]:
        """New-file line numbers inside any hunk, context included.

        A finding may legitimately sit on a context line: code that was
        already there can become wrong because of a line next to it.
        """
        return sorted({line.new_line for h in self.hunks for line in h.lines if line.new_line})

    def line_text(self, new_line: int) -> Optional[str]:
        for hunk in self.hunks:
            for line in hunk.lines:
                if line.new_line == new_line:
                    return line.text
        return None

    def added_line_count(self) -> int:
        return len(self.positions_added())

    def removed_line_count(self) -> int:
        return sum(1 for h in self.hunks for line in h.lines if line.kind == REMOVED)

    def render(self) -> str:
        head = "--- {0}\n+++ {1}\n".format(self.old_path or self.path, self.path)
        return head + "".join(h.render() for h in self.hunks)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<FileDiff {0} {1} +{2} -{3}>".format(
            self.path, self.status, self.added_line_count(), self.removed_line_count()
        )


def parse_unified_diff(text: str) -> List[FileDiff]:
    """Parse ``git diff`` output into :class:`FileDiff` objects."""
    files: List[FileDiff] = []
    current: Optional[FileDiff] = None
    hunk: Optional[Hunk] = None
    old_line = 0
    new_line = 0
    pending_rename_from: Optional[str] = None

    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            current = _start_file(raw, files)
            hunk = None
            pending_rename_from = None
            continue
        if current is None:
            continue
        if raw.startswith("new file mode"):
            current.status = STATUS_ADDED
            continue
        if raw.startswith("deleted file mode"):
            current.status = STATUS_DELETED
            continue
        if raw.startswith("rename from "):
            pending_rename_from = _unquote(raw[len("rename from ") :])
            continue
        if raw.startswith("rename to "):
            current.status = STATUS_RENAMED
            current.old_path = pending_rename_from
            current.path = _unquote(raw[len("rename to ") :])
            continue
        if raw.startswith("Binary files") or raw.startswith("GIT binary patch"):
            current.is_binary = True
            continue
        if raw.startswith("--- "):
            source = _strip_prefix(raw[4:])
            if source != "/dev/null":
                current.old_path = source
            continue
        if raw.startswith("+++ "):
            target = _strip_prefix(raw[4:])
            if target != "/dev/null":
                current.path = target
            continue
        match = _HUNK.match(raw)
        if match:
            old_start = int(match.group(1))
            old_count = int(match.group(2) or 1)
            new_start = int(match.group(3))
            new_count = int(match.group(4) or 1)
            hunk = Hunk(old_start, old_count, new_start, new_count, match.group(5) or "")
            current.hunks.append(hunk)
            old_line = old_start
            new_line = new_start
            continue
        if hunk is None:
            continue
        if raw.startswith("\\"):
            # "\ No newline at end of file" annotates the previous line.
            continue
        if raw.startswith("+"):
            hunk.lines.append(Line(ADDED, raw[1:], None, new_line))
            new_line += 1
        elif raw.startswith("-"):
            hunk.lines.append(Line(REMOVED, raw[1:], old_line, None))
            old_line += 1
        elif raw.startswith(" ") or raw == "":
            hunk.lines.append(Line(CONTEXT, raw[1:] if raw else "", old_line, new_line))
            old_line += 1
            new_line += 1
        else:
            # Anything else ends the hunk rather than being guessed at.
            hunk = None
    return files


def _start_file(header: str, files: List[FileDiff]) -> FileDiff:
    path = _paths_from_header(header)
    diff = FileDiff(path=path[1], old_path=path[0])
    files.append(diff)
    return diff


def _paths_from_header(header: str) -> Tuple[str, str]:
    """Read ``diff --git a/x b/y`` into (old, new).

    Paths with spaces make this ambiguous. Git quotes paths containing
    unusual characters, which is handled; for the unquoted ambiguous case the
    ``---``/``+++`` lines that follow correct the guess.
    """
    body = header[len("diff --git ") :]
    if body.startswith('"'):
        end = body.index('" ', 1)
        old = _unquote(body[: end + 1])
        new = _unquote(body[end + 2 :])
        return _strip_prefix(old), _strip_prefix(new)
    halves = body.split(" b/", 1)
    if len(halves) == 2:
        return _strip_prefix(halves[0]), _strip_prefix("b/" + halves[1])
    parts = body.split(" ")
    return _strip_prefix(parts[0]), _strip_prefix(parts[-1])


def _strip_prefix(path: str) -> str:
    path = _unquote(path.strip())
    for prefix in ("a/", "b/"):
        if path.startswith(prefix):
            return path[2:]
    return path


def _unquote(path: str) -> str:
    path = path.strip()
    if len(path) >= 2 and path.startswith('"') and path.endswith('"'):
        inner = path[1:-1]
        try:
            unescaped = inner.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError):  # pragma: no cover
            return inner
        # Git writes each byte of a non-ASCII name as an octal escape, so
        # unescaping gives bytes, not text. The name on disk is UTF-8.
        try:
            return unescaped.encode("latin-1").decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            return unescaped
    return path


def summarise(diffs: Iterable[FileDiff]) -> Dict[str, int]:
    """Counts for the report header."""
    diffs = list(diffs)
    return {
        "files": len(diffs),
        "added_lines": sum(d.added_line_count() for d in diffs),
        "removed_lines": sum(d.removed_line_count() for d in diffs),
        "binary_files": sum(1 for d in diffs if d.is_binary),
    }
