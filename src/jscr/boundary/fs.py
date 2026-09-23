"""Repository-root filesystem boundary.

Every byte JSCR reads from a repository comes through
:class:`RepositoryBoundary`. No other module opens a repository file.

The containment rule is applied to the *fully resolved* path, after symlinks,
``..`` segments, case folding on case-insensitive filesystems, and hardlink
resolution. A path that resolves outside the root is refused even if the
string form looked contained.
"""

from __future__ import annotations

import os
import stat
from typing import Iterable, Iterator, List, Optional

from ..errors import BoundaryViolation, ConfigError


def _join(head: str, tail: str) -> str:
    return tail if not head else head + "/" + tail


def _real(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


def _same_or_within(child: str, parent: str) -> bool:
    """True when ``child`` is ``parent`` or sits underneath it.

    ``os.path.commonpath`` is used rather than ``startswith`` because
    ``/repo-evil`` starts with ``/repo`` but is not inside it.
    """
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:
        # Different drives on Windows, or a mix of absolute and relative.
        return False


class RepositoryBoundary(object):
    """A read-only, containment-checked view of one repository."""

    def __init__(
        self,
        root: str,
        follow_symlinks: bool = False,
        max_file_bytes: int = 1048576,
        exclude: Optional[Iterable[str]] = None,
    ) -> None:
        if not os.path.isdir(root):
            raise ConfigError("repository root is not a directory: {0}".format(root))
        self.root = _real(root)
        self.follow_symlinks = bool(follow_symlinks)
        self.max_file_bytes = int(max_file_bytes)
        self.exclude = tuple(exclude or ())

    # -- containment ----------------------------------------------------
    def resolve(self, candidate: str) -> str:
        """Resolve ``candidate`` inside the repository or refuse it.

        Accepts a repository-relative path or an absolute path. Returns the
        real absolute path. Raises :class:`BoundaryViolation` otherwise.
        """
        if candidate is None or candidate == "":
            raise BoundaryViolation("fs.resolve", "empty path")
        if "\x00" in candidate:
            raise BoundaryViolation("fs.resolve", "path contains a NUL byte")
        joined = candidate if os.path.isabs(candidate) else os.path.join(self.root, candidate)
        resolved = _real(joined)

        # Containment is decided on the fully resolved path, so a string that
        # looked contained but resolves elsewhere is refused with the clearer
        # of the two reasons.
        if not _same_or_within(resolved, self.root):
            raise BoundaryViolation(
                "fs.resolve",
                "{0!r} resolves outside the repository root".format(candidate),
            )

        if not self.follow_symlinks:
            # A link that stays inside the root is still refused: following it
            # makes the file identity depend on something the repository
            # controls, and the repository is untrusted.
            link = self._first_symlink(joined)
            if link is not None:
                raise BoundaryViolation(
                    "fs.resolve",
                    "{0} is a symlink and repository.follow_symlinks is false".format(
                        self._lexical_name(link)
                    ),
                )

        return resolved

    def contains(self, candidate: str) -> bool:
        try:
            self.resolve(candidate)
        except BoundaryViolation:
            return False
        return True

    def _first_symlink(self, path: str) -> Optional[str]:
        current = os.path.abspath(path)
        seen: List[str] = []
        while True:
            seen.append(current)
            parent = os.path.dirname(current)
            if parent == current or _real(current) == self.root:
                break
            current = parent
        for item in seen:
            if os.path.islink(item):
                return item
        return None

    # -- reading --------------------------------------------------------
    def read_text(self, candidate: str, encoding: str = "utf-8") -> str:
        """Read a repository file as text, truncating at the size limit."""
        data = self.read_bytes(candidate)
        return data.decode(encoding, errors="replace")

    def read_bytes(self, candidate: str) -> bytes:
        path = self.resolve(candidate)
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise BoundaryViolation(
                "fs.read", "{0} is not a regular file".format(self.relative(path))
            )
        with open(path, "rb") as handle:
            data = handle.read(self.max_file_bytes + 1)
        if len(data) > self.max_file_bytes:
            # Truncate rather than refuse: a large file should not stop a
            # review, and the caller is told the content is partial.
            data = data[: self.max_file_bytes]
        return data

    def is_truncated(self, candidate: str) -> bool:
        path = self.resolve(candidate)
        return os.path.getsize(path) > self.max_file_bytes

    def exists(self, candidate: str) -> bool:
        try:
            path = self.resolve(candidate)
        except BoundaryViolation:
            return False
        return os.path.exists(path)

    # -- listing --------------------------------------------------------
    def walk(self) -> Iterator[str]:
        """Yield repository-relative paths of every readable regular file."""
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            here = "" if _real(dirpath) == self.root else self.relative(dirpath)
            dirnames[:] = sorted(d for d in dirnames if not self.excluded(_join(here, d)))
            for name in sorted(filenames):
                if self.excluded(_join(here, name)):
                    continue
                full = os.path.join(dirpath, name)
                if os.path.islink(full) and not self.follow_symlinks:
                    continue
                if not _same_or_within(_real(full), self.root):
                    continue
                yield self.relative(full)

    def excluded(self, relative_path: str) -> bool:
        """True when a repository-relative path is excluded by configuration.

        An entry with no slash excludes any path segment of that name, which is
        how ``node_modules`` works. An entry with a slash excludes that path and
        everything under it. Both forms are checked here so that every route a
        path can take into a review - the walk, or a diff - uses one answer.
        """
        parts = relative_path.split("/")
        for entry in self.exclude:
            if "/" in entry:
                if relative_path == entry or relative_path.startswith(entry + "/"):
                    return True
            elif entry in parts:
                return True
        return False

    # -- naming ---------------------------------------------------------
    def relative(self, path: str) -> str:
        return os.path.relpath(_real(path), self.root).replace(os.sep, "/")

    def _lexical_name(self, path: str) -> str:
        """Name a path without resolving its final component.

        Used when refusing a symlink: the refusal must name the link the
        caller asked for, not the target it happened to point at.
        """
        absolute = os.path.abspath(path)
        try:
            relative = os.path.relpath(absolute, self.root)
        except ValueError:  # pragma: no cover - different drive
            return absolute
        if relative.startswith(".."):
            return absolute
        return relative.replace(os.sep, "/")

    def relative_or_raw(self, path: str) -> str:
        """Name a path relative to the root, or verbatim when it is outside."""
        real = _real(path)
        if _same_or_within(real, self.root):
            return self.relative(path)
        return path

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "RepositoryBoundary({0!r})".format(self.root)


def boundary_from_config(config, root: Optional[str] = None) -> RepositoryBoundary:
    """Build a boundary from a :class:`jscr.config.Config`."""
    return RepositoryBoundary(
        root=root or config.get("repository.root", "."),
        follow_symlinks=config.get("repository.follow_symlinks", False),
        max_file_bytes=config.get("repository.max_file_bytes", 1048576),
        exclude=config.get("repository.exclude", ()),
    )
