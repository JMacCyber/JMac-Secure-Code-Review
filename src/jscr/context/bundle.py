"""Deterministic review bundles.

A bundle is everything one review pass will see: the diff, the files it
touched, and the bounded related context. Two runs over the same commit with
the same configuration produce byte-identical bundles, which is what makes a
review reproducible and a regression in prompt quality visible.

Budgets are enforced here and nowhere else. When the budget runs out the
bundle says so, in the bundle, so that the reviewer and the reader both know
the review was partial.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional, Sequence

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation
from ..vcs.diff import FileDiff, summarise
from .expand import related_paths

ROLE_CHANGED = "changed"
ROLE_RELATED = "related"


class BundleFile(object):
    """One file in a bundle, with the reason it is here."""

    __slots__ = ("path", "role", "content", "truncated", "diff", "reason")

    def __init__(
        self,
        path: str,
        role: str,
        content: str = "",
        truncated: bool = False,
        diff: Optional[FileDiff] = None,
        reason: str = "",
    ) -> None:
        self.path = path
        self.role = role
        self.content = content
        self.truncated = truncated
        self.diff = diff
        self.reason = reason

    def size(self) -> int:
        return len(self.content.encode("utf-8"))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role,
            "bytes": self.size(),
            "truncated": self.truncated,
            "reason": self.reason,
        }


class Bundle(object):
    """The complete, bounded input to one review."""

    def __init__(self, target: str, root: str) -> None:
        self.target = target
        self.root = root
        self.files: List[BundleFile] = []
        self.diffs: List[FileDiff] = []
        self.omitted: List[Dict[str, str]] = []
        self.refusals: List[Dict[str, str]] = []

    # -- composition ----------------------------------------------------
    def add(self, item: BundleFile) -> None:
        self.files.append(item)

    def omit(self, path: str, reason: str) -> None:
        self.omitted.append({"path": path, "reason": reason})

    def refuse(self, path: str, reason: str) -> None:
        self.refusals.append({"path": path, "reason": reason})

    # -- reading --------------------------------------------------------
    @property
    def changed_files(self) -> List[BundleFile]:
        return [f for f in self.files if f.role == ROLE_CHANGED]

    @property
    def related_files(self) -> List[BundleFile]:
        return [f for f in self.files if f.role == ROLE_RELATED]

    def total_bytes(self) -> int:
        return sum(f.size() for f in self.files)

    def diff_for(self, path: str) -> Optional[FileDiff]:
        for diff in self.diffs:
            if diff.path == path:
                return diff
        return None

    def digest(self) -> str:
        """A content hash. Identical bundles produce identical digests."""
        hasher = hashlib.sha256()
        hasher.update(self.target.encode("utf-8"))
        for item in self.files:
            hasher.update(item.path.encode("utf-8"))
            hasher.update(item.role.encode("utf-8"))
            hasher.update(item.content.encode("utf-8"))
        for diff in self.diffs:
            hasher.update(diff.render().encode("utf-8"))
        return hasher.hexdigest()[:16]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "digest": self.digest(),
            "totals": summarise(self.diffs),
            "bytes": self.total_bytes(),
            "files": [f.as_dict() for f in self.files],
            "omitted": self.omitted,
            "refusals": self.refusals,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Bundle {0} files={1} bytes={2}>".format(
            self.target, len(self.files), self.total_bytes()
        )


def build_bundle(
    boundary: RepositoryBoundary,
    diffs: Sequence[FileDiff],
    target: str,
    max_files: int = 40,
    max_total_bytes: int = 400000,
    expand_imports: bool = True,
    expand_tests: bool = True,
    expand_schemas: bool = True,
    expand_callers: bool = False,
    index: Optional[List[str]] = None,
) -> Bundle:
    """Assemble a bundle under a hard byte and file budget.

    Changed files are added first and are never dropped to make room for
    related context: the change is the subject of the review. Related files
    fill whatever budget is left, in the priority order
    :func:`jscr.context.expand.related_paths` returns.
    """
    bundle = Bundle(target=target, root=boundary.root)
    bundle.diffs = list(diffs)

    used_bytes = 0
    used_files = 0

    for diff in diffs:
        if diff.is_binary:
            bundle.omit(diff.path, "binary file")
            continue
        if diff.status == "deleted":
            bundle.omit(diff.path, "file was deleted")
            continue
        try:
            content = boundary.read_text(diff.path)
            truncated = boundary.is_truncated(diff.path)
        except BoundaryViolation as exc:
            bundle.refuse(diff.path, exc.reason)
            continue
        except OSError as exc:
            bundle.omit(diff.path, "unreadable: {0}".format(exc.strerror or exc))
            continue
        item = BundleFile(
            path=diff.path,
            role=ROLE_CHANGED,
            content=content,
            truncated=truncated,
            diff=diff,
            reason="changed by {0}".format(target),
        )
        # Changed files come first and are never dropped to make room for
        # related context, but they are not exempt from the budget. A
        # change touching thousands of files would otherwise build a
        # prompt no provider will accept, and the review fails with
        # nothing reviewed. The first file is always kept, so a single
        # oversized file is still sent and the provider's own limit is
        # what reports it. The hunks for every omitted file are still in
        # the diff, under its own ceiling.
        size = item.size()
        if bundle.files and (used_files >= max_files or used_bytes + size > max_total_bytes):
            bundle.omit(
                diff.path,
                "changed-file content omitted: context.max_files or "
                "context.max_total_bytes budget reached; the diff still "
                "carries this file's hunks",
            )
            continue
        bundle.add(item)
        used_bytes += size
        used_files += 1

    changed_paths = [d.path for d in diffs]
    candidates = related_paths(
        boundary,
        changed_paths,
        expand_imports=expand_imports,
        expand_tests=expand_tests,
        expand_schemas=expand_schemas,
        expand_callers=expand_callers,
        index=index,
    )

    for path in candidates:
        if used_files >= max_files:
            bundle.omit(path, "context.max_files budget reached")
            continue
        try:
            content = boundary.read_text(path)
            truncated = boundary.is_truncated(path)
        except BoundaryViolation as exc:
            bundle.refuse(path, exc.reason)
            continue
        except OSError:
            continue
        size = len(content.encode("utf-8"))
        if used_bytes + size > max_total_bytes:
            bundle.omit(path, "context.max_total_bytes budget reached")
            continue
        bundle.add(
            BundleFile(
                path=path,
                role=ROLE_RELATED,
                content=content,
                truncated=truncated,
                reason="related to a changed file",
            )
        )
        used_bytes += size
        used_files += 1
    return bundle


def language_of(path: str) -> str:
    """A language name for fencing code blocks. Cosmetic, never a decision."""
    suffix = os.path.splitext(path)[1].lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".jsx": "jsx",
        ".ts": "typescript",
        ".tsx": "tsx",
        ".go": "go",
        ".rb": "ruby",
        ".rs": "rust",
        ".java": "java",
        ".php": "php",
        ".cs": "csharp",
        ".kt": "kotlin",
        ".swift": "swift",
        ".c": "c",
        ".h": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".sh": "bash",
        ".sql": "sql",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".toml": "toml",
    }.get(suffix, "")
