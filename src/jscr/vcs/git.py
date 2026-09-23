"""Safe git invocation.

git is the one external program JSCR runs by default, and it is run under
tight constraints:

* the argument vector is built by JSCR, never by string interpolation, and
  every user-supplied revision is passed after ``--`` or validated first;
* the working directory is the repository root, fixed by the boundary;
* repository-controlled configuration that can execute code is neutralised
  (``core.fsmonitor``, ``core.hooksPath``, ``core.pager``, external diff and
  textconv drivers, ``protocol.ext``);
* no network subcommand is ever invoked: JSCR does not fetch, pull or push.

Running git against an untrusted repository is not free of risk, and the
threat model says so plainly. These settings remove the paths by which a
repository's own files can make git run a program of the repository's
choosing.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

from ..boundary.fs import RepositoryBoundary
from ..errors import GitError

#: A revision must look like a revision. This refuses option injection
#: (``--upload-pack=...``) before git ever sees the string.
_REVISION = re.compile(r"^[A-Za-z0-9._/@^~{}\-]{1,255}$")

#: git settings that would let repository content choose a program to run.
_SAFE_CONFIG: Tuple[Tuple[str, str], ...] = (
    ("core.fsmonitor", ""),
    ("core.hooksPath", "/dev/null"),
    ("core.pager", "cat"),
    ("core.askPass", ""),
    ("core.editor", "true"),
    ("diff.external", ""),
    ("protocol.ext.allow", "never"),
    ("credential.helper", ""),
    ("gc.auto", "0"),
    ("safe.directory", "*"),
)


# The tree with nothing in it. Diffing HEAD against it lists every tracked
# file as added, which is how --all reviews a whole repository with the same
# engine that reviews a change. Git names it by hash, so there is one per
# object format.
_EMPTY_TREE = {
    "sha1": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "sha256": "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
}


class GitRange(object):
    """What to review: a commit, a range, the whole tree, or the worktree."""

    __slots__ = ("base", "head", "staged", "worktree", "every_file", "first_commit")

    def __init__(
        self,
        base: Optional[str] = None,
        head: Optional[str] = None,
        staged: bool = False,
        worktree: bool = False,
        every_file: bool = False,
        first_commit: bool = False,
    ) -> None:
        self.base = base
        self.head = head
        self.staged = staged
        self.worktree = worktree
        self.every_file = every_file
        # A commit with no parent. Its change is everything it adds.
        self.first_commit = first_commit

    def describe(self) -> str:
        if self.every_file:
            return "every tracked file at {0}".format(self.head or "HEAD")
        if self.first_commit:
            return "commit {0} (first commit, so every file it adds)".format(self.head)
        if self.worktree:
            return "working tree"
        if self.staged:
            return "staged changes"
        if self.base and self.head:
            return "{0}..{1}".format(self.base, self.head)
        if self.head:
            return "commit {0}".format(self.head)
        return "working tree"

    @classmethod
    def from_args(
        cls,
        commit: Optional[str] = None,
        base: Optional[str] = None,
        head: Optional[str] = None,
        staged: bool = False,
        worktree: bool = False,
        every_file: bool = False,
    ) -> "GitRange":
        if every_file:
            return cls(head=head or "HEAD", every_file=True)
        if commit:
            return cls(base="{0}^".format(commit), head=commit)
        if base:
            return cls(base=base, head=head or "HEAD")
        if staged:
            return cls(staged=True)
        if worktree:
            return cls(worktree=True)
        return cls(worktree=True)


class Git(object):
    """A constrained git client bound to one repository."""

    def __init__(
        self, boundary: RepositoryBoundary, binary: str = "git", timeout: int = 120
    ) -> None:
        self.boundary = boundary
        self.binary = binary
        self.timeout = timeout

    # -- invocation -----------------------------------------------------
    def run(self, args: Sequence[str]) -> str:
        """Run a git subcommand and return stdout as text."""
        command: List[str] = [self.binary, "--no-pager"]
        for key, value in _SAFE_CONFIG:
            command.extend(["-c", "{0}={1}".format(key, value)])
        command.extend(args)
        try:
            completed = subprocess.run(  # noqa: S603 - argv is built here, never a shell string
                command,
                cwd=self.boundary.root,
                env=self._environment(),
                capture_output=True,
                timeout=self.timeout,
                shell=False,
            )
        except FileNotFoundError:
            raise GitError("git executable not found: {0}".format(self.binary)) from None
        except subprocess.TimeoutExpired:
            raise GitError(
                "git timed out after {0}s: {1}".format(self.timeout, " ".join(args))
            ) from None
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise GitError("git {0} failed: {1}".format(" ".join(args), detail or "no output"))
        return completed.stdout.decode("utf-8", errors="replace")

    def _environment(self) -> Dict[str, str]:
        """A minimal environment.

        Inherited git variables can redirect the repository, the config files
        and the object store, so they are dropped rather than passed through.
        """
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "SYSTEMROOT")
        env = {k: v for k, v in os.environ.items() if k in keep}
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_OPTIONAL_LOCKS"] = "0"
        env["GIT_ATTR_NOSYSTEM"] = "1"
        env.setdefault("PATH", "/usr/bin:/bin")
        return env

    # -- queries --------------------------------------------------------
    def version(self) -> str:
        return self.run(["--version"]).strip()

    def is_repository(self) -> bool:
        try:
            return self.run(["rev-parse", "--is-inside-work-tree"]).strip() == "true"
        except GitError:
            return False

    def resolve(self, revision: str) -> str:
        """Turn a revision into a full object id, refusing anything odd."""
        validate_revision(revision)
        return self.run(
            ["rev-parse", "--verify", "--quiet", "{0}^{{commit}}".format(revision)]
        ).strip()

    def empty_tree(self) -> str:
        """The empty tree's id in this repository's object format."""
        try:
            name = self.run(["rev-parse", "--show-object-format"]).strip()
        except GitError:
            # Older git has no --show-object-format and only knows sha1.
            name = "sha1"
        if name not in _EMPTY_TREE:
            raise GitError("unknown object format: {0!r}".format(name))
        return _EMPTY_TREE[name]

    def settle(self, target: GitRange) -> GitRange:
        """Mark a first commit as one, so the report does not name a parent
        that does not exist. Every other target comes back unchanged."""
        if not (target.base and target.head) or target.base != target.head + "^":
            return target
        if self._parent_or_empty(target.base) == target.base:
            return target
        return GitRange(head=target.head, first_commit=True)

    def _parent_or_empty(self, base: str) -> str:
        """Swap a missing parent for the empty tree.

        A root commit has no parent, so ``X^`` does not exist and git refuses
        the range. Its change is everything it adds, which is what a diff
        against the empty tree shows. Only a parent that is missing while the
        commit itself exists is swapped; a bad revision still fails.
        """
        if not base.endswith("^"):
            return base
        if self._is_commit(base) or not self._is_commit(base[:-1]):
            return base
        return self.empty_tree()

    def _is_commit(self, revision: str) -> bool:
        validate_revision(revision)
        try:
            self.run(["rev-parse", "--verify", "--quiet", "{0}^{{commit}}".format(revision)])
        except GitError:
            return False
        return True

    def head_commit(self) -> str:
        return self.run(["rev-parse", "HEAD"]).strip()

    def current_branch(self) -> str:
        return self.run(["rev-parse", "--abbrev-ref", "HEAD"]).strip()

    def commit_message(self, revision: str) -> str:
        validate_revision(revision)
        return self.run(["log", "-1", "--format=%B", revision, "--"]).strip()

    def merge_base(self, base: str, head: str) -> str:
        validate_revision(base)
        validate_revision(head)
        return self.run(["merge-base", base, head]).strip()

    def diff(self, target: GitRange, context_lines: int = 3) -> str:
        """Produce the unified diff for ``target``."""
        args: List[str] = [
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--find-renames",
            "--unified={0}".format(int(context_lines)),
        ]
        if target.worktree:
            args.append("HEAD")
        elif target.staged:
            args.append("--cached")
        else:
            if target.every_file or target.first_commit:
                base = self.empty_tree()
            else:
                base = self._parent_or_empty(target.base or "HEAD^")
            head = target.head or "HEAD"
            validate_revision(base)
            validate_revision(head)
            # Two dots, not three: review what the head actually contains
            # relative to the base, not relative to a merge base that may
            # hide changes brought in by a merge.
            args.append("{0}..{1}".format(base, head))
        args.append("--")
        return self.run(args)

    def changed_files(self, target: GitRange) -> List[str]:
        """Repository-relative paths touched by ``target``."""
        from .diff import parse_unified_diff

        return [d.path for d in parse_unified_diff(self.diff(target, context_lines=0))]

    def file_at(self, revision: str, path: str) -> str:
        """Read a file as it stood at ``revision``."""
        validate_revision(revision)
        relative = self.boundary.relative(self.boundary.resolve(path))
        return self.run(["show", "{0}:{1}".format(revision, relative)])


def validate_revision(revision: str) -> None:
    """Refuse a revision string that could be read as an option or a path."""
    if not revision or revision.startswith("-"):
        raise GitError("invalid revision: {0!r}".format(revision))
    if not _REVISION.match(revision):
        raise GitError("invalid revision: {0!r}".format(revision))
