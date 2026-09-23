"""The commit gate.

A commit is the last moment a defect is cheap. The gate runs before one lands,
reports what it found, and stops there: it does not fix anything and it does
not decide anything. A person reads the report and approves.

The pre-commit pass is deterministic on purpose. Rules, secrets, manifests and
infrastructure files, no model call, no network. A gate that takes seven
minutes is switched off within a day, and a gate that is off catches nothing.
The model review is the deeper dive, asked for by name once the fast pass has
shown there is something worth the wait.

Approval is two git objects, both additive:

  a marker  a tag over the exact tree as it stands, made from ``git stash
            create`` so nothing in the working tree moves
  a branch  where the fixes go, so the main line still holds the version that
            was reviewed

Nothing here deletes or rewrites. The marker is the way back.
"""

from __future__ import annotations

import datetime
import os
from typing import Any, List, Optional, Tuple

DETERMINISTIC = (
    ("provider.name", "null"),
    ("provider.allow_cli", False),
    ("egress.enabled", False),
)

REPORT_DIR = os.path.join(".jscr", "reports")


def stamp(now: Optional[datetime.datetime] = None) -> str:
    """A sortable, filename-safe UTC stamp. One per gate run."""
    moment = now or datetime.datetime.utcnow()
    return moment.strftime("%Y%m%d-%H%M%S")


def report_path(root: str, mark: str) -> str:
    return os.path.join(root, REPORT_DIR, "gate-{0}.html".format(mark))


def marker_tag(mark: str) -> str:
    return "jscr-marker-{0}".format(mark)


def fix_branch(mark: str) -> str:
    return "jscr-fix-{0}".format(mark)


def counts_line(result: Any) -> str:
    """The spread, worst first, naming every severity that is present."""
    counts = result.counts()
    parts = [
        "{0} {1}".format(counts.get(name, 0), name)
        for name in ("Critical", "High", "Medium", "Low", "Info")
        if counts.get(name)
    ]
    if not parts:
        return "No findings."
    return "{0} finding(s): {1}.".format(len(result.findings), ", ".join(parts))


def next_steps(path: str, mark: str, deep_offered: bool) -> List[str]:
    """What the person does next, as commands they can read before running."""
    lines = ["Open the report:", "  {0}".format(path), ""]
    if deep_offered:
        lines += [
            "Deeper dive, if the fast pass is not enough. This calls the model,",
            "takes minutes, and needs egress allowed in your configuration:",
            "  jscr gate --deep",
            "",
        ]
    lines += [
        "Approve, and the gate saves the version and branches for the fix:",
        "  jscr gate --approve",
        "",
        "To commit without the gate, and record that you did:",
        "  git commit --no-verify",
    ]
    return lines


def save_marker(git: Any, mark: str) -> Tuple[str, str, bool]:
    """Tag the tree exactly as it stands, without moving any of it.

    ``git stash create`` writes a commit object for the current index and
    working tree and prints its id. It does not touch the tree, the index or
    the stash list. Tagging that id gives one name that restores this exact
    state. When there is nothing to stash it prints nothing, and HEAD is
    already the state worth naming.
    """
    created = git.run(["stash", "create"]).strip()
    target = created or git.head_commit()
    tag = marker_tag(mark)
    git.run(["tag", "-a", tag, target, "-m", "JSCR gate marker before fixes"])
    return tag, target, bool(created)


def start_branch(git: Any, mark: str) -> str:
    """Branch for the fix. Staged and unstaged changes carry over untouched."""
    name = fix_branch(mark)
    git.run(["checkout", "-b", name])
    return name


def approval_note(tag: str, target: str, branch: str, stashed: bool) -> List[str]:
    return [
        "Version saved.",
        "  marker  {0}  ({1})".format(tag, target[:12]),
        "  branch  {0}".format(branch),
        "",
        "Return to the saved version at any point with:",
        "  git stash apply {0}".format(tag) if stashed else "  git checkout {0}".format(tag),
        "",
        "Now hand the report's prompt to your AI. It fixes on this branch,",
        "one commit per finding, runs the tests, and hands back for your review.",
        "Nothing merges without you.",
    ]
