#!/usr/bin/env python3
"""Remove generated build output, and nothing else.

A wildcard shell command in a Makefile is one typo away from removing
source. This script only touches a closed list of generated directory
names, only inside this repository, and refuses to follow symlinks out of
it. It prints what it removes.
"""

from __future__ import annotations

import os
import shutil
import sys

GENERATED_DIRS = ("__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache")
TOP_LEVEL = ("build", "dist", ".jscr-cache")


def _inside(root: str, path: str) -> bool:
    real = os.path.realpath(path)
    return os.path.commonpath([os.path.realpath(root), real]) == os.path.realpath(root)


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    removed = 0

    targets = []
    for name in TOP_LEVEL:
        candidate = os.path.join(root, name)
        if os.path.isdir(candidate):
            targets.append(candidate)
    for dirpath, dirnames, _files in os.walk(root):
        for name in list(dirnames):
            if name in GENERATED_DIRS:
                targets.append(os.path.join(dirpath, name))
                dirnames.remove(name)
    for name in os.listdir(os.path.join(root, "src")):
        if name.endswith(".egg-info"):
            targets.append(os.path.join(root, "src", name))

    for target in targets:
        if not _inside(root, target):
            sys.stderr.write("skipped (outside the repository): {0}\n".format(target))
            continue
        if os.path.islink(target):
            sys.stderr.write("skipped (symlink): {0}\n".format(target))
            continue
        shutil.rmtree(target)
        sys.stdout.write("removed {0}\n".format(os.path.relpath(target, root)))
        removed += 1

    sys.stdout.write("{0} generated director(ies) removed\n".format(removed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
