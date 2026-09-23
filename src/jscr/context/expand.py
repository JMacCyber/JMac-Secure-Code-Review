"""Bounded context expansion.

A diff on its own is often not reviewable. Whether a change is a SQL
injection depends on where the string goes; whether a removed check matters
depends on who called it. So JSCR pulls in a bounded set of related files:
imports, the tests that cover the file, and schema or configuration files
that the change refers to.

Expansion is deterministic. It is a fixed set of rules over file names and
import statements, not a model deciding what it would like to see. Bounds are
enforced by the caller in :mod:`jscr.context.bundle`; this module only
proposes candidates, in priority order.
"""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set

from ..boundary.fs import RepositoryBoundary
from ..errors import BoundaryViolation

#: Import syntax per language. Each pattern captures the module or path.
_IMPORT_PATTERNS: Dict[str, Sequence[re.Pattern]] = {
    ".py": (
        re.compile(r"^\s*from\s+([.\w]+)\s+import\b", re.MULTILINE),
        re.compile(r"^\s*import\s+([.\w]+)", re.MULTILINE),
    ),
    ".js": (
        re.compile(r"""^\s*import\s+[^'"]*['"]([^'"]+)['"]""", re.MULTILINE),
        re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)"""),
    ),
    ".go": (re.compile(r"""^\s*(?:[\w.]+\s+)?"([^"]+)"\s*$""", re.MULTILINE),),
    ".rb": (re.compile(r"""^\s*require(?:_relative)?\s+['"]([^'"]+)['"]""", re.MULTILINE),),
    ".rs": (re.compile(r"^\s*use\s+([\w:]+)", re.MULTILINE),),
    ".java": (re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", re.MULTILINE),),
    ".php": (re.compile(r"^\s*use\s+([\w\\]+)\s*;", re.MULTILINE),),
}
_IMPORT_PATTERNS[".ts"] = _IMPORT_PATTERNS[".js"]
_IMPORT_PATTERNS[".tsx"] = _IMPORT_PATTERNS[".js"]
_IMPORT_PATTERNS[".jsx"] = _IMPORT_PATTERNS[".js"]
_IMPORT_PATTERNS[".mjs"] = _IMPORT_PATTERNS[".js"]
_IMPORT_PATTERNS[".cjs"] = _IMPORT_PATTERNS[".js"]

_SOURCE_SUFFIXES = (
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rb",
    ".rs",
    ".java",
    ".php",
    ".cs",
    ".kt",
    ".swift",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
)

_SCHEMA_NAMES = (
    "schema.sql",
    "schema.prisma",
    "openapi.yaml",
    "openapi.yml",
    "openapi.json",
    "swagger.yaml",
    "swagger.json",
    "requirements.txt",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "cargo.toml",
    "gemfile",
    "pom.xml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
)

_TEST_MARKERS = ("test", "tests", "spec", "__tests__", "_test", ".test", ".spec")


def related_paths(
    boundary: RepositoryBoundary,
    changed: Sequence[str],
    expand_imports: bool = True,
    expand_tests: bool = True,
    expand_schemas: bool = True,
    expand_callers: bool = False,
    index: Optional[List[str]] = None,
) -> List[str]:
    """Candidate paths related to ``changed``, most useful first.

    Returns repository-relative paths that exist and are not themselves in
    ``changed``. Ordering is the priority order the caller should honour when
    it runs out of budget: imports, then tests, then callers, then schemas.
    """
    known = list(index) if index is not None else list(boundary.walk())
    known_set = set(known)
    changed_set = set(changed)

    imports: List[str] = []
    tests: List[str] = []
    callers: List[str] = []
    schemas: List[str] = []

    for path in changed:
        if expand_imports:
            imports.extend(_imports_for(boundary, path, known_set))
        if expand_tests:
            tests.extend(_tests_for(path, known))
        if expand_schemas:
            schemas.extend(_schemas_for(path, known))
    if expand_callers:
        callers.extend(_callers_for(boundary, changed, known))

    ordered: List[str] = []
    seen: Set[str] = set(changed_set)
    for group in (imports, tests, callers, schemas):
        for candidate in group:
            if candidate in seen or candidate not in known_set:
                continue
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _imports_for(boundary: RepositoryBoundary, path: str, known: Set[str]) -> List[str]:
    suffix = os.path.splitext(path)[1].lower()
    patterns = _IMPORT_PATTERNS.get(suffix)
    if not patterns or path not in known:
        return []
    try:
        text = boundary.read_text(path)
    except Exception:  # boundary refusal or unreadable file
        return []
    targets: List[str] = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            resolved = _resolve_import(match.group(1), path, suffix, known)
            if resolved:
                targets.append(resolved)
    return targets


def _resolve_import(target: str, importer: str, suffix: str, known: Set[str]) -> Optional[str]:
    """Map an import statement to a repository file, or give up.

    Only local imports resolve. A third-party package is not in the
    repository, and guessing at one would waste the context budget.
    """
    directory = os.path.dirname(importer)
    if suffix == ".py":
        if target.startswith("."):
            depth = len(target) - len(target.lstrip("."))
            base = directory
            for _ in range(depth - 1):
                base = os.path.dirname(base)
            module = target.lstrip(".").replace(".", "/")
            stem = "/".join(p for p in (base, module) if p)
        else:
            stem = target.replace(".", "/")
        for candidate in ("{0}.py".format(stem), "{0}/__init__.py".format(stem)):
            if candidate in known:
                return candidate
        return None
    if target.startswith("."):
        stem = os.path.normpath(os.path.join(directory, target)).replace(os.sep, "/")
        for extension in ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
            candidate = stem + extension
            if candidate in known:
                return candidate
        for index_name in ("index.ts", "index.js"):
            candidate = "{0}/{1}".format(stem, index_name)
            if candidate in known:
                return candidate
        return None
    # Non-relative: try it as a repository path (Go and Java style).
    flattened = target.replace(".", "/").replace("::", "/")
    for extension in ("", ".go", ".java", ".rs", ".rb", ".php"):
        candidate = flattened + extension
        if candidate in known:
            return candidate
    tail = flattened.rsplit("/", 1)[-1]
    for candidate in known:
        if candidate.endswith("/{0}.go".format(tail)) or candidate.endswith("/{0}.rs".format(tail)):
            return candidate
    return None


def _tests_for(path: str, known: Iterable[str]) -> List[str]:
    """Files that look like tests for ``path``."""
    stem = os.path.splitext(os.path.basename(path))[0]
    if not stem or _is_test(path):
        return []
    hits: List[str] = []
    for candidate in known:
        if not _is_test(candidate):
            continue
        name = os.path.basename(candidate).lower()
        if stem.lower() in name:
            hits.append(candidate)
    return hits


def _is_test(path: str) -> bool:
    lowered = path.lower()
    parts = lowered.split("/")
    name = parts[-1]
    if any(part in ("test", "tests", "spec", "__tests__") for part in parts[:-1]):
        return True
    return any(marker in name for marker in ("test_", "_test", ".test.", ".spec.", "spec_"))


def _schemas_for(path: str, known: Iterable[str]) -> List[str]:
    """Schema and manifest files near a changed file."""
    directory = os.path.dirname(path)
    hits: List[str] = []
    for candidate in known:
        name = os.path.basename(candidate).lower()
        if name not in _SCHEMA_NAMES:
            continue
        candidate_dir = os.path.dirname(candidate)
        if candidate_dir == directory or candidate_dir == "":
            hits.append(candidate)
        elif directory.startswith(candidate_dir + "/"):
            hits.append(candidate)
    return hits


def _callers_for(
    boundary: RepositoryBoundary, changed: Sequence[str], known: Sequence[str]
) -> List[str]:
    """Files that name a changed module.

    A text search, not a call graph. It is honest about being approximate:
    a hit means the file mentions the module, which is usually enough to make
    a reviewer's judgement better and is cheap to compute in any language.
    """
    stems = {os.path.splitext(os.path.basename(p))[0] for p in changed}
    stems = {s for s in stems if len(s) >= 4 and s not in ("index", "main", "utils")}
    if not stems:
        return []
    hits: List[str] = []
    for candidate in known:
        if candidate in set(changed):
            continue
        if os.path.splitext(candidate)[1].lower() not in _SOURCE_SUFFIXES:
            continue
        try:
            text = boundary.read_text(candidate)
        except (OSError, UnicodeDecodeError, BoundaryViolation):
            # Context expansion is best effort: an unreadable candidate is
            # left out. Narrow on purpose, so a boundary failure still raises.
            continue
        if any(stem in text for stem in stems):
            hits.append(candidate)
        if len(hits) >= 25:
            break
    return hits
