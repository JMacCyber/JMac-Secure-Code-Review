"""What this repository depends on, read from the files already in it.

Nothing here resolves a version or asks a registry anything: the inventory is
what the manifests and lockfiles say, and a field a manifest does not carry
is left empty rather than guessed. That keeps the SBOM honest — an empty
licence means "not declared here", not "none".
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

NPM = "npm"
PYPI = "pypi"
GO = "go"
CARGO = "cargo"

_SCOPE_RUNTIME = "runtime"
_SCOPE_DEV = "development"
_SCOPE_OPTIONAL = "optional"

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:([=<>!~]=?)\s*([^\s;#]+))?")
_GO_REQUIRE = re.compile(r"^\s*(?:require\s+)?([\w./-]+\.[\w./-]+)\s+(v[\w.+-]+)")
_TOML_TABLE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
_TOML_KEY = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$")

#: A dependency whose version string points somewhere other than the registry.
_NON_REGISTRY = re.compile(r"^(?:git\+|git:|https?:|file:|link:|github:|bitbucket:|gitlab:)")


class Package(object):
    """One dependency, as declared."""

    __slots__ = ("ecosystem", "name", "version", "licence", "scope", "source", "declared_in")

    def __init__(
        self,
        ecosystem: str,
        name: str,
        version: str = "",
        licence: str = "",
        scope: str = _SCOPE_RUNTIME,
        source: str = "registry",
        declared_in: str = "",
    ) -> None:
        self.ecosystem = ecosystem
        self.name = name
        self.version = version
        self.licence = licence
        self.scope = scope
        self.source = source
        self.declared_in = declared_in

    @property
    def key(self) -> str:
        return "{0}:{1}@{2}".format(self.ecosystem, self.name, self.version or "unspecified")

    def as_dict(self) -> Dict[str, str]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "licence": self.licence,
            "scope": self.scope,
            "source": self.source,
            "declared_in": self.declared_in,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Package {0}>".format(self.key)


def _load_json(reader, path: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(reader(path))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _source_of(spec: str) -> str:
    text = str(spec or "")
    if _NON_REGISTRY.match(text):
        return text.split(":", 1)[0].replace("+", "-")
    if text.endswith((".tgz", ".tar.gz", ".zip")):
        return "url"
    return "registry"


def _npm(reader, path: str) -> List[Package]:
    data = _load_json(reader, path)
    if data is None:
        return []
    packages: List[Package] = []
    groups = (
        ("dependencies", _SCOPE_RUNTIME),
        ("devDependencies", _SCOPE_DEV),
        ("optionalDependencies", _SCOPE_OPTIONAL),
        ("peerDependencies", _SCOPE_RUNTIME),
    )
    for field, scope in groups:
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec in sorted(block.items()):
            packages.append(
                Package(
                    ecosystem=NPM,
                    name=str(name),
                    version=str(spec or ""),
                    scope=scope,
                    source=_source_of(str(spec or "")),
                    declared_in=path,
                )
            )
    return packages


def _npm_lock(reader, path: str) -> List[Package]:
    """Lockfile entries carry the resolved version, and sometimes the licence."""
    data = _load_json(reader, path)
    if data is None:
        return []
    packages: List[Package] = []
    entries = data.get("packages")
    if isinstance(entries, dict):
        for location, entry in sorted(entries.items()):
            if not location or not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or location.split("node_modules/")[-1])
            packages.append(
                Package(
                    ecosystem=NPM,
                    name=name,
                    version=str(entry.get("version") or ""),
                    licence=str(entry.get("license") or ""),
                    scope=_SCOPE_DEV if entry.get("dev") else _SCOPE_RUNTIME,
                    source=_source_of(str(entry.get("resolved") or "")),
                    declared_in=path,
                )
            )
        return packages
    legacy = data.get("dependencies")
    if isinstance(legacy, dict):
        for name, entry in sorted(legacy.items()):
            if not isinstance(entry, dict):
                continue
            packages.append(
                Package(
                    ecosystem=NPM,
                    name=str(name),
                    version=str(entry.get("version") or ""),
                    scope=_SCOPE_DEV if entry.get("dev") else _SCOPE_RUNTIME,
                    source=_source_of(str(entry.get("resolved") or "")),
                    declared_in=path,
                )
            )
    return packages


def _requirements(reader, path: str) -> List[Package]:
    try:
        text = reader(path)
    except Exception:
        return []
    packages: List[Package] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        packages.append(
            Package(
                ecosystem=PYPI,
                name=match.group(1),
                version="{0}{1}".format(match.group(2) or "", match.group(3) or "").strip(),
                source="registry",
                declared_in=path,
            )
        )
    return packages


def _toml_pairs(text: str) -> List[tuple]:
    """(table, key, value) for the flat keys of a small TOML file."""
    table = ""
    rows: List[tuple] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        header = _TOML_TABLE.match(line)
        if header:
            table = header.group(1).strip()
            continue
        pair = _TOML_KEY.match(line)
        if pair:
            rows.append((table, pair.group(1), pair.group(2).strip().strip("\"'")))
    return rows


def _pyproject(reader, path: str) -> List[Package]:
    try:
        text = reader(path)
    except Exception:
        return []
    packages: List[Package] = []
    licence = ""
    for table, key, value in _toml_pairs(text):
        if table == "project" and key == "license":
            licence = value.strip("{} ").replace("text =", "").strip("\"' ")
    # dependencies = ["a>=1", "b"] may span lines, so read the array whole.
    for block in re.findall(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL):
        for item in re.findall(r'"([^"]+)"|\'([^\']+)\'', block):
            spec = item[0] or item[1]
            match = _REQ_LINE.match(spec)
            if match:
                packages.append(
                    Package(
                        ecosystem=PYPI,
                        name=match.group(1),
                        version="{0}{1}".format(match.group(2) or "", match.group(3) or ""),
                        declared_in=path,
                    )
                )
    if licence and not packages:
        packages.append(
            Package(
                ecosystem=PYPI,
                name=_project_name(text) or "this-project",
                licence=licence,
                scope="self",
                declared_in=path,
            )
        )
    for package in packages:
        if not package.licence and package.scope == "self":
            package.licence = licence
    return packages


def _project_name(text: str) -> str:
    for table, key, value in _toml_pairs(text):
        if table == "project" and key == "name":
            return value
    return ""


def _gomod(reader, path: str) -> List[Package]:
    try:
        text = reader(path)
    except Exception:
        return []
    packages: List[Package] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("module ") or line.startswith("//"):
            continue
        match = _GO_REQUIRE.match(line)
        if match:
            packages.append(
                Package(
                    ecosystem=GO,
                    name=match.group(1),
                    version=match.group(2),
                    scope=_SCOPE_DEV if "// indirect" in raw else _SCOPE_RUNTIME,
                    declared_in=path,
                )
            )
    return packages


def _cargo(reader, path: str) -> List[Package]:
    try:
        text = reader(path)
    except Exception:
        return []
    packages: List[Package] = []
    for table, key, value in _toml_pairs(text):
        if table in ("dependencies", "dev-dependencies", "build-dependencies"):
            packages.append(
                Package(
                    ecosystem=CARGO,
                    name=key,
                    version=value.strip("{}").strip() if not value.startswith("{") else "",
                    scope=_SCOPE_DEV if table != "dependencies" else _SCOPE_RUNTIME,
                    declared_in=path,
                )
            )
    return packages


_READERS = (
    ("package-lock.json", _npm_lock),
    ("package.json", _npm),
    ("requirements.txt", _requirements),
    ("pyproject.toml", _pyproject),
    ("go.mod", _gomod),
    ("Cargo.toml", _cargo),
)


def manifest_paths(paths: Iterable[str]) -> List[str]:
    """The manifest files among ``paths``, ignoring anything under node_modules."""
    found: List[str] = []
    for path in paths:
        normalised = path.replace("\\", "/")
        if "node_modules/" in normalised or "/vendor/" in normalised:
            continue
        base = os.path.basename(normalised)
        if base in {name for name, _ in _READERS} or base.startswith("requirements"):
            found.append(path)
    return sorted(found)


def read_inventory(reader, paths: Sequence[str]) -> List[Package]:
    """Every declared dependency found in ``paths``.

    ``reader`` is a callable taking a path and returning text. It is passed in
    rather than imported so that the repository boundary stays the only thing
    that decides which files may be opened.
    """
    packages: List[Package] = []
    for path in manifest_paths(paths):
        base = os.path.basename(path.replace("\\", "/"))
        for name, handler in _READERS:
            if base == name or (name == "requirements.txt" and base.startswith("requirements")):
                packages.extend(handler(reader, path))
                break
    seen: Dict[str, Package] = {}
    for package in packages:
        # A package named by both the manifest and the lockfile is one package;
        # keep the row that carries the most information.
        current = seen.get(package.key)
        if current is None or (not current.licence and package.licence):
            seen[package.key] = package
    return sorted(seen.values(), key=lambda p: (p.ecosystem, p.name, p.version))
