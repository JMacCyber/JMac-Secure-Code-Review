"""The bill of materials for a repository.

CycloneDX 1.5, written from the manifests already in the tree. The document
says where each component came from — which file declared it — because an SBOM
whose provenance is unstated cannot be checked by the person reading it.

What is not here is as important as what is. There is no transitive resolution
and no registry lookup: this engine makes no network requests, so the document
describes what the repository declares, and its metadata says exactly that.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any, Dict, Sequence

from .inventory import CARGO, GO, NPM, PYPI, Package, read_inventory

_PURL = {NPM: "npm", PYPI: "pypi", GO: "golang", CARGO: "cargo"}

SPEC_VERSION = "1.5"


def _purl(package: Package) -> str:
    kind = _PURL.get(package.ecosystem, package.ecosystem)
    name = package.name.lstrip("@").replace("@", "%40")
    if package.ecosystem == NPM and package.name.startswith("@"):
        name = package.name[1:]
        return "pkg:npm/%40{0}@{1}".format(name, package.version or "unspecified")
    return "pkg:{0}/{1}@{2}".format(kind, name, package.version or "unspecified")


def _component(package: Package) -> Dict[str, Any]:
    component: Dict[str, Any] = {
        "type": "library",
        "name": package.name,
        "version": package.version or "unspecified",
        "purl": _purl(package),
        "scope": "required" if package.scope == "runtime" else "optional",
        "bom-ref": _purl(package),
        "properties": [
            {"name": "jscr:declared-in", "value": package.declared_in},
            {"name": "jscr:source", "value": package.source},
            {"name": "jscr:scope", "value": package.scope},
        ],
    }
    if package.licence:
        component["licenses"] = [{"license": {"id": package.licence}}]
    return component


def build_sbom(
    reader,
    paths: Sequence[str],
    project: str = "repository",
    version: str = "",
    timestamp: str = "",
) -> Dict[str, Any]:
    """A CycloneDX document for the dependencies declared in ``paths``."""
    packages = read_inventory(reader, paths)
    components = [_component(p) for p in packages if p.scope != "self"]
    stamp = timestamp or datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    manifests = sorted({p.declared_in for p in packages})
    serial = hashlib.sha256(
        ("|".join(c["purl"] for c in components) + project).encode("utf-8")
    ).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:{0}-{1}-{2}-{3}-{4}".format(
            serial[:8], serial[8:12], serial[12:16], serial[16:20], serial[20:32]
        ),
        "version": 1,
        "metadata": {
            "timestamp": stamp,
            "tools": [{"vendor": "JMac", "name": "jscr", "version": _tool_version()}],
            "component": {
                "type": "application",
                "name": project,
                "version": version or "unspecified",
                "bom-ref": "root",
            },
            "properties": [
                {"name": "jscr:resolution", "value": "declared-only"},
                {"name": "jscr:network", "value": "none"},
                {
                    "name": "jscr:note",
                    "value": (
                        "Components are what the manifests and lockfiles in this "
                        "repository declare. No registry was contacted, so transitive "
                        "dependencies appear only where a lockfile records them."
                    ),
                },
                {"name": "jscr:manifests", "value": ", ".join(manifests) or "none found"},
            ],
        },
        "components": components,
    }


def render(document: Dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False) + "\n"


def _tool_version() -> str:
    try:
        from .. import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - version is cosmetic here
        return "unknown"
