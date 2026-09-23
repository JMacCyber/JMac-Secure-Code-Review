"""Configuration loading.

JSCR reads one JSON file. JSON is deliberate: the parser is in the standard
library, it has no code execution semantics, no include directive, no
environment interpolation and no ambiguity about types. See
``docs/adr/0003-json-configuration.md``.

Every security-relevant setting defaults to the closed position. A missing
configuration file is not an error; it produces the closed defaults.
"""

from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict, List, Optional

from .errors import ConfigError

CONFIG_FILENAME = ".jscr.json"
SCHEMA_VERSION = 1

#: The closed defaults. Nothing here reaches the network, runs repository code,
#: writes source content to disk, or contacts a model provider.
DEFAULTS: Dict[str, Any] = {
    "version": SCHEMA_VERSION,
    "repository": {
        "root": ".",
        "follow_symlinks": False,
        "max_file_bytes": 1048576,
        "exclude": [".git", "node_modules", ".venv", "dist", "build"],
    },
    "context": {
        "max_files": 40,
        "max_total_bytes": 400000,
        # The diff had no ceiling, so a base commit far enough back built
        # a prompt no provider would accept. Whole files are dropped at
        # this figure, never a partial hunk.
        "max_diff_bytes": 400000,
        "max_expansion_rounds": 2,
        "expand_imports": True,
        "expand_tests": True,
        "expand_schemas": True,
        "expand_callers": False,
    },
    "redaction": {
        "enabled": True,
        "block_on_secret": True,
        "extra_patterns": [],
    },
    "egress": {
        "enabled": False,
        "allow_hosts": [],
        "allow_ports": [443],
        "allow_private_addresses": False,
        "allow_redirects": False,
        "timeout_seconds": 30,
    },
    "provider": {
        "name": "null",
        "model": "",
        "endpoint": "",
        "api_key_env": "",
        "max_output_tokens": 4096,
        "temperature": 0.0,
        # The claude_cli provider answers by starting a program, so it
        # is off until the operator says otherwise, the same way the
        # external scanners are.
        "allow_cli": False,
        "cli_binary": "claude",
        "cli_timeout_seconds": 600,
    },
    "scanners": {
        # Internal scanners read files and run no other program, so they are on
        # by default: switching one off can only lose findings.
        "workflow-permissions": True,
        "manifest": True,
        "iac": True,
        "artefacts": True,
        "licences": True,
        "semgrep": False,
        # A rule file on disk. Empty means: the repository's own .semgrep.yml
        # if it has one, else the rules shipped with JSCR.
        "semgrep_config": "",
        "gitleaks": False,
        "trivy": False,
        "timeout_seconds": 300,
    },
    "execution": {
        "allow_repository_code": False,
        "allow_repository_hooks": False,
    },
    "tools": {
        "allow": [],
    },
    "persistence": {
        "mode": "metadata_only",
        "directory": ".jscr-cache",
    },
    "telemetry": {"enabled": False},
    "update": {"check": False},
    "review": {
        "verify_findings": True,
        "min_confidence": 0.6,
        "max_findings": 200,
        # The verification prompt carries the findings as well as the code.
        # These two bound it: how much finding text goes in one pass, and
        # how many passes a single review will spend.
        "verify_batch_bytes": 80000,
        "max_verify_batches": 4,
    },
}

_VALID_PERSISTENCE = ("metadata_only", "none", "full")


class Config(object):
    """An immutable view over merged configuration values.

    Values are addressed by dotted path so that policy code reads as the
    requirement it implements::

        config.get("egress.enabled")
    """

    __slots__ = ("_data", "path")

    def __init__(self, data: Dict[str, Any], path: Optional[str] = None) -> None:
        self._data = data
        self.path = path

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def override(self, key: str, value: Any) -> None:
        """Set one value for this run only.

        Used by ``--set key=value``. The key must already exist: the closed
        schema is the same protection on the command line as it is in the
        file. A typed ``--set egres.enabled=true`` has to fail loudly, not
        create a new setting nobody reads.
        """
        parts = key.split(".")
        node = self._data
        for part in parts[:-1]:
            if part not in node or not isinstance(node[part], dict):
                raise ConfigError("unknown setting: {0}".format(key))
            node = node[part]
        if parts[-1] not in node:
            raise ConfigError("unknown setting: {0}".format(key))
        node[parts[-1]] = value
        _validate(self._data, self.path or "--set")

    def as_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Config(path={0!r})".format(self.path)

    @classmethod
    def defaults(cls) -> "Config":
        return cls(copy.deepcopy(DEFAULTS), None)

    @classmethod
    def load(cls, path: Optional[str] = None, root: Optional[str] = None) -> "Config":
        """Load configuration, falling back to the closed defaults.

        ``path`` wins if given. Otherwise ``root/.jscr.json`` is used when it
        exists. A file that exists but cannot be parsed is an error: silently
        falling back to defaults would hide a typo in a security setting.
        """
        if path is None and root is not None:
            candidate = os.path.join(root, CONFIG_FILENAME)
            path = candidate if os.path.isfile(candidate) else None
        if path is None:
            return cls.defaults()
        if not os.path.isfile(path):
            raise ConfigError("configuration file not found: {0}".format(path))
        try:
            with open(path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except ValueError as exc:
            raise ConfigError("{0}: invalid JSON: {1}".format(path, exc)) from exc
        if not isinstance(raw, dict):
            raise ConfigError("{0}: top level must be an object".format(path))
        merged = _merge(copy.deepcopy(DEFAULTS), raw, path)
        _validate(merged, path)
        return cls(merged, path)


def _merge(base: Dict[str, Any], over: Dict[str, Any], path: str) -> Dict[str, Any]:
    """Merge user values over defaults, rejecting unknown keys.

    Unknown keys are rejected rather than ignored. A misspelled
    ``"egres": {"enabled": true}`` must not read as a silently closed egress
    setting that the operator believes they opened, nor the reverse.
    """
    for key, value in over.items():
        if key not in base:
            raise ConfigError("{0}: unknown setting {1!r}".format(path, key))
        if isinstance(base[key], dict) and isinstance(value, dict):
            _merge(base[key], value, path)
        elif isinstance(base[key], dict) != isinstance(value, dict):
            raise ConfigError("{0}: wrong type for {1!r}".format(path, key))
        else:
            base[key] = value
    return base


def _validate(data: Dict[str, Any], path: str) -> None:
    if data.get("version") != SCHEMA_VERSION:
        raise ConfigError(
            "{0}: unsupported config version {1!r}, expected {2}".format(
                path, data.get("version"), SCHEMA_VERSION
            )
        )
    mode = data["persistence"]["mode"]
    if mode not in _VALID_PERSISTENCE:
        raise ConfigError(
            "{0}: persistence.mode must be one of {1}".format(path, ", ".join(_VALID_PERSISTENCE))
        )
    hosts = data["egress"]["allow_hosts"]
    if not isinstance(hosts, list) or any(not isinstance(h, str) for h in hosts):
        raise ConfigError("{0}: egress.allow_hosts must be a list of strings".format(path))
    if data["egress"]["enabled"] and not hosts:
        raise ConfigError(
            "{0}: egress.enabled is true but egress.allow_hosts is empty; "
            "name the hosts you intend to reach".format(path)
        )
    tools = data["tools"]["allow"]
    if not isinstance(tools, list) or any(not isinstance(t, str) for t in tools):
        raise ConfigError("{0}: tools.allow must be a list of strings".format(path))
    for numeric in (
        "repository.max_file_bytes",
        "context.max_files",
        "context.max_total_bytes",
        "context.max_expansion_rounds",
        "review.max_findings",
    ):
        value = _dig(data, numeric)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ConfigError("{0}: {1} must be a non-negative integer".format(path, numeric))
    confidence = data["review"]["min_confidence"]
    if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        raise ConfigError("{0}: review.min_confidence must be between 0 and 1".format(path))


def _dig(data: Dict[str, Any], dotted: str) -> Any:
    node: Any = data
    for part in dotted.split("."):
        node = node[part]
    return node


def default_config_json() -> str:
    """Return the default configuration as JSON text."""
    return json.dumps(DEFAULTS, indent=2, sort_keys=False) + "\n"


def config_keys() -> List[str]:
    """Every dotted setting name, for documentation and shell completion."""
    out: List[str] = []

    def walk(node: Dict[str, Any], prefix: str) -> None:
        for key, value in node.items():
            dotted = "{0}{1}".format(prefix, key)
            if isinstance(value, dict):
                walk(value, dotted + ".")
            else:
                out.append(dotted)

    walk(DEFAULTS, "")
    return sorted(out)
