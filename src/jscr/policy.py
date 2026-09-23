"""The deterministic policy layer.

Every capability JSCR has passes through :class:`Policy`. The model is never
consulted about whether an action is permitted; it is consulted only about
what to ask for. A model that asks for something the policy denies gets a
refusal record, and the refusal is reported.

Each decision is recorded so a run can be audited after the fact: what was
asked for, what was allowed, what was denied and why.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Tuple

from .config import Config
from .errors import PolicyDenied

# Action names. Keep them stable: they appear in reports and in tests.
FS_READ = "fs.read"
NET_CONNECT = "net.connect"
PROVIDER_USE = "provider.use"
EXEC_RUN = "exec.run"
TOOL_CALL = "tool.call"
PERSIST_WRITE = "persist.write"
TELEMETRY_SEND = "telemetry.send"
UPDATE_CHECK = "update.check"

ALL_ACTIONS = (
    FS_READ,
    NET_CONNECT,
    PROVIDER_USE,
    EXEC_RUN,
    TOOL_CALL,
    PERSIST_WRITE,
    TELEMETRY_SEND,
    UPDATE_CHECK,
)


class Decision(object):
    """The outcome of one policy question."""

    __slots__ = ("action", "subject", "allowed", "reason")

    def __init__(self, action: str, subject: str, allowed: bool, reason: str) -> None:
        self.action = action
        self.subject = subject
        self.allowed = allowed
        self.reason = reason

    def as_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "subject": self.subject,
            "allowed": self.allowed,
            "reason": self.reason,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "allow" if self.allowed else "deny"
        return "<Decision {0} {1} {2}: {3}>".format(state, self.action, self.subject, self.reason)


class Policy(object):
    """Deny by default. Allow only what configuration names explicitly."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._log: List[Decision] = []

    @property
    def config(self) -> Config:
        return self._config

    @property
    def decisions(self) -> Tuple[Decision, ...]:
        """Every decision taken, in order. The audit trail for a run."""
        return tuple(self._log)

    @property
    def denials(self) -> Tuple[Decision, ...]:
        return tuple(d for d in self._log if not d.allowed)

    # -- the single decision point --------------------------------------
    def check(self, action: str, subject: str = "") -> Decision:
        """Answer one policy question and record the answer."""
        handler = _HANDLERS.get(action)
        if handler is None:
            decision = Decision(action, subject, False, "unknown action")
        else:
            allowed, reason = handler(self._config, subject)
            decision = Decision(action, subject, allowed, reason)
        self._log.append(decision)
        return decision

    def require(self, action: str, subject: str = "") -> Decision:
        """Like :meth:`check`, but raise :class:`PolicyDenied` on refusal."""
        decision = self.check(action, subject)
        if not decision.allowed:
            raise PolicyDenied(action, decision.reason)
        return decision

    def allows(self, action: str, subject: str = "") -> bool:
        return self.check(action, subject).allowed

    def explain(self) -> List[Dict[str, Any]]:
        """Answer every capability question now, before anything runs.

        This is what ``jscr policy`` prints. An operator should be able to
        read what the tool is permitted to do without having to run a review
        and watch what happens.
        """
        probes = (
            (FS_READ, ""),
            (NET_CONNECT, _first_host(self.config)),
            (PROVIDER_USE, str(self.config.get("provider.name") or "null")),
            (EXEC_RUN, "semgrep"),
            (TOOL_CALL, "any tool"),
            (PERSIST_WRITE, "review output"),
            (TELEMETRY_SEND, "usage data"),
            (UPDATE_CHECK, "new releases"),
        )
        rows: List[Dict[str, Any]] = []
        for action, subject in probes:
            allowed, reason = _HANDLERS[action](self.config, subject)
            rows.append(
                {
                    "action": action,
                    "subject": subject,
                    "allowed": allowed,
                    "reason": reason,
                }
            )
        return rows

    def summary(self) -> Dict[str, Any]:
        """A compact audit summary suitable for the report footer."""
        counts: Dict[str, Dict[str, int]] = {}
        for decision in self._log:
            bucket = counts.setdefault(decision.action, {"allowed": 0, "denied": 0})
            bucket["allowed" if decision.allowed else "denied"] += 1
        return {
            "decisions": len(self._log),
            "by_action": counts,
            "denied": [d.as_dict() for d in self.denials],
        }


# -- handlers -----------------------------------------------------------
# Each returns (allowed, reason). They read configuration and nothing else:
# no environment, no ambient state, no model output.


def _fs_read(config: Config, subject: str) -> Tuple[bool, str]:
    # Path containment itself is enforced by jscr.boundary.fs, which is the
    # only component that can resolve a path. Policy answers the coarser
    # question of whether reading repository files is on at all.
    del subject
    return True, "repository reads are the purpose of the tool"


def _net_connect(config: Config, subject: str) -> Tuple[bool, str]:
    if not config.get("egress.enabled"):
        return False, "egress.enabled is false"
    host, _, port_text = subject.partition(":")
    host = host.strip().lower()
    if not host:
        return False, "no host given"
    allowed_hosts = [h.strip().lower() for h in config.get("egress.allow_hosts", [])]
    if not _host_matches(host, allowed_hosts):
        return False, "host {0!r} is not in egress.allow_hosts".format(host)
    if port_text:
        try:
            port = int(port_text)
        except ValueError:
            return False, "port {0!r} is not a number".format(port_text)
        if port not in list(config.get("egress.allow_ports", [])):
            return False, "port {0} is not in egress.allow_ports".format(port)
    return True, "host is on the egress allowlist"


# Which provider names exist, and which of them need to leave the machine.
# Kept here rather than in the provider package so that the answer to "may
# this provider be used" is decided by policy and not by the component
# asking the question.
KNOWN_PROVIDERS = {
    "null": False,
    "anthropic": True,
    "openai_compatible": True,
    # True means "prompt content leaves this machine", which is the
    # question egress.enabled answers. The claude_cli provider opens no
    # socket itself, but the program it starts does, so the operator
    # still has to say that content may leave.
    "claude_cli": True,
}


def _provider_use(config: Config, subject: str) -> Tuple[bool, str]:
    configured = str(config.get("provider.name") or "")
    if not configured:
        return False, "no provider configured"
    if configured not in KNOWN_PROVIDERS:
        # Not guessed, not treated as an OpenAI-compatible endpoint, not
        # fallen back to null. An unrecognised name means the operator's
        # intent is unknown, and acting on an unknown intent is the thing
        # this layer exists to prevent.
        return False, "provider {0!r} is not a provider JSCR knows; known: {1}".format(
            configured, ", ".join(sorted(KNOWN_PROVIDERS))
        )
    if KNOWN_PROVIDERS[configured] and not config.get("egress.enabled"):
        return False, (
            "provider {0!r} needs network access but egress.enabled is false; "
            "enable egress and name the host in egress.allow_hosts".format(configured)
        )
    if subject and subject != configured:
        # This is the no-silent-fallback rule. A second provider is never
        # reached because the first one failed.
        return False, "provider {0!r} requested but {1!r} is configured".format(subject, configured)
    return True, "provider {0!r} is the configured provider".format(configured)


# Scanners the operator can switch on by name. The list is here, in the
# policy layer, rather than in the scanner package: what may be executed is
# a policy question, and a scanner that could add itself to its own
# allowlist would not be an allowlist.
KNOWN_SCANNERS = ("semgrep", "gitleaks", "trivy")


def _exec_run(config: Config, subject: str) -> Tuple[bool, str]:
    """Two different questions share this action, and they get different answers.

    Running a named scanner is running a program the operator chose and
    switched on. Running anything else means running code that came out of
    the repository under review, which is the thing this tool is built not
    to do by accident. The first is governed by ``scanners.<name>``; the
    second by ``execution.allow_repository_code``, which is false by
    default and should usually stay that way.
    """
    name = subject.strip()
    if name == "claude_cli":
        # A provider that answers by starting a program is still a
        # program being started, and it gets its own switch rather than
        # riding on a scanner's or on allow_repository_code.
        if config.get("provider.allow_cli"):
            return True, "provider.allow_cli is true"
        return False, (
            "provider.allow_cli is false; the claude_cli provider answers by starting a program"
        )
    if name in KNOWN_SCANNERS:
        if config.get("scanners.{0}".format(name)):
            return True, "scanners.{0} is true".format(name)
        return False, "scanners.{0} is false".format(name)
    if config.get("execution.allow_repository_code"):
        return True, "execution.allow_repository_code is true"
    return False, "execution.allow_repository_code is false; {0!r} not run".format(subject)


def _tool_call(config: Config, subject: str) -> Tuple[bool, str]:
    allow = list(config.get("tools.allow", []))
    if not allow:
        return False, "tools.allow is empty"
    if subject in allow:
        return True, "tool {0!r} is allowlisted".format(subject)
    return False, "tool {0!r} is not in tools.allow".format(subject)


def _persist_write(config: Config, subject: str) -> Tuple[bool, str]:
    mode = config.get("persistence.mode")
    if mode == "none":
        return False, "persistence.mode is none"
    if mode == "full":
        return True, "persistence.mode is full"
    # metadata_only
    if subject == "metadata":
        return True, "persistence.mode is metadata_only"
    return False, "persistence.mode is metadata_only; {0!r} is not metadata".format(subject)


def _telemetry_send(config: Config, subject: str) -> Tuple[bool, str]:
    del subject
    if config.get("telemetry.enabled"):
        return True, "telemetry.enabled is true"
    return False, "telemetry.enabled is false"


def _update_check(config: Config, subject: str) -> Tuple[bool, str]:
    del subject
    if config.get("update.check"):
        return True, "update.check is true"
    return False, "update.check is false; JSCR does not update itself"


_HANDLERS = {
    FS_READ: _fs_read,
    NET_CONNECT: _net_connect,
    PROVIDER_USE: _provider_use,
    EXEC_RUN: _exec_run,
    TOOL_CALL: _tool_call,
    PERSIST_WRITE: _persist_write,
    TELEMETRY_SEND: _telemetry_send,
    UPDATE_CHECK: _update_check,
}


def _host_matches(host: str, patterns: List[str]) -> bool:
    """Match a host against the allowlist.

    An entry may be an exact host or a leading-wildcard pattern such as
    ``*.example.com``. A bare ``*`` is rejected: an allowlist that allows
    everything is not an allowlist.
    """
    for pattern in patterns:
        if pattern in ("*", ""):
            continue
        if pattern.startswith("*."):
            # One label, and not the apex. "*.example.com" covers
            # api.example.com and nothing else: not example.com, and not
            # api.example.com.attacker.test, which ends with neither.
            suffix = pattern[1:]  # ".example.com"
            if host.endswith(suffix) and host.count(".") == pattern.count("."):
                return True
        elif fnmatch.fnmatch(host, pattern) and "*" not in pattern:
            return True
        elif host == pattern:
            return True
    return False


def _first_host(config: Config) -> str:
    """A representative destination for the policy explanation.

    With no allowlist there is nothing to probe, so the explanation uses a
    name that is deliberately not in any allowlist. The answer is then the
    honest one: with no hosts configured, nothing may be reached.
    """
    hosts = list(config.get("egress.allow_hosts", []) or [])
    host = hosts[0] if hosts else "any.host"
    ports = list(config.get("egress.allow_ports", []) or [443])
    return "{0}:{1}".format(host, ports[0])
