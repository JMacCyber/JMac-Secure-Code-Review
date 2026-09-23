"""Exception hierarchy.

Every refusal raised by the policy layer carries a machine-readable ``code``
so that refusals can be asserted in tests and counted in reports. A refusal is
a normal outcome, not a crash.
"""

from __future__ import annotations


class JscrError(Exception):
    """Base class for every error raised by JSCR."""

    code = "jscr.error"


class ConfigError(JscrError):
    """The configuration file is missing, malformed, or contradictory."""

    code = "jscr.config"


class PolicyDenied(JscrError):
    """A requested action was denied by the deterministic policy layer.

    Raised with the action name and the reason, both of which are safe to show
    to a user and to assert on in a test.
    """

    code = "jscr.policy.denied"

    def __init__(self, action: str, reason: str) -> None:
        super().__init__("denied: {0}: {1}".format(action, reason))
        self.action = action
        self.reason = reason


class BoundaryViolation(PolicyDenied):
    """A path resolved outside the repository boundary."""

    code = "jscr.boundary.violation"


class EgressDenied(PolicyDenied):
    """A network destination was not on the egress allowlist."""

    code = "jscr.egress.denied"


class SecretDetected(PolicyDenied):
    """Content held a probable secret and the policy blocks egress of secrets."""

    code = "jscr.redaction.secret"


class ProviderError(JscrError):
    """A model provider failed. JSCR never silently falls back to another one."""

    code = "jscr.provider"


class GitError(JscrError):
    """A git invocation failed."""

    code = "jscr.git"
