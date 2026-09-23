"""The Claude CLI provider.

It answers a prompt by starting the ``claude`` command in print mode and
reading its JSON envelope, rather than by opening a connection itself. The
operator's existing CLI sign-in is the credential, so no API key is read,
stored or passed anywhere.

Two limitations, stated because hiding them would defeat the point of the
egress layer:

1. **The host allowlist is not enforced for this provider.** JSCR's egress
   guard inspects connections JSCR makes. This provider makes none: the
   child process does, and JSCR cannot see or constrain where it goes.
   ``egress.enabled`` is still required, because that setting is the
   operator's statement that prompt content may leave the machine — but
   ``egress.allow_hosts`` is a claim about JSCR's own traffic only.
2. **The CLI brings its own system prompt, settings and project files.**
   The child is started in an empty directory, with MCP servers switched
   off and its tools refused, so it cannot read the repository under
   review. It can still be shaped by the operator's user-level settings.
   That is the operator's configuration, not the repository's.

Everything JSCR sends has already been through redaction, exactly as it is
for the networked providers.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - argument list only, never a shell
import tempfile
from typing import Any, Dict, List, Optional

from ..config import Config
from ..errors import ProviderError
from .base import Completion, Provider

#: Tools the child is refused. The child has no work that needs them: the
#: prompt already carries the code. A tool call would be the child reading
#: something JSCR did not choose and redaction never saw.
_REFUSED_TOOLS = (
    "Bash",
    "Read",
    "Write",
    "Edit",
    "NotebookEdit",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "Task",
)

#: The external scanners run with a whitelisted environment, because a
#: scanner needs nothing but a PATH. This provider is the opposite case:
#: its whole purpose is to reach the operator's existing CLI sign-in, and
#: a cut-down environment breaks that — measured, the CLI answers
#: "Not logged in · Please run /login". So the child inherits the
#: environment JSCR was started with. State it plainly rather than let it
#: look like an oversight: whatever is exported in the operator's shell is
#: visible to the CLI they chose to run.
_INHERITS_ENVIRONMENT = True


class ClaudeCliProvider(Provider):
    """Runs the operator's signed-in ``claude`` CLI in print mode."""

    name = "claude_cli"

    #: JSCR opens no socket for this provider. The child does. See the
    #: module docstring: this is False because it describes JSCR's own
    #: traffic, not because the prompt stays on the machine.
    requires_network = False

    def __init__(self, config: Config) -> None:
        self.binary = str(config.get("provider.cli_binary", "claude") or "claude")
        self.model = str(config.get("provider.model") or "")
        self.timeout = int(config.get("provider.cli_timeout_seconds", 600))

    def complete(
        self,
        system: str,
        user: str,
        max_output_tokens: int = 4096,
        temperature: float = 0.0,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> Completion:
        # The CLI takes neither of these. Saying so beats accepting them
        # and quietly ignoring them.
        del max_output_tokens, temperature
        argv: List[str] = [
            self.binary,
            "--print",
            "--output-format",
            "json",
            "--strict-mcp-config",
            "--disallowed-tools",
        ]
        argv.extend(_REFUSED_TOOLS)
        if self.model:
            argv.extend(["--model", self.model])
        if system:
            # --system-prompt replaces the CLI's own; --append-system-prompt
            # keeps it. Measured on claude-opus-5 over a real repository:
            # appending
            # produced 10,645 characters of conversational prose where the
            # prompt asked for JSON, because the CLI's default prompt is
            # written for a person at a terminal. Replacing it leaves the
            # reviewer prompt as the only instruction in the session.
            argv.extend(["--system-prompt", system])
        if json_schema:
            # The shape stops being a request and becomes a constraint: the
            # CLI validates the answer against this schema before returning
            # it, so a prose reply cannot come back at all.
            argv.extend(["--json-schema", json.dumps(json_schema)])
        return self._parse(self._run(argv, user))

    def _run(self, argv: List[str], stdin_text: str) -> Dict[str, Any]:
        environment = dict(os.environ) if _INHERITS_ENVIRONMENT else {}
        # An empty directory, so the child has no repository to find and no
        # project settings to pick up from the tree under review.
        workdir = tempfile.mkdtemp(prefix="jscr-claude-cli-")
        try:
            completed = subprocess.run(  # noqa: S603 - argv built here, never a shell string
                argv,
                cwd=workdir,
                env=environment,
                input=stdin_text.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout,
                shell=False,
            )
        except FileNotFoundError as err:
            raise ProviderError(
                "{0} was not found on PATH; provider.cli_binary names the "
                "command that answers the prompt".format(self.binary)
            ) from err
        except subprocess.TimeoutExpired as err:
            raise ProviderError(
                "{0} did not answer within {1}s".format(self.binary, self.timeout)
            ) from err
        raw = completed.stdout.decode("utf-8", "replace").strip()
        detail = completed.stderr.decode("utf-8", "replace").strip()[:400]
        try:
            envelope = json.loads(raw)
        except ValueError as err:
            # No envelope, so the exit code is all there is to report.
            raise ProviderError(
                "{0} exited {1} without the JSON envelope --output-format json "
                "promises; stderr: {2}".format(self.binary, completed.returncode, detail or "empty")
            ) from err
        # A non-zero exit with a good envelope is the CLI's own shutdown
        # work failing — the operator's session hooks, for instance — after
        # the answer was already produced. The envelope is the contract;
        # ``is_error`` inside it is how the CLI reports a failed answer.
        # Discarding a completed review over unrelated teardown would cost a
        # second run and tell the operator nothing true.
        if not isinstance(envelope, dict):
            raise ProviderError(
                "{0} returned {1}, not an object".format(self.binary, type(envelope).__name__)
            )
        return envelope

    def _parse(self, envelope: Dict[str, Any]) -> Completion:
        if envelope.get("is_error"):
            raise ProviderError(
                "{0} reported an error: {1}".format(
                    self.binary, str(envelope.get("result") or envelope.get("subtype") or "")[:400]
                )
            )
        text = envelope.get("result")
        if not isinstance(text, str) or not text.strip():
            raise ProviderError("{0} returned an empty result".format(self.binary))
        usage = envelope.get("usage") or {}
        # Cached input is input: it was read, it was paid for, and leaving
        # it out would under-report what the review cost.
        input_tokens = sum(
            int(usage.get(key) or 0)
            for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
        )
        return Completion(
            text=text,
            model=self.model or "claude-cli",
            input_tokens=input_tokens,
            output_tokens=int(usage.get("output_tokens") or 0),
            stop_reason=str(envelope.get("stop_reason") or ""),
            raw={
                "cost_usd": envelope.get("total_cost_usd"),
                "session_id": envelope.get("session_id"),
            },
        )

    def describe(self) -> Dict[str, Any]:
        return {
            "provider": self.name,
            "requires_network": self.requires_network,
            "binary": self.binary,
            "model": self.model or "the CLI's default",
            "credential": "the CLI's own sign-in; no API key is read",
            "egress_allowlist_enforced": False,
        }
