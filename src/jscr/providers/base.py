"""The provider interface.

A provider turns a prompt into text. It knows nothing about repositories,
policy or findings, and it never reads configuration or the environment on
its own: everything it needs is passed in. That is what makes a provider
replaceable and what makes the null provider a truthful stand-in during
tests.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class Completion(object):
    """What a provider returned, plus what it cost."""

    __slots__ = ("text", "model", "input_tokens", "output_tokens", "stop_reason", "raw")

    def __init__(
        self,
        text: str,
        model: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        stop_reason: str = "",
        raw: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.text = text
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.stop_reason = stop_reason
        self.raw = raw or {}

    def as_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "stop_reason": self.stop_reason,
            "characters": len(self.text),
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Completion {0} {1} chars>".format(self.model or "?", len(self.text))


class Provider(object):
    """Base class. Subclasses implement :meth:`complete` and nothing else."""

    #: Name used in configuration under ``provider.name``.
    name = "base"

    #: True when the provider needs network egress. The gateway refuses to
    #: build a networked provider unless egress is configured, so that a
    #: misconfiguration fails at startup rather than mid-review.
    requires_network = False

    def complete(
        self,
        system: str,
        user: str,
        max_output_tokens: int = 4096,
        temperature: float = 0.0,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> Completion:
        """Answer the prompt.

        ``json_schema`` is the shape the caller needs back. A provider that
        can make the shape a constraint rather than a request should do so;
        one that cannot ignores it, because the prompt asks for the same
        shape in words either way.
        """
        raise NotImplementedError

    def describe(self) -> Dict[str, Any]:
        return {"provider": self.name, "requires_network": self.requires_network}
