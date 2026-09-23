"""The provider gateway.

One job: build the provider that configuration names, and no other.

There is no fallback chain. If the configured provider cannot be built or
fails during a review, the review fails and says so. A silent fallback would
mean the operator who approved one destination, one key and one data
processor gets a different one at the moment it matters most — during a
failure, which is exactly when nobody is reading the log.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Type, cast

from ..config import Config
from ..egress.guard import EgressGuard
from ..errors import ProviderError
from ..policy import EXEC_RUN, PROVIDER_USE, Policy
from .anthropic import AnthropicProvider
from .base import Provider
from .claude_cli import ClaudeCliProvider
from .null import NullProvider
from .openai_compatible import OpenAICompatibleProvider

_REGISTRY: Dict[str, Type[Provider]] = {
    NullProvider.name: NullProvider,
    AnthropicProvider.name: AnthropicProvider,
    ClaudeCliProvider.name: ClaudeCliProvider,
    OpenAICompatibleProvider.name: OpenAICompatibleProvider,
}


class Gateway(object):
    """Builds exactly the configured provider."""

    def __init__(self, policy: Policy, guard: EgressGuard) -> None:
        self.policy = policy
        self.guard = guard
        self.config: Config = policy.config

    def build(self) -> Provider:
        name = str(self.config.get("provider.name") or "").strip()
        self.policy.require(PROVIDER_USE, name)
        if name not in _REGISTRY:
            raise ProviderError(
                "unknown provider {0!r}; known providers are {1}".format(
                    name, ", ".join(sorted(_REGISTRY))
                )
            )
        factory = _REGISTRY[name]
        if name == ClaudeCliProvider.name:
            # It opens no socket, so the egress guard never sees it, but
            # the program it starts reaches the network. Both gates
            # apply: one for leaving the machine, one for starting a
            # program.
            if not self.config.get("egress.enabled"):
                raise ProviderError(
                    "provider 'claude_cli' sends prompt content off this machine "
                    "through the CLI; set egress.enabled to say that is intended"
                )
            self.policy.require(EXEC_RUN, name)
            return ClaudeCliProvider(self.config)
        if not factory.requires_network:
            return factory()

        if not self.config.get("egress.enabled"):
            raise ProviderError(
                "provider {0!r} needs network access but egress.enabled is false; "
                "enable egress and name the host in egress.allow_hosts".format(name)
            )
        api_key = self._api_key()
        model = str(self.config.get("provider.model") or "")
        endpoint = str(self.config.get("provider.endpoint") or "")
        # Networked providers share this constructor; the null provider,
        # which takes none of it, has already returned above. Cast rather
        # than widen the registry type, so the registry still guarantees
        # that every entry is a Provider.
        networked = cast(Any, factory)
        return cast(Provider, networked(self.guard, api_key, model, endpoint))

    def _api_key(self) -> str:
        """Read the key from the named environment variable, and nowhere else.

        Not from a file in the repository, not from a keychain, not from a
        default variable name. The operator names the variable; JSCR reads
        that one. A key that is absent is an error, never an anonymous
        request.
        """
        variable = str(self.config.get("provider.api_key_env") or "").strip()
        if not variable:
            raise ProviderError(
                "provider.api_key_env must name the environment variable holding the API key"
            )
        value = os.environ.get(variable, "")
        if not value:
            raise ProviderError(
                "environment variable {0} is empty; no credential was found".format(variable)
            )
        return value

    def describe(self) -> Dict[str, Any]:
        return {
            "configured": self.config.get("provider.name"),
            "model": self.config.get("provider.model"),
            "fallback": "none",
        }
