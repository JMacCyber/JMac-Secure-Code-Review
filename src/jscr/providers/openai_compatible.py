"""OpenAI-compatible chat completions provider.

One class covers every service that speaks the chat-completions shape,
including self-hosted servers. The endpoint is always given explicitly in
configuration: JSCR does not guess where a model lives.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..egress.guard import EgressGuard
from ..egress.http import post_json
from ..errors import ProviderError
from .base import Completion, Provider


class OpenAICompatibleProvider(Provider):
    name = "openai_compatible"
    requires_network = True

    def __init__(self, guard: EgressGuard, api_key: str, model: str, endpoint: str) -> None:
        if not model:
            raise ProviderError("provider.model must name a model")
        if not endpoint:
            raise ProviderError(
                "provider.endpoint must be set for the {0} provider".format(self.name)
            )
        self.guard = guard
        self._api_key = api_key
        self.model = model
        self.endpoint = endpoint

    def complete(
        self,
        system: str,
        user: str,
        max_output_tokens: int = 4096,
        temperature: float = 0.0,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> Completion:
        # response_format carries a schema on some servers and not others,
        # and this provider talks to any of them. The shape is asked for in
        # the prompt instead.
        del json_schema
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": int(max_output_tokens),
            "temperature": float(temperature),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {}
        if self._api_key:
            headers["authorization"] = "Bearer {0}".format(self._api_key)
        response = post_json(self.guard, self.endpoint, payload, headers=headers)
        if response.status != 200:
            raise ProviderError(
                "{0} returned HTTP {1}: {2}".format(
                    self.name, response.status, response.body[:400].decode("utf-8", "replace")
                )
            )
        body = response.json or {}
        choices = body.get("choices") or []
        text = ""
        finish = ""
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or {}
            text = str(message.get("content") or "")
            finish = str(choices[0].get("finish_reason") or "")
        usage = body.get("usage") or {}
        return Completion(
            text=text,
            model=str(body.get("model") or self.model),
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
            stop_reason=finish,
        )

    def describe(self) -> Dict[str, Any]:
        return {"provider": self.name, "model": self.model, "endpoint": self.endpoint}
