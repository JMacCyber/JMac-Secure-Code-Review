"""Anthropic Messages API provider."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..egress.guard import EgressGuard
from ..egress.http import post_json
from ..errors import ProviderError
from .base import Completion, Provider

DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"


class AnthropicProvider(Provider):
    name = "anthropic"
    requires_network = True

    def __init__(self, guard: EgressGuard, api_key: str, model: str, endpoint: str = "") -> None:
        if not model:
            raise ProviderError("provider.model must name a model")
        self.guard = guard
        self._api_key = api_key
        self.model = model
        self.endpoint = endpoint or DEFAULT_ENDPOINT

    def complete(
        self,
        system: str,
        user: str,
        max_output_tokens: int = 4096,
        temperature: float = 0.0,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> Completion:
        # The Messages API takes a schema only through a tool definition.
        # Until that is built, the shape is asked for in the prompt.
        del json_schema
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": int(max_output_tokens),
            "temperature": float(temperature),
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        response = post_json(
            self.guard,
            self.endpoint,
            payload,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": API_VERSION,
            },
        )
        if response.status != 200:
            raise ProviderError(
                "anthropic returned HTTP {0}: {1}".format(
                    response.status, _error_detail(response.json, response.body)
                )
            )
        body = response.json or {}
        text = "".join(
            block.get("text", "")
            for block in body.get("content", [])
            if isinstance(block, dict) and block.get("type") == "text"
        )
        usage = body.get("usage") or {}
        return Completion(
            text=text,
            model=body.get("model", self.model),
            input_tokens=int(usage.get("input_tokens") or 0),
            output_tokens=int(usage.get("output_tokens") or 0),
            stop_reason=str(body.get("stop_reason") or ""),
        )

    def describe(self) -> Dict[str, Any]:
        return {"provider": self.name, "model": self.model, "endpoint": self.endpoint}


def _error_detail(parsed: Any, body: bytes) -> str:
    if isinstance(parsed, dict):
        error = parsed.get("error")
        if isinstance(error, dict) and error.get("message"):
            return str(error["message"])
    return body[:400].decode("utf-8", errors="replace")
