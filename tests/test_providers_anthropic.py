"""The Anthropic Messages provider.

Same rule as the other provider tests: ``post_json`` is replaced, so no
test opens a connection. What is checked is the request this module builds
and the answer it reads back, including the answers a server can send that
are not the happy one.
"""

from __future__ import annotations

import unittest

from jscr.errors import ProviderError
from jscr.providers import anthropic
from jscr.providers.anthropic import API_VERSION, DEFAULT_ENDPOINT, AnthropicProvider

from .support import fake_model_key


class _Response(object):
    """Stands in for ``HttpResponse``."""

    def __init__(self, status=200, body_json=None, body=b""):
        self.status = status
        self.json = body_json
        self.body = body
        self.headers = {"content-type": "application/json"}


class _Recorder(object):
    """Stands in for post_json and remembers how it was called."""

    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, guard, url, payload, headers=None, timeout=None):
        self.calls.append({"guard": guard, "url": url, "payload": payload, "headers": headers})
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def _answer(**overrides):
    body = {
        "model": "server-side-model",
        "content": [{"type": "text", "text": "the answer"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 12, "output_tokens": 4},
    }
    body.update(overrides)
    return body


class _Guard(object):
    """Not an EgressGuard. This module never calls one, so nothing is faked."""


class ProviderCase(unittest.TestCase):
    def setUp(self):
        self.guard = _Guard()

    def provider(self, api_key=None, model="a-model", endpoint=""):
        key = fake_model_key() if api_key is None else api_key
        return AnthropicProvider(guard=self.guard, api_key=key, model=model, endpoint=endpoint)

    def send(self, response=None, system="be terse", user="review this", **kwargs):
        if response is None:
            response = _Response(body_json=_answer())
        recorder = _Recorder(response)
        real = anthropic.post_json
        anthropic.post_json = recorder
        self.addCleanup(setattr, anthropic, "post_json", real)
        provider = kwargs.pop("provider", None) or self.provider()
        completion = provider.complete(system, user, **kwargs)
        self.recorder = recorder
        self.sent = recorder.calls[0]
        return completion


class HowItIsBuilt(ProviderCase):
    def test_a_model_is_required(self):
        with self.assertRaises(ProviderError) as caught:
            self.provider(model="")
        self.assertIn("provider.model", str(caught.exception))

    def test_no_endpoint_means_the_published_one(self):
        # Unlike the openai-compatible provider, this one knows where the
        # service is, because there is only one.
        self.assertEqual(self.provider().endpoint, DEFAULT_ENDPOINT)

    def test_a_given_endpoint_wins(self):
        proxy = "https://gateway.internal/v1/messages"
        self.assertEqual(self.provider(endpoint=proxy).endpoint, proxy)

    def test_the_guard_handed_in_is_the_guard_kept(self):
        self.assertIs(self.provider().guard, self.guard)

    def test_the_provider_declares_that_it_needs_the_network(self):
        self.assertTrue(AnthropicProvider.requires_network)

    def test_the_provider_name_is_the_configuration_name(self):
        self.assertEqual(AnthropicProvider.name, "anthropic")


class TheRequestItBuilds(ProviderCase):
    def test_the_endpoint_is_the_url_posted_to(self):
        self.send()
        self.assertEqual(self.sent["url"], DEFAULT_ENDPOINT)

    def test_the_guard_is_passed_through_to_the_http_layer(self):
        self.send()
        self.assertIs(self.sent["guard"], self.guard)

    def test_the_system_prompt_is_its_own_field_not_a_message(self):
        self.send(system="rules", user="diff")
        self.assertEqual(self.sent["payload"]["system"], "rules")
        self.assertEqual(self.sent["payload"]["messages"], [{"role": "user", "content": "diff"}])

    def test_the_model_is_in_the_body(self):
        self.send(provider=self.provider(model="a-model"))
        self.assertEqual(self.sent["payload"]["model"], "a-model")

    def test_the_default_token_ceiling_is_sent(self):
        self.send()
        self.assertEqual(self.sent["payload"]["max_tokens"], 4096)

    def test_a_token_ceiling_is_sent_as_an_integer(self):
        self.send(max_output_tokens="512")
        self.assertEqual(self.sent["payload"]["max_tokens"], 512)

    def test_a_temperature_is_sent_as_a_float(self):
        self.send(temperature=1)
        self.assertEqual(self.sent["payload"]["temperature"], 1.0)

    def test_nothing_else_is_put_in_the_body(self):
        self.send()
        self.assertEqual(
            sorted(self.sent["payload"]),
            ["max_tokens", "messages", "model", "system", "temperature"],
        )

    def test_the_key_goes_in_the_x_api_key_header(self):
        key = fake_model_key()
        self.send(provider=self.provider(api_key=key))
        self.assertEqual(self.sent["headers"]["x-api-key"], key)

    def test_the_api_version_is_pinned(self):
        self.send()
        self.assertEqual(self.sent["headers"]["anthropic-version"], API_VERSION)

    def test_the_key_is_never_put_in_the_body(self):
        key = fake_model_key()
        self.send(provider=self.provider(api_key=key))
        self.assertNotIn(key, repr(self.sent["payload"]))

    def test_a_requested_json_schema_is_not_sent_as_a_constraint(self):
        # The Messages API takes a schema only through a tool definition,
        # which is not built yet, so the prompt asks for the shape.
        self.send(json_schema={"type": "object"})
        self.assertNotIn("tools", self.sent["payload"])

    def test_one_call_sends_one_request(self):
        self.send()
        self.assertEqual(len(self.recorder.calls), 1)


class TheAnswerItReadsBack(ProviderCase):
    def test_a_text_block_becomes_the_text(self):
        self.assertEqual(self.send().text, "the answer")

    def test_several_text_blocks_are_joined_in_order(self):
        answer = _answer(
            content=[{"type": "text", "text": "one "}, {"type": "text", "text": "two"}]
        )
        self.assertEqual(self.send(_Response(body_json=answer)).text, "one two")

    def test_a_block_that_is_not_text_is_skipped(self):
        answer = _answer(
            content=[
                {"type": "thinking", "thinking": "hidden"},
                {"type": "text", "text": "shown"},
            ]
        )
        self.assertEqual(self.send(_Response(body_json=answer)).text, "shown")

    def test_a_block_that_is_not_an_object_is_skipped(self):
        answer = _answer(content=["not an object", {"type": "text", "text": "shown"}])
        self.assertEqual(self.send(_Response(body_json=answer)).text, "shown")

    def test_no_content_gives_empty_text(self):
        self.assertEqual(self.send(_Response(body_json=_answer(content=[]))).text, "")

    def test_the_model_the_server_reports_is_used(self):
        self.assertEqual(self.send().model, "server-side-model")

    def test_the_configured_model_is_used_when_the_server_names_none(self):
        answer = _answer()
        del answer["model"]
        self.assertEqual(self.send(_Response(body_json=answer)).model, "a-model")

    def test_the_stop_reason_is_read(self):
        self.assertEqual(self.send().stop_reason, "end_turn")

    def test_a_missing_stop_reason_becomes_an_empty_string(self):
        self.assertEqual(self.send(_Response(body_json=_answer(stop_reason=None))).stop_reason, "")

    def test_token_counts_are_read_from_usage(self):
        completion = self.send()
        self.assertEqual((completion.input_tokens, completion.output_tokens), (12, 4))

    def test_missing_usage_counts_as_zero_rather_than_unknown(self):
        completion = self.send(_Response(body_json=_answer(usage=None)))
        self.assertEqual((completion.input_tokens, completion.output_tokens), (0, 0))

    def test_an_empty_body_gives_an_empty_completion_rather_than_an_error(self):
        completion = self.send(_Response(body_json=None))
        self.assertEqual((completion.text, completion.stop_reason), ("", ""))


class WhenTheServerRefuses(ProviderCase):
    def test_a_non_200_status_raises(self):
        with self.assertRaises(ProviderError):
            self.send(_Response(status=500, body=b"upstream said no"))

    def test_the_error_names_the_provider_and_the_status(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(_Response(status=429, body=b"slow down"))
        message = str(caught.exception)
        self.assertIn("anthropic", message)
        self.assertIn("429", message)

    def test_the_services_own_error_message_is_used_when_it_sends_one(self):
        body = {"type": "error", "error": {"type": "invalid_request", "message": "bad model"}}
        with self.assertRaises(ProviderError) as caught:
            self.send(_Response(status=400, body_json=body, body=b"{...}"))
        self.assertIn("bad model", str(caught.exception))

    def test_an_error_object_with_no_message_falls_back_to_the_raw_body(self):
        body = {"error": {"type": "overloaded"}}
        with self.assertRaises(ProviderError) as caught:
            self.send(_Response(status=529, body_json=body, body=b"overloaded_error"))
        self.assertIn("overloaded_error", str(caught.exception))

    def test_an_error_that_is_not_an_object_falls_back_to_the_raw_body(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(_Response(status=502, body_json=["nope"], body=b"gateway said no"))
        self.assertIn("gateway said no", str(caught.exception))

    def test_a_long_error_body_is_cut_to_400_characters(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(_Response(status=500, body=b"x" * 5000))
        self.assertEqual(str(caught.exception).count("x"), 400)

    def test_an_error_body_that_is_not_utf8_still_produces_a_message(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(_Response(status=502, body=b"\xff\xfe bad bytes"))
        self.assertIn("502", str(caught.exception))

    def test_an_egress_refusal_is_not_swallowed(self):
        with self.assertRaises(ProviderError):
            self.send(ProviderError("egress denied"))


class WhatItSaysAboutItself(ProviderCase):
    def test_describe_names_the_provider_the_model_and_the_endpoint(self):
        self.assertEqual(
            self.provider(model="a-model").describe(),
            {"provider": "anthropic", "model": "a-model", "endpoint": DEFAULT_ENDPOINT},
        )

    def test_describe_never_includes_the_key(self):
        key = fake_model_key()
        self.assertNotIn(key, repr(self.provider(api_key=key).describe()))


if __name__ == "__main__":
    unittest.main()
