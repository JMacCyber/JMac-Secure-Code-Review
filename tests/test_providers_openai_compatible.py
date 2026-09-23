"""The OpenAI-compatible provider.

No test here opens a connection. Each one replaces ``post_json``, the one
place in JSCR that talks to the network, and checks the request this
provider builds and the answer it reads back. The guard is a stand-in for
the same reason: this module hands the guard on, it never asks it anything.
"""

from __future__ import annotations

import unittest

from jscr.errors import ProviderError
from jscr.providers import openai_compatible
from jscr.providers.openai_compatible import OpenAICompatibleProvider

from .support import fake_model_key

ENDPOINT = "https://models.example.com/v1/chat/completions"


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
        self.calls.append(
            {
                "guard": guard,
                "url": url,
                "payload": payload,
                "headers": headers,
                "timeout": timeout,
            }
        )
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def _answer(**overrides):
    body = {
        "model": "server-side-model",
        "choices": [
            {"message": {"role": "assistant", "content": "the answer"}, "finish_reason": "stop"}
        ],
        "usage": {"prompt_tokens": 11, "completion_tokens": 3},
    }
    body.update(overrides)
    return body


class _Guard(object):
    """Not an EgressGuard. This module never calls one, so nothing is faked."""


class ProviderCase(unittest.TestCase):
    def setUp(self):
        self.guard = _Guard()

    def provider(self, api_key=None, model="a-model", endpoint=ENDPOINT):
        key = fake_model_key() if api_key is None else api_key
        return OpenAICompatibleProvider(
            guard=self.guard, api_key=key, model=model, endpoint=endpoint
        )

    def send(self, response=None, system="be terse", user="review this", **kwargs):
        """Run complete() with post_json replaced, and keep the recorder."""
        if response is None:
            response = _Response(body_json=_answer())
        recorder = _Recorder(response)
        real = openai_compatible.post_json
        openai_compatible.post_json = recorder
        self.addCleanup(setattr, openai_compatible, "post_json", real)
        provider = kwargs.pop("provider", None) or self.provider()
        completion = provider.complete(system, user, **kwargs)
        self.recorder = recorder
        self.sent = recorder.calls[0]
        return completion


class WhatTheProviderRefusesToBeBuiltWithout(ProviderCase):
    def test_a_model_is_required(self):
        with self.assertRaises(ProviderError) as caught:
            self.provider(model="")
        self.assertIn("provider.model", str(caught.exception))

    def test_an_endpoint_is_required(self):
        with self.assertRaises(ProviderError) as caught:
            self.provider(endpoint="")
        self.assertIn("provider.endpoint", str(caught.exception))

    def test_the_endpoint_message_names_the_provider(self):
        # The message has to say which provider needs it, because the
        # gateway can build more than one.
        with self.assertRaises(ProviderError) as caught:
            self.provider(endpoint="")
        self.assertIn("openai_compatible", str(caught.exception))

    def test_the_model_is_checked_before_the_endpoint(self):
        with self.assertRaises(ProviderError) as caught:
            self.provider(model="", endpoint="")
        self.assertIn("provider.model", str(caught.exception))

    def test_no_api_key_is_allowed(self):
        # A self-hosted server usually wants no key at all.
        provider = self.provider(api_key="")
        self.assertEqual(provider.endpoint, ENDPOINT)

    def test_the_endpoint_is_kept_exactly_as_given(self):
        # JSCR does not guess where a model lives, so it does not tidy the
        # address either.
        odd = "http://127.0.0.1:8000/v1/chat/completions"
        self.assertEqual(self.provider(endpoint=odd).endpoint, odd)

    def test_the_model_is_kept_exactly_as_given(self):
        self.assertEqual(self.provider(model="vendor/model:7b").model, "vendor/model:7b")

    def test_the_guard_handed_in_is_the_guard_kept(self):
        self.assertIs(self.provider().guard, self.guard)

    def test_the_provider_declares_that_it_needs_the_network(self):
        self.assertTrue(OpenAICompatibleProvider.requires_network)

    def test_the_provider_name_is_the_configuration_name(self):
        self.assertEqual(OpenAICompatibleProvider.name, "openai_compatible")


class TheRequestItBuilds(ProviderCase):
    def test_the_endpoint_is_the_url_posted_to(self):
        self.send()
        self.assertEqual(self.sent["url"], ENDPOINT)

    def test_the_guard_is_passed_through_to_the_http_layer(self):
        self.send()
        self.assertIs(self.sent["guard"], self.guard)

    def test_the_model_is_in_the_body(self):
        self.send(provider=self.provider(model="a-model"))
        self.assertEqual(self.sent["payload"]["model"], "a-model")

    def test_the_system_and_user_prompts_are_two_messages_in_order(self):
        self.send(system="rules", user="diff")
        self.assertEqual(
            self.sent["payload"]["messages"],
            [
                {"role": "system", "content": "rules"},
                {"role": "user", "content": "diff"},
            ],
        )

    def test_the_default_token_ceiling_is_sent(self):
        self.send()
        self.assertEqual(self.sent["payload"]["max_tokens"], 4096)

    def test_a_token_ceiling_is_sent_as_an_integer(self):
        self.send(max_output_tokens="512")
        self.assertEqual(self.sent["payload"]["max_tokens"], 512)

    def test_the_default_temperature_is_zero(self):
        self.send()
        self.assertEqual(self.sent["payload"]["temperature"], 0.0)

    def test_a_temperature_is_sent_as_a_float(self):
        self.send(temperature=1)
        self.assertEqual(self.sent["payload"]["temperature"], 1.0)
        self.assertIsInstance(self.sent["payload"]["temperature"], float)

    def test_nothing_else_is_put_in_the_body(self):
        self.send()
        self.assertEqual(
            sorted(self.sent["payload"]),
            ["max_tokens", "messages", "model", "temperature"],
        )

    def test_the_api_key_is_sent_as_a_bearer_token(self):
        key = fake_model_key()
        self.send(provider=self.provider(api_key=key))
        self.assertEqual(self.sent["headers"]["authorization"], "Bearer " + key)

    def test_no_authorization_header_is_sent_when_there_is_no_key(self):
        self.send(provider=self.provider(api_key=""))
        self.assertEqual(self.sent["headers"], {})

    def test_the_key_is_never_put_in_the_body(self):
        key = fake_model_key()
        self.send(provider=self.provider(api_key=key))
        self.assertNotIn(key, repr(self.sent["payload"]))

    def test_one_call_sends_one_request(self):
        self.send()
        self.assertEqual(len(self.recorder.calls), 1)

    def test_a_requested_json_schema_is_not_sent_as_a_constraint(self):
        # Some servers behind this endpoint support response_format and some
        # do not, so the shape is asked for in the prompt instead.
        self.send(json_schema={"type": "object"})
        self.assertNotIn("response_format", self.sent["payload"])


class TheAnswerItReadsBack(ProviderCase):
    def test_the_message_content_becomes_the_text(self):
        self.assertEqual(self.send().text, "the answer")

    def test_the_model_the_server_reports_is_used(self):
        self.assertEqual(self.send().model, "server-side-model")

    def test_the_configured_model_is_used_when_the_server_names_none(self):
        response = _Response(body_json=_answer(model=None))
        self.assertEqual(self.send(response).model, "a-model")

    def test_the_finish_reason_becomes_the_stop_reason(self):
        self.assertEqual(self.send().stop_reason, "stop")

    def test_token_counts_are_read_from_usage(self):
        completion = self.send()
        self.assertEqual((completion.input_tokens, completion.output_tokens), (11, 3))

    def test_missing_usage_counts_as_zero_rather_than_unknown(self):
        completion = self.send(_Response(body_json=_answer(usage=None)))
        self.assertEqual((completion.input_tokens, completion.output_tokens), (0, 0))

    def test_token_counts_that_arrive_as_text_are_made_numbers(self):
        answer = _answer(usage={"prompt_tokens": "8", "completion_tokens": "2"})
        completion = self.send(_Response(body_json=answer))
        self.assertEqual((completion.input_tokens, completion.output_tokens), (8, 2))

    def test_an_empty_body_gives_an_empty_completion_rather_than_an_error(self):
        completion = self.send(_Response(body_json=None))
        self.assertEqual((completion.text, completion.stop_reason), ("", ""))

    def test_no_choices_gives_empty_text(self):
        completion = self.send(_Response(body_json=_answer(choices=[])))
        self.assertEqual(completion.text, "")

    def test_a_choice_that_is_not_an_object_is_ignored(self):
        completion = self.send(_Response(body_json=_answer(choices=["not an object"])))
        self.assertEqual((completion.text, completion.stop_reason), ("", ""))

    def test_a_choice_with_no_message_gives_empty_text(self):
        completion = self.send(_Response(body_json=_answer(choices=[{"finish_reason": "stop"}])))
        self.assertEqual(completion.text, "")
        self.assertEqual(completion.stop_reason, "stop")

    def test_null_content_becomes_an_empty_string_not_the_word_none(self):
        answer = _answer(choices=[{"message": {"content": None}, "finish_reason": "stop"}])
        self.assertEqual(self.send(_Response(body_json=answer)).text, "")

    def test_a_missing_finish_reason_becomes_an_empty_string(self):
        answer = _answer(choices=[{"message": {"content": "hi"}}])
        self.assertEqual(self.send(_Response(body_json=answer)).stop_reason, "")

    def test_only_the_first_choice_is_read(self):
        answer = _answer(
            choices=[
                {"message": {"content": "first"}, "finish_reason": "stop"},
                {"message": {"content": "second"}, "finish_reason": "length"},
            ]
        )
        self.assertEqual(self.send(_Response(body_json=answer)).text, "first")

    def test_the_raw_body_is_not_carried_into_the_completion(self):
        # Nothing downstream should reach past the fields above.
        self.assertEqual(self.send().raw, {})


class WhenTheServerRefuses(ProviderCase):
    def response_with_status(self, status, body=b"upstream said no"):
        return _Response(status=status, body_json=None, body=body)

    def test_a_non_200_status_raises(self):
        with self.assertRaises(ProviderError):
            self.send(self.response_with_status(500))

    def test_the_error_names_the_provider_and_the_status(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(self.response_with_status(429))
        message = str(caught.exception)
        self.assertIn("openai_compatible", message)
        self.assertIn("429", message)

    def test_the_error_quotes_what_the_server_said(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(self.response_with_status(400, b"model not found"))
        self.assertIn("model not found", str(caught.exception))

    def test_a_long_error_body_is_cut_to_400_characters(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(self.response_with_status(500, b"x" * 5000))
        self.assertEqual(str(caught.exception).count("x"), 400)

    def test_an_error_body_that_is_not_utf8_still_produces_a_message(self):
        with self.assertRaises(ProviderError) as caught:
            self.send(self.response_with_status(502, b"\xff\xfe bad bytes"))
        self.assertIn("502", str(caught.exception))

    def test_a_201_is_treated_as_a_refusal_because_only_200_is_expected(self):
        with self.assertRaises(ProviderError):
            self.send(self.response_with_status(201, b"created"))

    def test_an_egress_refusal_is_not_swallowed(self):
        # The guard's answer is final; this provider does not retry it.
        with self.assertRaises(ProviderError):
            self.send(ProviderError("egress denied"))


class WhatItSaysAboutItself(ProviderCase):
    def test_describe_names_the_provider_the_model_and_the_endpoint(self):
        self.assertEqual(
            self.provider(model="a-model").describe(),
            {"provider": "openai_compatible", "model": "a-model", "endpoint": ENDPOINT},
        )

    def test_describe_never_includes_the_key(self):
        key = fake_model_key()
        self.assertNotIn(key, repr(self.provider(api_key=key).describe()))


if __name__ == "__main__":
    unittest.main()
