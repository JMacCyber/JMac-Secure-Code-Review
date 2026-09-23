"""The provider interface and the null provider.

The null provider is the default, so what it answers is the answer JSCR
gives when nobody has configured a model. It has to be a truthful stand-in:
a well-formed empty result, never an invented finding.
"""

from __future__ import annotations

import json
import unittest

from jscr.providers.base import Completion, Provider
from jscr.providers.null import NullProvider


class TheInterface(unittest.TestCase):
    def test_the_base_provider_answers_nothing_and_says_so(self):
        with self.assertRaises(NotImplementedError):
            Provider().complete("system", "user")

    def test_the_base_provider_describes_its_name_and_whether_it_needs_the_network(self):
        self.assertEqual(Provider().describe(), {"provider": "base", "requires_network": False})

    def test_a_completion_reports_what_it_cost_without_the_text(self):
        completion = Completion(
            text="four", model="m", input_tokens=9, output_tokens=1, stop_reason="stop"
        )
        self.assertEqual(
            completion.as_dict(),
            {
                "model": "m",
                "input_tokens": 9,
                "output_tokens": 1,
                "stop_reason": "stop",
                "characters": 4,
            },
        )

    def test_a_completion_with_no_raw_body_holds_an_empty_one(self):
        self.assertEqual(Completion(text="x").raw, {})


class TheNullProvider(unittest.TestCase):
    def answer(self):
        return NullProvider().complete("system", "user")

    def test_it_needs_no_network(self):
        self.assertFalse(NullProvider.requires_network)

    def test_it_answers_with_an_empty_finding_list_not_an_invented_one(self):
        self.assertEqual(json.loads(self.answer().text), {"findings": []})

    def test_it_names_itself_as_the_model(self):
        self.assertEqual(self.answer().model, "null")

    def test_the_stop_reason_says_which_provider_answered(self):
        # A reader of the report can tell an empty review from a real one.
        self.assertEqual(self.answer().stop_reason, "null_provider")

    def test_it_costs_nothing(self):
        completion = self.answer()
        self.assertEqual((completion.input_tokens, completion.output_tokens), (0, 0))


if __name__ == "__main__":
    unittest.main()
