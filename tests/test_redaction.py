"""Pre-egress inspection.

Fixtures are assembled at runtime from fragments. Nothing in this file is a
credential-shaped literal, deliberately: see tests/support.py.
"""

from __future__ import annotations

import unittest

from jscr.errors import SecretDetected
from jscr.redaction.secrets import Redactor

from .support import (
    fake_assigned_secret,
    fake_aws_key_id,
    fake_connection_string,
    fake_model_key,
    fake_private_key_block,
    fake_vcs_token,
)


class Detection(unittest.TestCase):
    def setUp(self):
        self.redactor = Redactor(enabled=True, block_on_secret=False)

    def assertCaught(self, text, label=""):
        hits = self.redactor.scan(text)
        self.assertTrue(hits, "not detected: {0}".format(label or text[:40]))
        return hits

    def test_aws_access_key_id(self):
        self.assertCaught("key = '{0}'".format(fake_aws_key_id()), "aws id")

    def test_vcs_token(self):
        self.assertCaught("token: {0}".format(fake_vcs_token()), "vcs token")

    def test_model_provider_key(self):
        self.assertCaught("ANTHROPIC_KEY={0}".format(fake_model_key()), "model key")

    def test_private_key_block(self):
        self.assertCaught(fake_private_key_block(), "private key")

    def test_password_in_a_connection_string(self):
        hits = self.assertCaught(fake_connection_string())
        self.assertEqual(hits[0].rule, "connection-string-password")

    def test_assigned_secret(self):
        self.assertCaught(fake_assigned_secret())


class NotSecrets(unittest.TestCase):
    """False positives cost trust, and a tool nobody trusts gets switched off."""

    def setUp(self):
        self.redactor = Redactor(enabled=True, block_on_secret=False)

    def test_obvious_placeholders_are_left_alone(self):
        for text in (
            'password = "changeme"',
            'password = "your-password-here"',
            'api_key = "xxxxxxxxxxxx"',
            'token = "TODO"',
            'secret = "example"',
        ):
            self.assertEqual(self.redactor.scan(text), [], text)

    def test_ordinary_code_is_left_alone(self):
        text = "def authenticate(user, password):\n    return check(user, password)\n"
        self.assertEqual(self.redactor.scan(text), [])

    def test_a_hash_in_a_lockfile_is_not_a_credential(self):
        self.assertEqual(
            self.redactor.scan("  integrity sha512-aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBrZXk="),
            [],
        )


class Redaction(unittest.TestCase):
    def setUp(self):
        self.redactor = Redactor(enabled=True, block_on_secret=False)

    def test_the_secret_is_gone_from_the_output(self):
        secret = fake_aws_key_id()
        clean, hits = self.redactor.redact("key = '{0}'".format(secret))
        self.assertNotIn(secret, clean)
        self.assertIn("[REDACTED:aws-access-key-id]", clean)
        self.assertEqual(len(hits), 1)

    def test_the_hit_record_never_carries_the_secret(self):
        secret = fake_vcs_token()
        _clean, hits = self.redactor.redact("token = {0}".format(secret))
        blob = repr(hits[0].__dict__ if hasattr(hits[0], "__dict__") else hits[0])
        self.assertNotIn(secret, blob)
        self.assertNotIn(secret, hits[0].preview)
        self.assertNotIn(secret, hits[0].fingerprint)

    def test_the_fingerprint_is_stable_for_the_same_secret(self):
        secret = fake_model_key()
        first = self.redactor.scan("a = {0}".format(secret))[0].fingerprint
        second = self.redactor.scan("b = {0}".format(secret))[0].fingerprint
        self.assertEqual(first, second)

    def test_several_secrets_are_all_removed(self):
        text = "id={0}\ntoken={1}\nkey={2}\n".format(
            fake_aws_key_id(), fake_vcs_token(), fake_model_key()
        )
        clean, hits = self.redactor.redact(text)
        self.assertGreaterEqual(len(hits), 3)
        for fragment in (fake_aws_key_id(), fake_vcs_token(), fake_model_key()):
            self.assertNotIn(fragment, clean)

    def test_overlapping_matches_are_not_double_counted(self):
        clean, hits = self.redactor.redact(fake_private_key_block())
        self.assertEqual(len(hits), 1)
        self.assertNotIn("MIIEow", clean)


class Blocking(unittest.TestCase):
    def test_block_on_secret_refuses_rather_than_redacts(self):
        redactor = Redactor(enabled=True, block_on_secret=True)
        with self.assertRaises(SecretDetected) as caught:
            redactor.redact("key = {0}".format(fake_aws_key_id()))
        self.assertIn("nothing was sent", str(caught.exception))

    def test_block_on_secret_is_the_default(self):
        with self.assertRaises(SecretDetected):
            Redactor().redact("key = {0}".format(fake_aws_key_id()))

    def test_disabled_redactor_passes_text_through(self):
        """Switching it off is allowed, and it is the operator's decision."""
        redactor = Redactor(enabled=False)
        text = "key = {0}".format(fake_aws_key_id())
        clean, hits = redactor.redact(text)
        self.assertEqual(clean, text)
        self.assertEqual(hits, [])


class ExtraPatterns(unittest.TestCase):
    def test_an_operator_pattern_is_applied(self):
        redactor = Redactor(enabled=True, block_on_secret=False, extra_patterns=[r"ACME-[0-9]{6}"])
        clean, hits = redactor.redact("badge ACME-123456 here")
        self.assertEqual(len(hits), 1)
        self.assertNotIn("ACME-123456", clean)

    def test_a_broken_pattern_is_an_error_not_a_silent_skip(self):
        with self.assertRaises(Exception):
            Redactor(enabled=True, extra_patterns=["([unclosed"])


if __name__ == "__main__":
    unittest.main()
