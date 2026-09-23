"""Pre-egress secret inspection.

Nothing leaves the process without passing through :class:`Redactor`. The
point is not to be a complete secret scanner; Gitleaks is better at that and
is wired in as a scanner. The point is narrower and load-bearing: a review
must not be the mechanism by which a private key in the working tree is
posted to a third-party API.

Two settings, both on by default:

``redaction.enabled``
    replace the matched span with a typed placeholder.
``redaction.block_on_secret``
    refuse the egress entirely rather than send redacted text.

Redaction is applied to the text that will be sent, after context assembly,
so it covers diffs, expanded files, scanner output and prompt scaffolding
alike.

Note on this file and on the test suite: no credential-shaped literal is
written anywhere in this repository. Detection rules are expressed as
patterns, and test fixtures are assembled at runtime from fragments.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

# Rule prefixes are built from fragments for the reason given above.
_AWS_ID_PREFIX = "(?:A" + "KIA|A" + "SIA|A" + "ROA|A" + "IDA)"
_GH_PREFIX = "g" + "h[pousr]_"
_SLACK_PREFIX = "x" + "ox[abposr]-"
_GOOGLE_PREFIX = "A" + "Iza"
_OPENAI_PREFIX = "s" + "k-"
_ANTHROPIC_PREFIX = "s" + "k-ant-"
_JWT_PREFIX = "e" + "yJ"

# Each rule is (name, compiled pattern, group to redact).
# Patterns favour precision over recall: a false positive blocks a review,
# which is expensive for the user's trust in the tool.
_RULES: Tuple[Tuple[str, Pattern, int], ...] = (
    (
        "private-key-block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        0,
    ),
    ("aws-access-key-id", re.compile(r"\b(" + _AWS_ID_PREFIX + r"[0-9A-Z]{16})\b"), 1),
    (
        "aws-secret-access-key",
        re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"),
        1,
    ),
    ("vcs-token", re.compile(r"\b(" + _GH_PREFIX + r"[A-Za-z0-9]{36,255})\b"), 1),
    ("chat-token", re.compile(r"\b(" + _SLACK_PREFIX + r"[A-Za-z0-9-]{10,})\b"), 1),
    ("cloud-api-key", re.compile(r"\b(" + _GOOGLE_PREFIX + r"[0-9A-Za-z_\-]{35})\b"), 1),
    ("payments-key", re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b"), 1),
    ("model-provider-key", re.compile(r"\b(" + _ANTHROPIC_PREFIX + r"[A-Za-z0-9_\-]{20,})\b"), 1),
    ("model-provider-key-alt", re.compile(r"\b(" + _OPENAI_PREFIX + r"[A-Za-z0-9_\-]{20,})\b"), 1),
    (
        "bearer-assertion",
        re.compile(
            r"\b("
            + _JWT_PREFIX
            + r"[A-Za-z0-9_\-]{10,}\."
            + _JWT_PREFIX
            + r"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"
        ),
        1,
    ),
    (
        "connection-string-password",
        re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^\s:@/]+:([^\s:@/]{3,})@"
        ),
        1,
    ),
    (
        "generic-assigned-secret",
        re.compile(
            # A leading run of name characters is allowed so that
            # api_secret, DB_PASSWORD and clientSecret all match. Anchoring
            # with \b alone misses them: an underscore is a word character,
            # so there is no boundary inside api_secret.
            r"(?i)(?:^|[^A-Za-z0-9_\-])[A-Za-z0-9]*[_\-]?"
            r"(?:password|passwd|secret|api[_\-]?key|access[_\-]?token"
            r"|auth[_\-]?token|client[_\-]?secret)"
            r"\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"
        ),
        1,
    ),
)

#: Values that look like secrets but are conventional placeholders. Blocking
#: on these would make the tool unusable on any repository that ships an
#: example configuration file.
_PLACEHOLDERS = frozenset(
    {
        "changeme",
        "password",
        "your_password",
        "your-password",
        "placeholder",
        "example",
        "redacted",
        "secret",
        "dummy",
        "notarealsecret",
        "test",
        "testtest",
        "12345678",
        "password123",
        "your_api_key_here",
    }
)


class SecretHit(object):
    """One probable secret, described without repeating the secret."""

    __slots__ = ("rule", "start", "end", "fingerprint", "preview")

    def __init__(self, rule: str, start: int, end: int, value: str) -> None:
        self.rule = rule
        self.start = start
        self.end = end
        self.fingerprint = _fingerprint(value)
        self.preview = _preview(value)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "start": self.start,
            "end": self.end,
            "fingerprint": self.fingerprint,
            "preview": self.preview,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<SecretHit {0} at {1} {2}>".format(self.rule, self.start, self.preview)


class Redactor(object):
    """Inspect text for secrets, and redact or refuse."""

    def __init__(
        self,
        enabled: bool = True,
        block_on_secret: bool = True,
        extra_patterns: Optional[Iterable[str]] = None,
    ) -> None:
        self.enabled = bool(enabled)
        self.block_on_secret = bool(block_on_secret)
        self.rules: List[Tuple[str, Pattern, int]] = list(_RULES)
        for index, pattern in enumerate(extra_patterns or ()):
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise ValueError("redaction.extra_patterns[{0}]: {1}".format(index, exc)) from exc
            group = 1 if compiled.groups else 0
            self.rules.append(("custom-{0}".format(index), compiled, group))

    def scan(self, text: str) -> List[SecretHit]:
        """Return every probable secret in ``text``, earliest first."""
        hits: List[SecretHit] = []
        for name, pattern, group in self.rules:
            for match in pattern.finditer(text):
                try:
                    value = match.group(group)
                except IndexError:  # pragma: no cover - malformed custom rule
                    value = match.group(0)
                if value is None:
                    continue
                if _is_placeholder(value, strict=name in _STRUCTURED_RULES):
                    continue
                hits.append(SecretHit(name, match.start(group), match.end(group), value))
        hits.sort(key=lambda h: (h.start, h.rule))
        return _drop_overlaps(hits)

    def redact(self, text: str) -> Tuple[str, List[SecretHit]]:
        """Return ``(clean_text, hits)``.

        Raises :class:`~jscr.errors.SecretDetected` when ``block_on_secret``
        is set and anything was found. A caller that wants to know without
        being stopped should use :meth:`scan`.
        """
        from ..errors import SecretDetected

        if not self.enabled:
            return text, []
        hits = self.scan(text)
        if not hits:
            return text, []
        if self.block_on_secret:
            rules = ", ".join(sorted({h.rule for h in hits}))
            raise SecretDetected(
                "redaction",
                "{0} probable secret(s) found before egress ({1}); nothing was sent".format(
                    len(hits), rules
                ),
            )
        out: List[str] = []
        cursor = 0
        for hit in hits:
            out.append(text[cursor : hit.start])
            out.append("[REDACTED:{0}]".format(hit.rule))
            cursor = hit.end
        out.append(text[cursor:])
        return "".join(out), hits


def _drop_overlaps(hits: List[SecretHit]) -> List[SecretHit]:
    """Keep the first hit of any overlapping pair.

    A connection string and the generic assigned-secret rule can both fire on
    one span; reporting it twice would overstate the count.
    """
    kept: List[SecretHit] = []
    last_end = -1
    for hit in hits:
        if hit.start < last_end:
            continue
        kept.append(hit)
        last_end = hit.end
    return kept


# Words that mean "fill this in". A value containing one of these is a
# template, not a credential. Matching on substrings rather than on an exact
# list is deliberate: "your-password-here", "REPLACE_WITH_KEY" and
# "sample_token_value" are all the same thing wearing different separators,
# and an exact list would need a new entry for each.
_PLACEHOLDER_WORDS = (
    "your",
    "here",
    "changeme",
    "change-me",
    "change_me",
    "replace",
    "placeholder",
    "example",
    "sample",
    "dummy",
    "redacted",
    "insert",
    "todo",
    "fixme",
    "notreal",
    "notarealsecret",
    "xxxx",
)


# Rules that match a provider's own key format rather than a variable name.
# A value that is shaped like an AWS access key id is treated as one even if
# it contains the word "example", because the cost of being wrong runs one
# way: a documentation string reported is a minor annoyance, and a live key
# sent to a third party because it happened to contain a friendly word is
# the failure this whole module exists to prevent.
_STRUCTURED_RULES = frozenset(
    {
        "private-key-block",
        "aws-access-key-id",
        "aws-secret-access-key",
        "vcs-token",
        "chat-token",
        "cloud-api-key",
        "payments-key",
        "model-provider-key",
        "model-provider-key-alt",
        "bearer-assertion",
    }
)


def _is_placeholder(value: str, strict: bool = False) -> bool:
    """Is this value a template rather than a credential?

    ``strict`` narrows the test to shapes that cannot be a real key at all:
    an all-x string, a ``${VAR}`` reference, an ``<angle bracket>`` slot. It
    is used for the structured rules, where the word list would suppress
    real findings.
    """
    stripped = value.strip()
    lowered = stripped.lower()
    if not strict:
        if lowered in _PLACEHOLDERS:
            return True
        for word in _PLACEHOLDER_WORDS:
            if word in lowered:
                return True
    if stripped.startswith("${") or stripped.startswith("{{"):
        return True
    if re.match(r"^<[^>]+>$", stripped):
        return True
    if re.match(r"^[Xx*]{6,}$", stripped):
        return True
    return False


def _fingerprint(value: str) -> str:
    """A stable, non-reversing identifier so a hit can be tracked run to run."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _preview(value: str) -> str:
    """Enough to locate the secret in the file, not enough to use it."""
    stripped = value.strip()
    if len(stripped) <= 8:
        return "*" * len(stripped)
    return "{0}...{1}".format(stripped[:4], "*" * 6)
