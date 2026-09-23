# ADR 0003 — JSON configuration with a closed schema

**Status:** Accepted
**Date:** 2026-09-20

## Context

YAML is the convention for tools like this. It is also the format with
`norway: no` parsing to `false`, several ways to write the same document,
anchors and aliases, and a history of deserialisation vulnerabilities. It
needs a third-party parser, which contradicts [ADR 0004](0004-zero-runtime-dependencies.md).

Separately: most tools ignore configuration keys they do not recognise. A
security tool that does this will one day read `egres.enabled: true`, ignore
it, and run with egress closed while the operator believes it is open — or
the reverse.

## Decision

Configuration is JSON, parsed by the standard library. The schema is closed:
unknown keys are rejected with an error naming the key, and the run stops.
Types are validated. `--set` goes through the same validation.

## Consequences

- No comments in the configuration file. Accepted: the file is short, and
  `docs/configuration.md` carries the explanation.
- More verbose than YAML. Accepted.
- A typo is an error, not a silent downgrade. This is the reason for the
  decision, and it is the one that matters.
- Adding a key is a deliberate act, which keeps the capability map honest.
