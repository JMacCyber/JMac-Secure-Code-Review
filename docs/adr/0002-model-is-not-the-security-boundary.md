# ADR 0002 — The model is never the security boundary

**Status:** Accepted
**Date:** 2026-09-20

## Context

This tool puts untrusted repository content into a prompt. That content will
contain text addressed to the reviewer, because attackers read the same blog
posts everyone else does. The common answers are better prompts, delimiters,
and a second model asked to check the first.

All three are useful and none is a boundary. A prompt is a request. A model
can be persuaded. Any design whose safety rests on a model declining
something is a design that fails on the day it matters.

## Decision

**Models may request actions. Deterministic policy decides whether those
actions are possible.**

Concretely:

- No module under `review/` or `providers/` holds a capability. They cannot
  read a file, open a socket, or start a process.
- Model output is parsed into findings and nothing else. It cannot name a
  host, a path or a program.
- Destinations come from configuration alone.
- Prompt hardening — the nonce-delimited blocks, the repeated instructions,
  the injection markers, making invisible characters visible — stays, and is
  documented as defence in depth, explicitly not as the control.
- The verification pass may reject a finding. It may not add a capability,
  and only an explicit rejection rejects, so a compromised verifier cannot
  erase a review by being unhelpful.

## Consequences

- A successful prompt injection produces a wrong finding. It does not produce
  an action. That is the whole point.
- Some features are unavailable by design: autofix, agentic repair, letting
  the model pull in more context on demand. Each would hand a capability to
  the component least able to be trusted with one.
- `tools.allow` exists for operators who need model-invoked tools, is empty
  by default, and is documented as handing over a capability.
- The claim is testable: `tests/adversarial/test_prompt_injection.py` asserts
  what an injection can and cannot reach.
