## What changed, and why

<!-- What a reviewer needs in order to judge it. -->

## Security impact

Tick anything this touches. If any box is ticked, say what it opens and why
that is acceptable, and link the ADR.

- [ ] A capability in `policy.py`, or a default that widens one
- [ ] An egress path, a destination, or the guard
- [ ] An execution path or a subprocess
- [ ] Prompt construction, or how untrusted content is handled
- [ ] Redaction, persistence, or anything that leaves the machine
- [ ] A runtime dependency (this needs an ADR overturning ADR 0004)
- [ ] None of the above

## Checks

- [ ] `make check` passes (tests, lint, types, egress audit)
- [ ] Tests added, including an adversarial test if this is security relevant
- [ ] Documentation updated (capability map, configuration, threat model as applicable)
- [ ] No credential-shaped literal added anywhere, including in tests
- [ ] Nothing degrades silently: a failure is reported and reflected in the exit code
