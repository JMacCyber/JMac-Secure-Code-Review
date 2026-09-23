# Contributing

Thank you for wanting to help. This is a security tool, so the bar is about
evidence rather than ceremony.

## Before writing code

Open an issue for anything that changes behaviour. For anything that changes
what the tool *may do* — a capability, a default, a destination, an execution
path — say so explicitly in the issue. Those changes need an ADR.

## The rules that are not negotiable

These are the reasons the project exists. A pull request that breaks one will
be declined regardless of how useful the feature is.

1. **No runtime dependency.** The shipped package imports the standard
   library only ([ADR 0004](docs/adr/0004-zero-runtime-dependencies.md)).
   Development tools are optional extras and are never imported by `jscr`.
2. **One network module.** Only `src/jscr/egress/http.py` may reach the
   network. `make egress-audit` enforces this by parsing every module.
3. **Deny by default.** A new capability is off until explicitly enabled, is
   named in `policy.py`, and appears in `docs/capability-map.md`.
4. **The model gets no capability.** Nothing under `review/` or `providers/`
   may read a file, open a socket or start a process
   ([ADR 0002](docs/adr/0002-model-is-not-the-security-boundary.md)).
5. **No credential-shaped literal, anywhere, including tests.** Assemble
   fixtures at runtime from fragments — see `tests/support.py`.
6. **Failures are loud.** Nothing degrades silently. If something did not
   run, the report says so and the exit code reflects it.

## Working on it

```
make check        # test, lint, types, egress audit
make test         # offline, no dependencies needed
make egress-audit # the structural proof
make selfreview   # JSCR reviews its own change
```

The suite must pass offline with nothing installed. A test that skips when
the machine has no network is not a control, and will be asked for changes.

## Tests

Every behavioural change needs a test. Security-relevant changes need an
**adversarial** test: assert the refusal, not only the success. The
interesting assertion is usually "nothing was sent", "the path was refused",
"the finding was rejected, with a reason".

New scanner rules need a true-positive case and a false-positive case. A rule
with no false-positive test will be asked for one.

## Style

- Python 3.9 compatible. `ruff` and `mypy` clean.
- Comments explain *why*, especially why a restriction exists. A comment that
  restates the code will be removed; a comment recording the reasoning behind
  a refusal is the most valuable thing in the file.
- Errors name what was refused and why, in words an operator can act on.
- Status and colour words are capitalised: Green, Amber, Red, High, Low.

## Commits and pull requests

Explain what changed and why it is safe. If the change touches a capability,
a default, an egress path, an execution path or a prompt, say so in the first
line of the description — reviewers read that first.

## Licence

Contributions are Apache-2.0. By submitting, you confirm the work is yours to
give and that you have not copied it from another project
([ADR 0001](docs/adr/0001-clean-room-independent-implementation.md)).
