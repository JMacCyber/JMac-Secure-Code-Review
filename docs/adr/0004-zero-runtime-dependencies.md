# ADR 0004 — Zero mandatory runtime dependencies

**Status:** Accepted
**Date:** 2026-09-20

## Context

A tool that reads private source code and can open a network connection is
an attractive target for a supply-chain attack. Any package it imports at
runtime can do everything it can do: read the same files, use the same
socket, read the same environment. A typical Python tool of this kind pulls
in tens to hundreds of transitive packages, each an independent party.

We would also be asking people to install this into CI, next to their source.

## Decision

`dependencies = []`. The shipped tool uses the standard library only,
including its HTTP and TLS. Python 3.9 or newer.

Development tools (ruff, mypy) are optional extras and are never imported by
the package. External scanners are separate programs, off by default, run
through the policy layer, never imported.

## Consequences

- More code written here: HTTP, retry, diff parsing, SARIF. All of it is
  code we can be held to, in a repository that can be audited in an afternoon.
- No dependency pinning, no lockfile drift, no transitive advisories, and an
  SBOM that is short enough to read.
- Installs anywhere Python runs, including an air-gapped machine.
- The test suite runs offline with nothing installed, which is also how it
  stays honest — see `docs/acceptance-tests.md`.
- We lose the ecosystem's conveniences. Accepted deliberately: for this tool,
  the dependency graph *is* the attack surface.
